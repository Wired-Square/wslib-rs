use crate::flow_control::{FlowControl, FlowStatus, StMin, UNLIMITED_BLOCK};
use crate::framing::{FirstFrame, Framing, Pdu};
use crate::pci::{LOW_NIBBLE, SN_FIRST};

/// Why a message in progress was dropped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Abort {
    OutOfSequence {
        expected: u8,
        received: u8,
    },
    /// A consecutive frame carried fewer bytes than the lesser of what its
    /// first frame's length allows and what the message still needs.
    Truncated {
        needed: usize,
        carried: usize,
    },
    /// A single or first frame arrived, valid or not.
    Superseded,
}

/// What the receiver does next.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    /// The frame was ignored, or it aborted the message.
    Nothing,
    /// A consecutive frame taken mid-message. Restart N_Cr; there is no flow
    /// control to send.
    Accepted,
    Message(Vec<u8>),
    SendFlowControl(FlowControl),
}

/// One frame's effect: the message it aborted, if any, and the next step.
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use]
pub struct Outcome {
    pub aborted: Option<Abort>,
    pub step: Step,
}

impl Outcome {
    const NOTHING: Self = Self::of(Step::Nothing);

    const fn of(step: Step) -> Self {
        Self {
            aborted: None,
            step,
        }
    }
}

#[derive(Debug, Clone)]
struct Receiving {
    message: Vec<u8>,
    len: usize,
    next_sn: u8,
    in_block: u8,
    cf_capacity: usize,
}

/// The receive side: frames in, whole messages and flow controls out.
#[derive(Debug, Clone)]
pub struct Reassembler {
    block_size: u8,
    st_min: StMin,
    framing: Framing,
    receiving: Option<Receiving>,
}

impl Reassembler {
    /// A receiver asking for `block_size` consecutive frames per flow control,
    /// 0 for all, at least `st_min` apart, with the default [`Framing`].
    pub fn new(block_size: u8, st_min: StMin) -> Self {
        Self::with_framing(block_size, st_min, Framing::default())
    }

    /// As [`new`](Self::new), reading frames as `framing` lays them out. A
    /// first frame announcing more than its `max_message` is answered with
    /// an overflow.
    pub fn with_framing(block_size: u8, st_min: StMin, framing: Framing) -> Self {
        Self {
            block_size,
            st_min,
            framing,
            receiving: None,
        }
    }

    pub fn is_receiving(&self) -> bool {
        self.receiving.is_some()
    }

    /// Drops any message in progress.
    pub fn reset(&mut self) {
        self.receiving = None;
    }

    /// Takes one received frame, padded or not. It ignores flow control and
    /// any frame its framing's [`classify`](Framing::classify) refuses.
    #[must_use = "a frame can complete a message or need a flow control sent"]
    pub fn on_frame(&mut self, frame: &[u8]) -> Outcome {
        match self.framing.decode(frame) {
            Some(Pdu::Single(data)) => Outcome {
                aborted: self.supersede(),
                step: data.map_or(Step::Nothing, |data| Step::Message(data.to_vec())),
            },
            Some(Pdu::First(first)) => Outcome {
                aborted: self.supersede(),
                step: first.map_or(Step::Nothing, |first| self.on_first(first)),
            },
            Some(Pdu::Consecutive { sn, data }) => self.on_consecutive(sn, data),
            Some(Pdu::FlowControl(_)) | None => Outcome::NOTHING,
        }
    }

    fn on_first(&mut self, first: FirstFrame<'_>) -> Step {
        if first.len > self.framing.max_len() {
            return Step::SendFlowControl(self.flow(FlowStatus::Overflow));
        }
        self.receiving = Some(Receiving {
            message: first.buffer(),
            len: first.len,
            next_sn: SN_FIRST,
            in_block: 0,
            cf_capacity: first.cf_capacity,
        });
        Step::SendFlowControl(self.continue_to_send())
    }

    fn on_consecutive(&mut self, sn: u8, data: &[u8]) -> Outcome {
        let Some(receiving) = self
            .receiving
            .as_mut()
            .filter(|receiving| data.len() <= receiving.cf_capacity)
        else {
            return Outcome::NOTHING;
        };
        if sn != receiving.next_sn {
            let expected = receiving.next_sn;
            return self.abort(Abort::OutOfSequence {
                expected,
                received: sn,
            });
        }
        let wanted = (receiving.len - receiving.message.len()).min(receiving.cf_capacity);
        let Some(data) = data.get(..wanted) else {
            return self.abort(Abort::Truncated {
                needed: wanted,
                carried: data.len(),
            });
        };
        receiving.message.extend_from_slice(data);
        receiving.next_sn = (sn + 1) & LOW_NIBBLE;
        if receiving.message.len() == receiving.len {
            let message = std::mem::take(&mut receiving.message);
            self.receiving = None;
            return Outcome::of(Step::Message(message));
        }
        if self.block_size == UNLIMITED_BLOCK {
            return Outcome::of(Step::Accepted);
        }
        receiving.in_block += 1;
        if receiving.in_block < self.block_size {
            return Outcome::of(Step::Accepted);
        }
        receiving.in_block = 0;
        Outcome::of(Step::SendFlowControl(self.continue_to_send()))
    }

    fn abort(&mut self, abort: Abort) -> Outcome {
        self.receiving = None;
        Outcome {
            aborted: Some(abort),
            step: Step::Nothing,
        }
    }

    fn supersede(&mut self) -> Option<Abort> {
        self.receiving.take().map(|_| Abort::Superseded)
    }

    fn continue_to_send(&self) -> FlowControl {
        self.flow(FlowStatus::ContinueToSend)
    }

    fn flow(&self, status: FlowStatus) -> FlowControl {
        FlowControl {
            status,
            block_size: self.block_size,
            st_min: self.st_min,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framing::{Addressing, FdLength, FrameFormat};
    use crate::pci::{CF_MAX_DATA, CF_PCI_LEN, CLASSIC_LEN, FF_DATA, FF_DL_MIN, MAX_MESSAGE};
    use crate::segment::Segmenter;

    fn framings() -> Vec<Framing> {
        let addressings = [
            Addressing::Normal,
            Addressing::Extended { tx: 0x10, rx: 0xF1 },
            Addressing::Mixed { tx: 0x55, rx: 0x55 },
        ];
        let formats = [
            FrameFormat::Classic,
            FrameFormat::Fd {
                length: FdLength::new(8).unwrap(),
            },
            FrameFormat::Fd {
                length: FdLength::new(20).unwrap(),
            },
            FrameFormat::Fd {
                length: FdLength::MAX,
            },
        ];
        let mut framings = Vec::new();
        for addressing in addressings {
            for format in formats {
                for padding in [None, Some(0xAA)] {
                    let mut framing = Framing::new(addressing, format);
                    framing.padding = padding;
                    framing.max_message = 70_000;
                    framings.push(framing);
                }
            }
        }
        framings
    }

    fn framed_round_trip(sender: &Framing, len: usize) {
        let data = message(len);
        let mut segmenter = Segmenter::with_framing(&data, sender).unwrap();
        let mut reassembler = Reassembler::with_framing(0, ST_MIN, sender.peer());
        let first = reassembler.on_frame(&segmenter.first());
        if segmenter.is_single() {
            assert_eq!(first, Outcome::of(Step::Message(data)), "{sender:?} {len}");
            return;
        }
        assert_eq!(first, Outcome::of(cts(0)), "{sender:?} {len}");
        let mut last = None;
        for frame in segmenter.by_ref() {
            match reassembler.on_frame(&frame) {
                Outcome {
                    aborted: None,
                    step: Step::Accepted,
                } => {}
                Outcome {
                    aborted: None,
                    step: Step::Message(message),
                } => last = Some(message),
                other => panic!("{sender:?} {len}: {other:?}"),
            }
        }
        assert_eq!(last, Some(data), "{sender:?} {len}");
    }

    #[test]
    fn every_addressing_format_and_padding_round_trips() {
        for framing in framings() {
            for len in [
                1,
                6,
                7,
                8,
                18,
                61,
                62,
                63,
                64,
                200,
                MAX_MESSAGE,
                MAX_MESSAGE + 1,
                70_000,
            ] {
                framed_round_trip(&framing, len);
            }
        }
    }

    #[test]
    fn a_frame_carrying_another_address_byte_is_ignored() {
        let sender = Framing::new(
            Addressing::Extended { tx: 0x10, rx: 0xF1 },
            FrameFormat::Classic,
        );
        let mut reassembler = Reassembler::with_framing(0, ST_MIN, sender);
        let ours = sender.peer().frame(&[0x01, 0x3E]);
        assert_eq!(
            reassembler.on_frame(&sender.frame(&[0x01, 0x3E])),
            Outcome::NOTHING
        );
        assert_eq!(
            reassembler.on_frame(&ours),
            Outcome::of(Step::Message(vec![0x3E]))
        );
    }

    #[test]
    fn a_first_frame_over_the_message_cap_is_answered_with_overflow() {
        let mut framing = Framing {
            max_message: 100,
            ..Framing::default()
        };
        let mut reassembler = Reassembler::with_framing(0, ST_MIN, framing);
        assert_eq!(
            reassembler.on_frame(&[0x10, 101, 0, 0, 0, 0, 0, 0]),
            Outcome::of(Step::SendFlowControl(FlowControl {
                status: FlowStatus::Overflow,
                block_size: 0,
                st_min: ST_MIN,
            }))
        );
        assert!(!reassembler.is_receiving());
        framing.max_message = 70_000;
        let mut reassembler = Reassembler::with_framing(0, ST_MIN, framing);
        let hostile = [0x10, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0, 0];
        assert!(matches!(
            reassembler.on_frame(&hostile).step,
            Step::SendFlowControl(FlowControl {
                status: FlowStatus::Overflow,
                ..
            })
        ));
        assert!(!reassembler.is_receiving());
    }

    #[test]
    fn a_consecutive_frame_longer_than_the_first_frame_is_ignored() {
        let fd = Framing::new(
            Addressing::Normal,
            FrameFormat::Fd {
                length: FdLength::MAX,
            },
        );
        let mut reassembler = Reassembler::with_framing(0, ST_MIN, fd);
        let first = [0x10, 30, 0, 1, 2, 3, 4, 5];
        assert_eq!(reassembler.on_frame(&first), Outcome::of(cts(0)));
        let mut long = vec![0x21];
        long.extend(6..17);
        assert_eq!(reassembler.on_frame(&long), Outcome::NOTHING);
        assert!(reassembler.is_receiving());
        assert_eq!(
            reassembler.on_frame(&[0x21, 6, 7, 8, 9, 10, 11, 12]),
            ACCEPTED
        );
    }

    #[test]
    fn an_announced_length_reserves_at_most_4095_bytes() {
        let framing = Framing {
            max_message: u32::MAX,
            ..Framing::default()
        };
        let mut reassembler = Reassembler::with_framing(0, ST_MIN, framing);
        let hostile = [0x10, 0x00, 0xFF, 0xFF, 0xFF, 0xF0, 0xAA, 0xBB];
        assert_eq!(reassembler.on_frame(&hostile), Outcome::of(cts(0)));
        let receiving = reassembler.receiving.as_ref().unwrap();
        assert_eq!(receiving.len, 0xFFFF_FFF0);
        assert!(receiving.message.capacity() <= MAX_MESSAGE);
    }

    #[test]
    fn a_can_fd_receiver_reads_consecutive_frames_as_long_as_the_first() {
        let fd = Framing::new(
            Addressing::Normal,
            FrameFormat::Fd {
                length: FdLength::MAX,
            },
        );
        let mut reassembler = Reassembler::with_framing(0, ST_MIN, fd);
        let mut first = vec![0x10, 30];
        first.extend(0..10);
        first.resize(12, 0);
        let Step::SendFlowControl(_) = reassembler.on_frame(&first).step else {
            panic!("a 12-byte first frame starts a message");
        };
        let mut cf = vec![0x21];
        cf.extend(10..20);
        assert_eq!(
            reassembler.on_frame(&cf).aborted,
            Some(Abort::Truncated {
                needed: 11,
                carried: 10
            })
        );
    }

    const PADDING: u8 = 0xCC;
    const ACCEPTED: Outcome = Outcome::of(Step::Accepted);
    const ST_MIN: StMin = StMin(0x05);

    fn message(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i * 7 + 3) as u8).collect()
    }

    fn padded(mut frame: Vec<u8>) -> Vec<u8> {
        frame.resize(CLASSIC_LEN, PADDING);
        frame
    }

    fn cts(block_size: u8) -> Step {
        Step::SendFlowControl(FlowControl {
            status: FlowStatus::ContinueToSend,
            block_size,
            st_min: ST_MIN,
        })
    }

    fn receiving(len: usize) -> Reassembler {
        let data = message(len);
        let mut reassembler = Reassembler::new(0, ST_MIN);
        assert_eq!(
            reassembler.on_frame(&Segmenter::new(&data).unwrap().first()),
            Outcome::of(cts(0))
        );
        reassembler
    }

    fn round_trip(len: usize, pad: fn(Vec<u8>) -> Vec<u8>) {
        let data = message(len);
        let mut segmenter = Segmenter::new(&data).unwrap();
        let mut reassembler = Reassembler::new(0, ST_MIN);
        let first = reassembler.on_frame(&pad(segmenter.first()));
        if segmenter.is_single() {
            assert_eq!(first, Outcome::of(Step::Message(data)), "{len}");
            return;
        }
        assert_eq!(first, Outcome::of(cts(0)), "{len}");
        let mut last = None;
        for frame in segmenter.by_ref() {
            assert_eq!(last, None, "{len}: completed early");
            match reassembler.on_frame(&pad(frame)) {
                Outcome {
                    aborted: None,
                    step: Step::Accepted,
                } => {}
                Outcome {
                    aborted: None,
                    step: Step::Message(message),
                } => last = Some(message),
                other => panic!("{len}: {other:?}"),
            }
        }
        assert_eq!(last, Some(data), "{len}");
        assert!(!reassembler.is_receiving());
    }

    #[test]
    fn round_trips_unpadded() {
        for len in [1, 7, 8, 62, 1200, MAX_MESSAGE] {
            round_trip(len, |frame| frame);
        }
    }

    #[test]
    fn round_trips_padded() {
        for len in [1, 7, 8, 62, 1200, MAX_MESSAGE] {
            round_trip(len, padded);
        }
    }

    #[test]
    fn round_trips_every_length() {
        for len in 1..=MAX_MESSAGE {
            round_trip(len, |frame| frame);
        }
    }

    #[test]
    fn padding_past_a_single_frames_length_is_ignored() {
        let mut reassembler = Reassembler::new(0, ST_MIN);
        let frame = [0x02, 0xAB, 0xCD, 0x00, 0x00, 0x00, 0x00, 0x00];
        assert_eq!(
            reassembler.on_frame(&frame),
            Outcome::of(Step::Message(vec![0xAB, 0xCD]))
        );
    }

    #[test]
    fn a_single_frame_of_length_0_or_over_7_is_ignored() {
        let mut reassembler = Reassembler::new(0, ST_MIN);
        assert_eq!(
            reassembler.on_frame(&[0x00, 1, 2, 3, 4, 5, 6, 7]),
            Outcome::NOTHING
        );
        for sf_dl in 0x08..=0x0F {
            assert_eq!(
                reassembler.on_frame(&[sf_dl, 1, 2, 3, 4, 5, 6, 7]),
                Outcome::NOTHING,
                "{sf_dl}"
            );
        }
    }

    #[test]
    fn a_single_frame_shorter_than_its_length_is_ignored() {
        let mut reassembler = Reassembler::new(0, ST_MIN);
        assert_eq!(reassembler.on_frame(&[0x03, 1, 2]), Outcome::NOTHING);
        assert_eq!(reassembler.on_frame(&[0x01]), Outcome::NOTHING);
    }

    const SUPERSEDED: Outcome = Outcome {
        aborted: Some(Abort::Superseded),
        step: Step::Nothing,
    };

    #[test]
    fn an_invalid_single_or_first_frame_ends_the_message_and_is_ignored() {
        let data = message(20);
        let segmenter = Segmenter::new(&data).unwrap();
        let first_cf = segmenter.clone().next().unwrap();
        for invalid in [
            &[0x03, 1, 2][..],
            &[0x00, 1, 2, 3, 4, 5, 6, 7],
            &[0x08, 1, 2, 3, 4, 5, 6, 7],
            &[0x10, 0x14, 0, 1, 2, 3, 4],
            &[0x10, 0x07, 0, 1, 2, 3, 4, 5],
            &[0x10, 0x00, 0x00, 0x00, 0x10, 0x00, 0xAA, 0xBB],
        ] {
            let mut reassembler = Reassembler::new(0, ST_MIN);
            assert_eq!(
                reassembler.on_frame(&segmenter.first()),
                Outcome::of(cts(0))
            );
            assert_eq!(reassembler.on_frame(invalid), SUPERSEDED, "{invalid:02x?}");
            assert!(!reassembler.is_receiving());
            assert_eq!(
                reassembler.on_frame(&first_cf),
                Outcome::NOTHING,
                "{invalid:02x?}"
            );
        }
    }

    #[test]
    fn a_first_frame_under_8_bytes_is_ignored() {
        let mut reassembler = Reassembler::new(0, ST_MIN);
        assert_eq!(
            reassembler.on_frame(&[0x10, 0x08, 0, 1, 2, 3, 4]),
            Outcome::NOTHING
        );
        assert!(!reassembler.is_receiving());
    }

    #[test]
    fn a_first_frame_length_under_8_is_ignored() {
        let mut reassembler = Reassembler::new(0, ST_MIN);
        for ff_dl in 0..FF_DL_MIN as u8 {
            assert_eq!(
                reassembler.on_frame(&[0x10, ff_dl, 0, 1, 2, 3, 4, 5]),
                Outcome::NOTHING,
                "{ff_dl}"
            );
        }
        assert!(!reassembler.is_receiving());
    }

    #[test]
    fn a_consecutive_frame_out_of_sequence_aborts() {
        let mut reassembler = receiving(100);
        assert_eq!(reassembler.on_frame(&[0x21, 0, 0, 0, 0, 0, 0, 0]), ACCEPTED);
        assert_eq!(
            reassembler.on_frame(&[0x23, 0, 0, 0, 0, 0, 0, 0]),
            Outcome {
                aborted: Some(Abort::OutOfSequence {
                    expected: 2,
                    received: 3
                }),
                step: Step::Nothing
            }
        );
        assert!(!reassembler.is_receiving());
        assert_eq!(
            reassembler.on_frame(&[0x22, 0, 0, 0, 0, 0, 0, 0]),
            Outcome::NOTHING
        );
    }

    #[test]
    fn a_repeated_consecutive_frame_aborts() {
        let mut reassembler = receiving(100);
        assert_eq!(reassembler.on_frame(&[0x21, 0, 0, 0, 0, 0, 0, 0]), ACCEPTED);
        assert_eq!(
            reassembler.on_frame(&[0x21, 0, 0, 0, 0, 0, 0, 0]).aborted,
            Some(Abort::OutOfSequence {
                expected: 2,
                received: 1
            })
        );
    }

    #[test]
    fn a_consecutive_frame_with_no_message_in_progress_is_ignored() {
        let mut reassembler = Reassembler::new(0, ST_MIN);
        assert_eq!(
            reassembler.on_frame(&[0x21, 1, 2, 3, 4, 5, 6, 7]),
            Outcome::NOTHING
        );
        assert!(!reassembler.is_receiving());
    }

    #[test]
    fn a_short_consecutive_frame_before_the_last_aborts() {
        let data = message(20);
        let segmenter = Segmenter::new(&data).unwrap();
        for carried in 0..CF_MAX_DATA {
            let mut reassembler = Reassembler::new(0, ST_MIN);
            assert_eq!(
                reassembler.on_frame(&segmenter.first()),
                Outcome::of(cts(0))
            );
            let full = segmenter.clone().next().unwrap();
            assert_eq!(
                reassembler.on_frame(&full[..CF_PCI_LEN + carried]),
                Outcome {
                    aborted: Some(Abort::Truncated {
                        needed: CF_MAX_DATA,
                        carried
                    }),
                    step: Step::Nothing
                },
                "{carried}"
            );
            assert!(!reassembler.is_receiving());
            assert_eq!(reassembler.on_frame(&full), Outcome::NOTHING);
        }
    }

    #[test]
    fn a_last_consecutive_frame_cut_short_aborts() {
        let data = message(FF_DATA + CF_MAX_DATA + 3);
        let mut segmenter = Segmenter::new(&data).unwrap();
        let mut reassembler = Reassembler::new(0, ST_MIN);
        assert_eq!(
            reassembler.on_frame(&segmenter.first()),
            Outcome::of(cts(0))
        );
        assert_eq!(reassembler.on_frame(&segmenter.next().unwrap()), ACCEPTED);
        let last = segmenter.next().unwrap();
        assert_eq!(
            reassembler.on_frame(&last[..last.len() - 1]),
            Outcome {
                aborted: Some(Abort::Truncated {
                    needed: 3,
                    carried: 2
                }),
                step: Step::Nothing
            }
        );
        assert!(!reassembler.is_receiving());
    }

    #[test]
    fn only_a_consecutive_frame_accepted_mid_message_steps_accepted() {
        let mut reassembler = receiving(100);
        assert_eq!(reassembler.on_frame(&[0x21, 0, 0, 0, 0, 0, 0, 0]), ACCEPTED);
        for ignored in [&[0x30, 0, 0][..], &[0x40], &[0x22; CLASSIC_LEN + 1]] {
            assert_eq!(
                reassembler.on_frame(ignored),
                Outcome::NOTHING,
                "{ignored:02x?}"
            );
            assert!(reassembler.is_receiving());
        }
        for refused in [
            &[0x23, 0, 0, 0, 0, 0, 0, 0][..],
            &[0x22, 0, 0],
            &[0x00],
            &[0x10, 0x07, 0, 0, 0, 0, 0, 0],
        ] {
            let mut reassembler = receiving(100);
            assert_eq!(reassembler.on_frame(&[0x21, 0, 0, 0, 0, 0, 0, 0]), ACCEPTED);
            let outcome = reassembler.on_frame(refused);
            assert!(outcome.aborted.is_some());
            assert_eq!(outcome.step, Step::Nothing);
            assert!(!reassembler.is_receiving());
        }
        let mut idle = Reassembler::new(0, ST_MIN);
        assert_eq!(
            idle.on_frame(&[0x21, 0, 0, 0, 0, 0, 0, 0]),
            Outcome::NOTHING
        );
    }

    #[test]
    fn a_new_single_frame_aborts_a_message_and_completes() {
        let mut reassembler = receiving(100);
        assert_eq!(
            reassembler.on_frame(&[0x01, 0x42]),
            Outcome {
                aborted: Some(Abort::Superseded),
                step: Step::Message(vec![0x42])
            }
        );
        assert!(!reassembler.is_receiving());
    }

    #[test]
    fn a_new_first_frame_aborts_a_message_and_starts_over() {
        let mut reassembler = receiving(100);
        assert_eq!(reassembler.on_frame(&[0x21, 0, 0, 0, 0, 0, 0, 0]), ACCEPTED);
        let data = message(9);
        let mut segmenter = Segmenter::new(&data).unwrap();
        assert_eq!(
            reassembler.on_frame(&segmenter.first()),
            Outcome {
                aborted: Some(Abort::Superseded),
                step: cts(0)
            }
        );
        assert_eq!(
            reassembler.on_frame(&segmenter.next().unwrap()),
            Outcome::of(Step::Message(data))
        );
    }

    #[test]
    fn flow_control_frames_are_ignored() {
        let mut reassembler = receiving(100);
        assert_eq!(reassembler.on_frame(&[0x30, 0, 0]), Outcome::NOTHING);
        assert!(reassembler.is_receiving());
    }

    #[test]
    fn a_frame_longer_than_classic_can_is_ignored() {
        let data = message(FF_DATA + CF_MAX_DATA * 2);
        let mut segmenter = Segmenter::new(&data).unwrap();
        let mut reassembler = Reassembler::new(0, ST_MIN);
        assert_eq!(
            reassembler.on_frame(&segmenter.first()),
            Outcome::of(cts(0))
        );
        let next = segmenter.next().unwrap();
        let mut long = next.clone();
        long.push(PADDING);
        assert_eq!(long.len(), CLASSIC_LEN + 1);
        assert_eq!(reassembler.on_frame(&long), Outcome::NOTHING);
        assert_eq!(reassembler.on_frame(&next), ACCEPTED);
        assert_eq!(
            reassembler.on_frame(&segmenter.next().unwrap()),
            Outcome::of(Step::Message(data))
        );
    }

    #[test]
    fn the_sequence_number_wraps_on_receive() {
        let data = message(FF_DATA + CF_MAX_DATA * 40);
        let segmenter = Segmenter::new(&data).unwrap();
        let mut reassembler = Reassembler::new(0, ST_MIN);
        assert_eq!(
            reassembler.on_frame(&segmenter.first()),
            Outcome::of(cts(0))
        );
        let frames: Vec<Vec<u8>> = segmenter.collect();
        assert_eq!(frames[15][0], 0x20);
        assert_eq!(frames[16][0], 0x21);
        let (last, rest) = frames.split_last().unwrap();
        for frame in rest {
            assert_eq!(reassembler.on_frame(frame), ACCEPTED);
        }
        assert_eq!(reassembler.on_frame(last), Outcome::of(Step::Message(data)));
    }

    #[test]
    fn a_block_size_asks_for_flow_control_after_each_block_but_the_last() {
        const BLOCK: u8 = 2;
        let data = message(FF_DATA + CF_MAX_DATA * 4);
        let segmenter = Segmenter::new(&data).unwrap();
        let mut reassembler = Reassembler::new(BLOCK, ST_MIN);
        assert_eq!(
            reassembler.on_frame(&segmenter.first()),
            Outcome::of(cts(BLOCK))
        );
        let steps: Vec<Step> = segmenter
            .map(|frame| reassembler.on_frame(&frame).step)
            .collect();
        assert_eq!(
            steps,
            [
                Step::Accepted,
                cts(BLOCK),
                Step::Accepted,
                Step::Message(data)
            ]
        );
    }

    #[test]
    fn a_block_size_counts_from_each_flow_control() {
        const BLOCK: u8 = 3;
        let data = message(FF_DATA + CF_MAX_DATA * 7 + 1);
        let segmenter = Segmenter::new(&data).unwrap();
        let mut reassembler = Reassembler::new(BLOCK, ST_MIN);
        assert_eq!(
            reassembler.on_frame(&segmenter.first()),
            Outcome::of(cts(BLOCK))
        );
        let asked: Vec<bool> = segmenter
            .map(|frame| matches!(reassembler.on_frame(&frame).step, Step::SendFlowControl(_)))
            .collect();
        assert_eq!(
            asked,
            [false, false, true, false, false, true, false, false]
        );
    }

    #[test]
    fn reset_drops_a_message_in_progress() {
        let mut reassembler = receiving(100);
        reassembler.reset();
        assert!(!reassembler.is_receiving());
        assert_eq!(
            reassembler.on_frame(&[0x21, 0, 0, 0, 0, 0, 0, 0]),
            Outcome::NOTHING
        );
    }
}
