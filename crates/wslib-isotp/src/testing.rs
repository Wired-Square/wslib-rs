//! A simulated ISO-TP peer, clockless and sans-IO, and a scripted
//! conversation that stamps both sides' frames for golden fixtures.

use std::collections::VecDeque;
use std::time::Duration;

use crate::flow_control::{FlowControl, FlowStatus, StMin};
use crate::framing::Framing;
use crate::pci::PciKind;
use crate::reassemble::{Reassembler, Step};
use crate::segment::Segmenter;
use crate::tap::{TimedFrame, micros};

/// A frame to send, `delay` after the frame this end sent before it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToSend {
    pub data: Vec<u8>,
    pub delay: Duration,
}

impl ToSend {
    fn now(data: Vec<u8>) -> Self {
        Self::after(Duration::ZERO, data)
    }

    fn after(delay: Duration, data: Vec<u8>) -> Self {
        Self { data, delay }
    }
}

#[derive(Debug)]
struct Endpoint {
    framing: Framing,
    reassembler: Reassembler,
    waits: u8,
    wait_gap: Duration,
    queued: VecDeque<Vec<u8>>,
    consecutive: VecDeque<Vec<u8>>,
}

impl Endpoint {
    fn new(framing: Framing, block_size: u8, st_min: StMin) -> Self {
        Self {
            framing,
            reassembler: Reassembler::with_framing(block_size, st_min, framing),
            waits: 0,
            wait_gap: Duration::ZERO,
            queued: VecDeque::new(),
            consecutive: VecDeque::new(),
        }
    }

    fn flow_control(&mut self, block_size: u8, st_min: StMin) {
        self.reassembler = Reassembler::with_framing(block_size, st_min, self.framing);
    }

    fn sending(&self) -> bool {
        !self.consecutive.is_empty()
    }

    fn send(&mut self, message: Vec<u8>) -> Vec<ToSend> {
        self.queued.push_back(message);
        let mut out = Vec::new();
        if !self.sending() {
            self.start_next(&mut out);
        }
        out
    }

    fn start_next(&mut self, out: &mut Vec<ToSend>) {
        while let Some(message) = self.queued.pop_front() {
            let segmenter = Segmenter::with_framing(&message, &self.framing)
                .expect("a message the framing carries");
            out.push(ToSend::now(segmenter.first()));
            self.consecutive = segmenter.collect();
            if self.sending() {
                return;
            }
        }
    }

    fn on_frame(&mut self, frame: &[u8]) -> (Vec<ToSend>, Option<Vec<u8>>) {
        let mut out = Vec::new();
        if self.framing.classify(frame) == Some(PciKind::FlowControl) {
            if let Ok(flow) = self.framing.parse_flow_control(frame) {
                self.on_flow_control(flow, &mut out);
            }
            return (out, None);
        }
        match self.reassembler.on_frame(frame).step {
            Step::SendFlowControl(flow) => {
                let waits = match flow.status {
                    FlowStatus::ContinueToSend => self.waits,
                    _ => 0,
                };
                let wait = FlowControl {
                    status: FlowStatus::Wait,
                    ..flow
                };
                let flows = (0..waits).map(|_| wait).chain([flow]);
                for (i, flow) in flows.enumerate() {
                    let gap = if i == 0 {
                        Duration::ZERO
                    } else {
                        self.wait_gap
                    };
                    out.push(ToSend::after(gap, self.framing.encode_flow_control(&flow)));
                }
                (out, None)
            }
            Step::Message(message) => (out, Some(message)),
            Step::Accepted | Step::Nothing => (out, None),
        }
    }

    fn on_flow_control(&mut self, flow: FlowControl, out: &mut Vec<ToSend>) {
        if !self.sending() {
            return;
        }
        match flow.status {
            FlowStatus::Wait => {}
            FlowStatus::Overflow => {
                self.consecutive.clear();
                self.start_next(out);
            }
            FlowStatus::ContinueToSend => {
                let block = match usize::from(flow.block_size) {
                    0 => self.consecutive.len(),
                    block => block.min(self.consecutive.len()),
                };
                let gap = flow.st_min.duration();
                for i in 0..block {
                    let frame = self.consecutive.pop_front().expect("within the block");
                    let delay = if i == 0 { Duration::ZERO } else { gap };
                    out.push(ToSend::after(delay, frame));
                }
                if !self.sending() {
                    self.start_next(out);
                }
            }
        }
    }
}

/// A simulated ISO-TP responder: received frames in, frames to send out. Each
/// complete request goes to `answer`, and each message it returns is sent in
/// turn, honouring the requester's flow control.
pub struct Responder<A> {
    endpoint: Endpoint,
    answer: A,
}

impl<A: FnMut(&[u8]) -> Vec<Vec<u8>>> Responder<A> {
    /// A responder framing its frames with `framing`, asking for every
    /// consecutive frame in one block with no gap, and never waiting.
    pub fn new(framing: Framing, answer: A) -> Self {
        Self {
            endpoint: Endpoint::new(framing, 0, StMin(0)),
            answer,
        }
    }

    /// The block size and STmin its flow controls ask for.
    pub fn flow_control(mut self, block_size: u8, st_min: StMin) -> Self {
        self.endpoint.flow_control(block_size, st_min);
        self
    }

    /// Sends `count` WAITs before each continue-to-send, `gap` apart.
    pub fn waits(mut self, count: u8, gap: Duration) -> Self {
        self.endpoint.waits = count;
        self.endpoint.wait_gap = gap;
        self
    }

    pub fn framing(&self) -> &Framing {
        &self.endpoint.framing
    }

    /// Takes a frame the tester sent, on the tester's id, and returns the
    /// frames to send on the responder's.
    pub fn on_frame(&mut self, frame: &[u8]) -> Vec<ToSend> {
        let (mut out, request) = self.endpoint.on_frame(frame);
        if let Some(request) = request {
            for response in (self.answer)(&request) {
                out.extend(self.endpoint.send(response));
            }
        }
        out
    }
}

#[derive(Clone, Copy)]
enum Speaker {
    Tester,
    Responder,
}

/// A tester and a [`Responder`] talking, every frame stamped on a simulated
/// clock: each frame goes `frame_gap` after the one before, or its own delay
/// if that is longer.
pub struct Conversation<A> {
    tester_id: u32,
    responder_id: u32,
    extended: bool,
    tester: Endpoint,
    responder: Responder<A>,
    now_us: u64,
    frame_gap: Duration,
    frames: Vec<TimedFrame>,
}

impl<A: FnMut(&[u8]) -> Vec<Vec<u8>>> Conversation<A> {
    pub const DEFAULT_FRAME_GAP: Duration = Duration::from_millis(1);

    /// The tester sends on `tester_id` with the responder's peer framing,
    /// asking for whole messages with no gap; the responder on
    /// `responder_id`. The first frame goes one gap after `start_us`.
    pub fn new(
        tester_id: u32,
        responder_id: u32,
        extended: bool,
        start_us: u64,
        responder: Responder<A>,
    ) -> Self {
        Self {
            tester_id,
            responder_id,
            extended,
            tester: Endpoint::new(responder.framing().peer(), 0, StMin(0)),
            responder,
            now_us: start_us,
            frame_gap: Self::DEFAULT_FRAME_GAP,
            frames: Vec::new(),
        }
    }

    pub fn frame_gap(mut self, gap: Duration) -> Self {
        self.frame_gap = gap;
        self
    }

    /// The block size and STmin the tester's flow controls ask for.
    pub fn tester_flow_control(mut self, block_size: u8, st_min: StMin) -> Self {
        self.tester.flow_control(block_size, st_min);
        self
    }

    /// Sends `request` and runs until both sides are quiet, returning the
    /// responses the tester received.
    pub fn exchange(&mut self, request: &[u8]) -> Vec<Vec<u8>> {
        let mut responses = Vec::new();
        let mut wire: VecDeque<(Speaker, ToSend)> = self
            .tester
            .send(request.to_vec())
            .into_iter()
            .map(|frame| (Speaker::Tester, frame))
            .collect();
        while let Some((speaker, frame)) = wire.pop_front() {
            self.pause(self.frame_gap.max(frame.delay));
            let id = match speaker {
                Speaker::Tester => self.tester_id,
                Speaker::Responder => self.responder_id,
            };
            self.frames.push(TimedFrame {
                id,
                extended: self.extended,
                data: frame.data.clone(),
                at_us: self.now_us,
            });
            match speaker {
                Speaker::Tester => wire.extend(
                    self.responder
                        .on_frame(&frame.data)
                        .into_iter()
                        .map(|frame| (Speaker::Responder, frame)),
                ),
                Speaker::Responder => {
                    let (out, response) = self.tester.on_frame(&frame.data);
                    wire.extend(out.into_iter().map(|frame| (Speaker::Tester, frame)));
                    responses.extend(response);
                }
            }
        }
        responses
    }

    /// Lets `quiet` pass with nothing on the bus.
    pub fn pause(&mut self, quiet: Duration) {
        self.now_us = self.now_us.saturating_add(micros(quiet));
    }

    pub fn frames(&self) -> &[TimedFrame] {
        &self.frames
    }

    pub fn into_frames(self) -> Vec<TimedFrame> {
        self.frames
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framing::{Addressing, FdLength, FrameFormat};

    fn echo(request: &[u8]) -> Vec<Vec<u8>> {
        vec![request.to_vec()]
    }

    fn message(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i * 5 + 1) as u8).collect()
    }

    #[test]
    fn a_single_frame_request_is_answered_at_once() {
        let mut responder = Responder::new(Framing::default(), echo);
        assert_eq!(
            responder.on_frame(&[0x02, 0x10, 0x03]),
            [ToSend::now(vec![0x02, 0x10, 0x03])]
        );
    }

    #[test]
    fn a_first_frame_is_answered_with_the_configured_flow_control_after_its_waits() {
        let gap = Duration::from_millis(30);
        let mut responder = Responder::new(Framing::default(), echo)
            .flow_control(4, StMin(0x0A))
            .waits(2, gap);
        assert_eq!(
            responder.on_frame(&[0x10, 0x14, 0, 1, 2, 3, 4, 5]),
            [
                ToSend::now(vec![0x31, 4, 0x0A]),
                ToSend::after(gap, vec![0x31, 4, 0x0A]),
                ToSend::after(gap, vec![0x30, 4, 0x0A]),
            ]
        );
    }

    #[test]
    fn responses_honour_the_requesters_block_size_and_st_min() {
        let response = message(6 + 7 * 5);
        let reply = response.clone();
        let mut responder = Responder::new(Framing::default(), move |_: &[u8]| vec![reply.clone()]);
        let first = responder.on_frame(&[0x01, 0x22]);
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].data[..2], [0x10, 41]);
        let fc = FlowControl {
            status: FlowStatus::ContinueToSend,
            block_size: 2,
            st_min: StMin(0xF5),
        };
        let block = responder.on_frame(&fc.encode());
        let delays: Vec<Duration> = block.iter().map(|frame| frame.delay).collect();
        assert_eq!(delays, [Duration::ZERO, Duration::from_micros(500)]);
        let wait = FlowControl {
            status: FlowStatus::Wait,
            ..fc
        };
        assert_eq!(responder.on_frame(&wait.encode()), []);
        assert_eq!(responder.on_frame(&fc.encode()).len(), 2);
        assert_eq!(responder.on_frame(&fc.encode()).len(), 1);
        assert_eq!(responder.on_frame(&fc.encode()), []);
    }

    #[test]
    fn an_overflow_drops_the_response_and_sends_the_next() {
        let mut responder = Responder::new(Framing::default(), |_: &[u8]| {
            vec![message(30), vec![0x7F, 0x22, 0x14]]
        });
        assert_eq!(responder.on_frame(&[0x01, 0x22]).len(), 1);
        let overflow = FlowControl {
            status: FlowStatus::Overflow,
            block_size: 0,
            st_min: StMin(0),
        };
        assert_eq!(
            responder.on_frame(&overflow.encode()),
            [ToSend::now(vec![0x03, 0x7F, 0x22, 0x14])]
        );
    }

    #[test]
    fn several_responses_go_in_turn_each_after_the_last_finishes() {
        let pending = vec![0x7F, 0x31, 0x78];
        let done = message(12);
        let (p, d) = (pending.clone(), done.clone());
        let responder = Responder::new(Framing::default(), move |_: &[u8]| {
            vec![p.clone(), d.clone()]
        });
        let mut conversation = Conversation::new(0x7E0, 0x7E8, false, 0, responder);
        assert_eq!(
            conversation.exchange(&[0x31, 0x01, 0xFF, 0x00]),
            [pending, done]
        );
    }

    #[test]
    fn a_conversation_stamps_both_sides_in_order() {
        let framing = Framing::new(
            Addressing::Extended { tx: 0xF1, rx: 0x10 },
            FrameFormat::Fd {
                length: FdLength::new(16).unwrap(),
            },
        );
        let responder = Responder::new(framing, echo).flow_control(2, StMin(3));
        let mut conversation = Conversation::new(0x18DA10F1, 0x18DAF110, true, 0, responder)
            .tester_flow_control(1, StMin(0));
        let request = message(60);
        assert_eq!(
            conversation.exchange(&request),
            std::slice::from_ref(&request)
        );
        let frames = conversation.frames();
        assert!(frames.windows(2).all(|pair| pair[0].at_us < pair[1].at_us));
        assert_eq!(frames[0].id, 0x18DA10F1);
        assert_eq!(frames[0].data[0], 0x10);
        assert_eq!(frames[1].id, 0x18DAF110);
        assert_eq!(frames[1].data[..2], [0xF1, 0x30]);
        assert_eq!(frames[3].at_us - frames[2].at_us, 3_000);
        assert!(frames.iter().all(|frame| frame.extended));
    }
}
