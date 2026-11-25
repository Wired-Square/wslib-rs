use std::time::Duration;

use crate::flow_control::{FlowControl, FlowControlError, FlowStatus};
use crate::framing::{Framing, Pdu};
use crate::pci::{LOW_NIBBLE, SN_FIRST};

/// A CAN data frame seen on a bus, and when, in microseconds from any fixed
/// origin.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(rename = "IsoTpTimedFrame"))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct TimedFrame {
    pub id: u32,
    /// A 29-bit id, or 11-bit.
    pub extended: bool,
    pub data: Vec<u8>,
    #[cfg_attr(feature = "ts", ts(type = "number"))]
    pub at_us: u64,
}

pub(crate) fn micros(span: Duration) -> u64 {
    u64::try_from(span.as_micros()).unwrap_or(u64::MAX)
}

/// One end of a tapped conversation: A sends on [`TapConfig::a_id`], B on
/// [`TapConfig::b_id`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(rename = "IsoTpSide"))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub enum Side {
    A,
    B,
}

impl Side {
    pub fn other(self) -> Self {
        match self {
            Self::A => Self::B,
            Self::B => Self::A,
        }
    }

    fn index(self) -> usize {
        self as usize
    }
}

/// The conversation an [`IsoTpTap`] watches. [`new`](Self::new) sets every
/// other field to its default.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct TapConfig {
    pub a_id: u32,
    pub b_id: u32,
    /// 29-bit ids, or 11-bit.
    pub extended: bool,
    /// Side A's framing: its addressing's `tx` byte leads A's frames and `rx`
    /// B's. With one id both ways, these bytes tell the sides apart.
    pub framing: Framing,
    /// The longest a message goes without a frame that restarts its timer
    /// before it is dropped as timed out: any frame of the sender's, or a
    /// flow control the message is waiting for (after its first frame or at
    /// the end of a block), waits included while within `wait_limit`. A flow
    /// control arriving when none is due is recorded but restarts nothing.
    pub n_cr: Duration,
    /// Waits in a row a message survives. One more drops it.
    pub wait_limit: u32,
}

impl TapConfig {
    pub const DEFAULT_N_CR: Duration = Duration::from_secs(1);
    pub const DEFAULT_WAIT_LIMIT: u32 = 10;

    pub fn new(a_id: u32, b_id: u32, extended: bool) -> Self {
        Self {
            a_id,
            b_id,
            extended,
            framing: Framing::default(),
            n_cr: Self::DEFAULT_N_CR,
            wait_limit: Self::DEFAULT_WAIT_LIMIT,
        }
    }
}

/// A [`TapConfig`] whose sides send on one id with one address byte, so no
/// frame can be told to be A's or B's.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("both sides send on id {id:#x} with the same addressing")]
pub struct IndistinctSides {
    pub id: u32,
}

/// A complete message one side sent.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(rename = "IsoTpTapMessage"))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct TapMessage {
    pub from: Side,
    pub data: Vec<u8>,
    /// Its single frame, or its first and consecutive frames.
    pub frames: u32,
    #[cfg_attr(feature = "ts", ts(type = "number"))]
    pub first_at_us: u64,
    #[cfg_attr(feature = "ts", ts(type = "number"))]
    pub last_at_us: u64,
    /// The first [`MAX_FLOW_CONTROLS`](Self::MAX_FLOW_CONTROLS) flow controls
    /// the other side sent for it, waits included, in order.
    pub flow_controls: Vec<FlowControl>,
    /// Every flow control the other side sent for it, kept or not.
    pub flow_control_count: u32,
}

impl TapMessage {
    pub const MAX_FLOW_CONTROLS: usize = 64;
}

/// Something the tap saw go wrong, or that a reader of the conversation
/// should know.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(rename = "IsoTpTapNotice"))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct TapNotice {
    /// The side sending the message it concerns.
    pub side: Side,
    /// The time of the frame that showed it.
    #[cfg_attr(feature = "ts", ts(type = "number"))]
    pub at_us: u64,
    /// Serialised as `notice`, since a [`TapEvent`] carrying it takes `kind`.
    #[cfg_attr(feature = "serde", serde(rename = "notice"))]
    pub kind: NoticeKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(rename = "IsoTpNoticeKind"))]
#[cfg_attr(
    feature = "serde",
    serde(
        tag = "kind",
        rename_all = "camelCase",
        rename_all_fields = "camelCase"
    )
)]
pub enum NoticeKind {
    /// A consecutive frame out of sequence dropped the message.
    OutOfSequence { expected: u8, received: u8 },
    /// A consecutive frame too short dropped the message.
    Truncated { needed: usize, carried: usize },
    /// A single or first frame, valid or not, dropped the message.
    Superseded,
    /// The message's frames stopped for N_Cr or more, and it was dropped.
    TimedOut {
        #[cfg_attr(feature = "ts", ts(type = "number"))]
        gap_us: u64,
    },
    /// The receiver refused the message with an overflow.
    Overflow,
    /// The receiver asked the sender to wait.
    Wait,
    /// More waits in a row than [`TapConfig::wait_limit`] dropped the
    /// message.
    TooManyWaits,
    /// A flow control with a reserved status dropped the message.
    ReservedFlowStatus { status: u8 },
    /// A first frame announced more than the framing's `max_message`.
    TooLong { len: usize },
    /// A valid single or first frame came after a dropped message or frames
    /// the tap could not place.
    Resynchronised { skipped: u32 },
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(rename = "IsoTpTapEvent"))]
#[cfg_attr(feature = "serde", serde(tag = "kind", rename_all = "camelCase"))]
pub enum TapEvent {
    Message(TapMessage),
    Notice(TapNotice),
}

#[derive(Debug)]
struct Receiving {
    message: Vec<u8>,
    len: usize,
    next_sn: u8,
    cf_capacity: usize,
    frames: u32,
    first_at_us: u64,
    last_at_us: u64,
    flow_controls: Vec<FlowControl>,
    flow_control_count: u32,
    waits: u32,
    timed_from_us: u64,
    awaiting_flow: bool,
    block_left: Option<u8>,
}

impl Receiving {
    fn restart_timer(&mut self, at_us: u64) {
        self.timed_from_us = self.timed_from_us.max(at_us);
    }

    fn into_message(self, from: Side) -> TapMessage {
        TapMessage {
            from,
            data: self.message,
            frames: self.frames,
            first_at_us: self.first_at_us,
            last_at_us: self.last_at_us,
            flow_controls: self.flow_controls,
            flow_control_count: self.flow_control_count,
        }
    }
}

enum Start {
    Invalid,
    TooLong(usize),
    Valid,
}

#[derive(Debug, Default)]
struct SideState {
    receiving: Option<Receiving>,
    skipped: u32,
    lost: bool,
}

impl SideState {
    fn skip(&mut self) {
        self.skipped = self.skipped.saturating_add(1);
    }
}

/// Both sides of one ISO-TP conversation, reassembled from the frames a
/// passive listener sees. It keeps no clock: every time it judges comes from
/// the frames, so a capture replayed gives what the live bus gave.
#[derive(Debug)]
pub struct IsoTpTap {
    config: TapConfig,
    readers: [Framing; 2],
    sides: [SideState; 2],
}

impl IsoTpTap {
    pub fn new(config: TapConfig) -> Result<Self, IndistinctSides> {
        let addressing = config.framing.addressing;
        if config.a_id == config.b_id && addressing.peer() == addressing {
            return Err(IndistinctSides { id: config.a_id });
        }
        Ok(Self {
            readers: [config.framing.peer(), config.framing],
            config,
            sides: Default::default(),
        })
    }

    pub fn config(&self) -> &TapConfig {
        &self.config
    }

    /// Takes the next frame seen on the bus, whatever its id: a frame on
    /// another id still times out a message whose sender went quiet. A frame
    /// on one of the conversation's ids that does not lead with that side's
    /// address byte is not the conversation's, and is ignored as another id
    /// is.
    pub fn push(&mut self, frame: &TimedFrame) -> Vec<TapEvent> {
        let mut events = Vec::new();
        self.expire(frame.at_us, &mut events);
        if let Some(side) = self.side_of(frame) {
            self.on_frame(side, frame, &mut events);
        }
        events
    }

    pub fn is_receiving(&self, side: Side) -> bool {
        self.sides[side.index()].receiving.is_some()
    }

    /// Forgets both sides' messages in progress, as across a gap in the
    /// capture.
    pub fn reset(&mut self) {
        self.sides = Default::default();
    }

    fn side_of(&self, frame: &TimedFrame) -> Option<Side> {
        if frame.extended != self.config.extended {
            return None;
        }
        [Side::A, Side::B].into_iter().find(|&side| {
            frame.id == self.id(side) && self.readers[side.index()].carries_rx_byte(&frame.data)
        })
    }

    fn id(&self, side: Side) -> u32 {
        match side {
            Side::A => self.config.a_id,
            Side::B => self.config.b_id,
        }
    }

    fn expire(&mut self, at: u64, events: &mut Vec<TapEvent>) {
        for side in [Side::A, Side::B] {
            let Some(receiving) = &self.sides[side.index()].receiving else {
                continue;
            };
            let gap_us = at.saturating_sub(receiving.timed_from_us);
            if Duration::from_micros(gap_us) >= self.config.n_cr {
                self.drop_message(side, at, NoticeKind::TimedOut { gap_us }, events);
            }
        }
    }

    fn on_frame(&mut self, side: Side, frame: &TimedFrame, events: &mut Vec<TapEvent>) {
        let at = frame.at_us;
        let reader = &self.readers[side.index()];
        match reader.decode(&frame.data) {
            None | Some(Pdu::FlowControl(Err(FlowControlError::NotFlowControl))) => {
                self.sides[side.index()].skip();
            }
            Some(Pdu::FlowControl(flow)) => self.on_flow_control(side.other(), flow, at, events),
            Some(Pdu::Single(data)) => {
                let start = if data.is_some() {
                    Start::Valid
                } else {
                    Start::Invalid
                };
                if let (true, Some(data)) = (self.begin(side, at, start, events), data) {
                    events.push(TapEvent::Message(TapMessage {
                        from: side,
                        data: data.to_vec(),
                        frames: 1,
                        first_at_us: at,
                        last_at_us: at,
                        flow_controls: Vec::new(),
                        flow_control_count: 0,
                    }));
                }
            }
            Some(Pdu::First(first)) => {
                let start = match &first {
                    None => Start::Invalid,
                    Some(first) if first.len > reader.max_len() => Start::TooLong(first.len),
                    Some(_) => Start::Valid,
                };
                if let (true, Some(first)) = (self.begin(side, at, start, events), first) {
                    self.sides[side.index()].receiving = Some(Receiving {
                        message: first.buffer(),
                        len: first.len,
                        next_sn: SN_FIRST,
                        cf_capacity: first.cf_capacity,
                        frames: 1,
                        first_at_us: at,
                        last_at_us: at,
                        flow_controls: Vec::new(),
                        flow_control_count: 0,
                        waits: 0,
                        timed_from_us: at,
                        awaiting_flow: true,
                        block_left: None,
                    });
                }
            }
            Some(Pdu::Consecutive { sn, data }) => self.on_consecutive(side, sn, data, at, events),
        }
    }

    /// Ends the message in progress and says whether a new one starts.
    fn begin(&mut self, side: Side, at: u64, start: Start, events: &mut Vec<TapEvent>) -> bool {
        let state = &mut self.sides[side.index()];
        if state.receiving.take().is_some() {
            notice(events, side, at, NoticeKind::Superseded);
        }
        match start {
            Start::Invalid => {
                state.skip();
                false
            }
            Start::TooLong(len) => {
                state.lost = true;
                notice(events, side, at, NoticeKind::TooLong { len });
                false
            }
            Start::Valid => {
                if state.lost || state.skipped > 0 {
                    let skipped = state.skipped;
                    notice(events, side, at, NoticeKind::Resynchronised { skipped });
                }
                state.lost = false;
                state.skipped = 0;
                true
            }
        }
    }

    fn on_consecutive(
        &mut self,
        side: Side,
        sn: u8,
        data: &[u8],
        at: u64,
        events: &mut Vec<TapEvent>,
    ) {
        let state = &mut self.sides[side.index()];
        let Some(receiving) = state
            .receiving
            .as_mut()
            .filter(|receiving| data.len() <= receiving.cf_capacity)
        else {
            state.skip();
            return;
        };
        if sn != receiving.next_sn {
            let expected = receiving.next_sn;
            let kind = NoticeKind::OutOfSequence {
                expected,
                received: sn,
            };
            return self.drop_message(side, at, kind, events);
        }
        let needed = (receiving.len - receiving.message.len()).min(receiving.cf_capacity);
        let Some(data) = data.get(..needed) else {
            let carried = data.len();
            let kind = NoticeKind::Truncated { needed, carried };
            return self.drop_message(side, at, kind, events);
        };
        receiving.message.extend_from_slice(data);
        receiving.next_sn = (sn + 1) & LOW_NIBBLE;
        receiving.frames += 1;
        receiving.last_at_us = receiving.last_at_us.max(at);
        receiving.restart_timer(at);
        receiving.awaiting_flow = receiving.block_left.as_mut().is_some_and(|left| {
            *left = left.saturating_sub(1);
            *left == 0
        });
        if receiving.message.len() < receiving.len {
            return;
        }
        if let Some(done) = state.receiving.take() {
            events.push(TapEvent::Message(done.into_message(side)));
        }
    }

    fn on_flow_control(
        &mut self,
        sender: Side,
        flow: Result<FlowControl, FlowControlError>,
        at: u64,
        events: &mut Vec<TapEvent>,
    ) {
        let Some(receiving) = self.sides[sender.index()].receiving.as_mut() else {
            return;
        };
        let due = receiving.awaiting_flow;
        let flow = match flow {
            Ok(flow) => flow,
            Err(FlowControlError::ReservedStatus(status)) if due => {
                let kind = NoticeKind::ReservedFlowStatus { status };
                return self.drop_message(sender, at, kind, events);
            }
            Err(_) => return,
        };
        receiving.flow_control_count = receiving.flow_control_count.saturating_add(1);
        if receiving.flow_controls.len() < TapMessage::MAX_FLOW_CONTROLS {
            receiving.flow_controls.push(flow);
        }
        if !due {
            return;
        }
        match flow.status {
            FlowStatus::ContinueToSend => {
                receiving.waits = 0;
                receiving.awaiting_flow = false;
                receiving.restart_timer(at);
                receiving.block_left = (flow.block_size != 0).then_some(flow.block_size);
            }
            FlowStatus::Wait => {
                receiving.waits += 1;
                if receiving.waits > self.config.wait_limit {
                    self.drop_message(sender, at, NoticeKind::TooManyWaits, events);
                } else {
                    receiving.restart_timer(at);
                    notice(events, sender, at, NoticeKind::Wait);
                }
            }
            FlowStatus::Overflow => self.drop_message(sender, at, NoticeKind::Overflow, events),
        }
    }

    fn drop_message(&mut self, side: Side, at: u64, kind: NoticeKind, events: &mut Vec<TapEvent>) {
        let state = &mut self.sides[side.index()];
        state.receiving = None;
        state.lost = true;
        notice(events, side, at, kind);
    }
}

fn notice(events: &mut Vec<TapEvent>, side: Side, at_us: u64, kind: NoticeKind) {
    events.push(TapEvent::Notice(TapNotice { side, at_us, kind }));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flow_control::StMin;
    use crate::framing::{Addressing, FrameFormat};
    use crate::segment::Segmenter;

    const TESTER: u32 = 0x7E0;
    const ECU: u32 = 0x7E8;
    const OTHER: u32 = 0x123;
    const N_CR: Duration = TapConfig::DEFAULT_N_CR;
    const N_CR_US: u64 = N_CR.as_micros() as u64;

    fn ms(millis: u64) -> u64 {
        millis * 1000
    }

    fn frame(id: u32, data: &[u8], millis: u64) -> TimedFrame {
        stamped(id, data, ms(millis))
    }

    fn stamped(id: u32, data: &[u8], at_us: u64) -> TimedFrame {
        TimedFrame {
            id,
            extended: false,
            data: data.to_vec(),
            at_us,
        }
    }

    fn tap() -> IsoTpTap {
        IsoTpTap::new(TapConfig::new(TESTER, ECU, false)).unwrap()
    }

    fn extended(a_id: u32, b_id: u32) -> IsoTpTap {
        let mut config = TapConfig::new(a_id, b_id, false);
        config.framing = Framing::new(
            Addressing::Extended { tx: 0x10, rx: 0xF1 },
            FrameFormat::Classic,
        );
        IsoTpTap::new(config).unwrap()
    }

    fn wait() -> FlowControl {
        FlowControl {
            status: FlowStatus::Wait,
            block_size: 0,
            st_min: StMin(0),
        }
    }

    fn message(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i * 3) as u8).collect()
    }

    fn cts(block_size: u8, st_min: u8) -> FlowControl {
        FlowControl {
            status: FlowStatus::ContinueToSend,
            block_size,
            st_min: StMin(st_min),
        }
    }

    fn notices(events: &[TapEvent]) -> Vec<(Side, NoticeKind)> {
        events
            .iter()
            .filter_map(|event| match event {
                TapEvent::Notice(notice) => Some((notice.side, notice.kind)),
                TapEvent::Message(_) => None,
            })
            .collect()
    }

    fn messages(events: Vec<TapEvent>) -> Vec<TapMessage> {
        events
            .into_iter()
            .filter_map(|event| match event {
                TapEvent::Message(message) => Some(message),
                TapEvent::Notice(_) => None,
            })
            .collect()
    }

    fn feed(tap: &mut IsoTpTap, frames: &[TimedFrame]) -> Vec<TapEvent> {
        frames.iter().flat_map(|frame| tap.push(frame)).collect()
    }

    fn multi_frame(
        id: u32,
        data: &[u8],
        fc_id: u32,
        flow: FlowControl,
        from: u64,
    ) -> Vec<TimedFrame> {
        let segmenter = Segmenter::new(data).unwrap();
        let mut frames = vec![
            frame(id, &segmenter.first(), from),
            frame(fc_id, &flow.encode(), from + 1),
        ];
        for (i, cf) in segmenter.enumerate() {
            frames.push(frame(id, &cf, from + 2 + i as u64));
        }
        frames
    }

    #[test]
    fn a_single_frame_each_way_is_a_message_from_each_side() {
        let mut tap = tap();
        let events = feed(
            &mut tap,
            &[
                frame(TESTER, &[0x02, 0x10, 0x01], 5),
                frame(ECU, &[0x02, 0x50, 0x01], 7),
            ],
        );
        assert_eq!(
            messages(events),
            [
                TapMessage {
                    from: Side::A,
                    data: vec![0x10, 0x01],
                    frames: 1,
                    first_at_us: ms(5),
                    last_at_us: ms(5),
                    flow_controls: vec![],
                    flow_control_count: 0,
                },
                TapMessage {
                    from: Side::B,
                    data: vec![0x50, 0x01],
                    frames: 1,
                    first_at_us: ms(7),
                    last_at_us: ms(7),
                    flow_controls: vec![],
                    flow_control_count: 0,
                },
            ]
        );
    }

    #[test]
    fn a_multi_frame_message_carries_its_frame_count_times_and_flow_control() {
        let data = message(20);
        let mut tap = tap();
        let events = feed(&mut tap, &multi_frame(ECU, &data, TESTER, cts(0, 5), 100));
        assert_eq!(
            messages(events),
            [TapMessage {
                from: Side::B,
                data,
                frames: 3,
                first_at_us: ms(100),
                last_at_us: ms(103),
                flow_controls: vec![cts(0, 5)],
                flow_control_count: 1,
            }]
        );
    }

    #[test]
    fn both_sides_reassemble_at_once() {
        let request = message(30);
        let response = message(40);
        let a = multi_frame(TESTER, &request, ECU, cts(0, 0), 0);
        let b = multi_frame(ECU, &response, TESTER, cts(0, 0), 0);
        let mut interleaved = Vec::new();
        for i in 0..a.len().max(b.len()) {
            interleaved.extend(a.get(i).cloned());
            interleaved.extend(b.get(i).cloned());
        }
        let got = messages(feed(&mut tap(), &interleaved));
        let datas: Vec<(Side, Vec<u8>)> = got.into_iter().map(|m| (m.from, m.data)).collect();
        assert_eq!(datas, [(Side::A, request), (Side::B, response)]);
    }

    #[test]
    fn an_out_of_sequence_frame_drops_the_message_until_the_next_start() {
        let data = message(30);
        let mut frames = multi_frame(TESTER, &data, ECU, cts(0, 0), 0);
        frames.remove(3);
        frames.push(frame(TESTER, &[0x01, 0x3E], 50));
        let events = feed(&mut tap(), &frames);
        assert_eq!(
            notices(&events),
            [
                (
                    Side::A,
                    NoticeKind::OutOfSequence {
                        expected: 2,
                        received: 3
                    }
                ),
                (Side::A, NoticeKind::Resynchronised { skipped: 1 }),
            ]
        );
        assert_eq!(messages(events).len(), 1);
    }

    #[test]
    fn a_short_consecutive_frame_drops_the_message_as_truncated() {
        let mut tap = tap();
        tap.push(&frame(TESTER, &[0x10, 0x0A, 0, 1, 2, 3, 4, 5], 0));
        let events = tap.push(&frame(TESTER, &[0x21, 6, 7], 1));
        assert_eq!(
            notices(&events),
            [(
                Side::A,
                NoticeKind::Truncated {
                    needed: 4,
                    carried: 2
                }
            )]
        );
        assert!(!tap.is_receiving(Side::A));
    }

    #[test]
    fn a_gap_of_n_cr_or_more_since_the_senders_last_frame_times_the_message_out_on_any_later_frame()
    {
        let mut tap = tap();
        tap.push(&frame(TESTER, &[0x10, 0x14, 0, 1, 2, 3, 4, 5], 0));
        let events = tap.push(&frame(OTHER, &[0xFF], N_CR.as_millis() as u64));
        assert_eq!(
            notices(&events),
            [(Side::A, NoticeKind::TimedOut { gap_us: N_CR_US })]
        );
        assert!(!tap.is_receiving(Side::A));
    }

    #[test]
    fn a_wait_chain_longer_than_n_cr_keeps_the_message_while_each_wait_is_due() {
        let data = message(20);
        let segmenter = Segmenter::new(&data).unwrap();
        let mut frames = vec![frame(TESTER, &segmenter.first(), 0)];
        frames.extend((1..=4).map(|i| frame(ECU, &wait().encode(), 600 * i)));
        frames.push(frame(ECU, &cts(0, 0).encode(), 3000));
        for (i, cf) in segmenter.enumerate() {
            frames.push(frame(TESTER, &cf, 3001 + i as u64));
        }
        let events = feed(&mut tap(), &frames);
        assert_eq!(notices(&events), [(Side::A, NoticeKind::Wait); 4]);
        assert_eq!(messages(events)[0].data, data);
    }

    #[test]
    fn a_continue_to_send_when_none_is_due_restarts_nothing() {
        let mut tap = tap();
        tap.push(&frame(TESTER, &[0x10, 0x14, 0, 1, 2, 3, 4, 5], 0));
        tap.push(&frame(ECU, &cts(0, 0).encode(), 10));
        for at in [500, 900] {
            assert_eq!(tap.push(&frame(ECU, &cts(0, 0).encode(), at)), []);
        }
        let events = tap.push(&frame(OTHER, &[0xFF], 1010));
        assert_eq!(
            notices(&events),
            [(Side::A, NoticeKind::TimedOut { gap_us: N_CR_US })]
        );
        assert!(!tap.is_receiving(Side::A));
    }

    #[test]
    fn a_consecutive_frame_ends_the_wait_for_flow_control_so_a_later_one_restarts_nothing() {
        let mut tap = tap();
        tap.push(&frame(TESTER, &[0x10, 0x14, 0, 1, 2, 3, 4, 5], 0));
        tap.push(&frame(TESTER, &[0x21, 6, 7, 8, 9, 10, 11, 12], 2));
        assert_eq!(tap.push(&frame(ECU, &cts(0, 0).encode(), 900)), []);
        let events = tap.push(&frame(TESTER, &[0x22, 13, 14, 15, 16, 17, 18, 19], 1800));
        assert_eq!(
            notices(&events),
            [(Side::A, NoticeKind::TimedOut { gap_us: ms(1798) })]
        );
    }

    #[test]
    fn a_flow_control_at_the_end_of_a_block_restarts_the_timer() {
        let mut tap = tap();
        tap.push(&frame(TESTER, &[0x10, 0x1B, 0, 1, 2, 3, 4, 5], 0));
        tap.push(&frame(ECU, &cts(1, 0).encode(), 1));
        tap.push(&frame(ECU, &cts(1, 0).encode(), 500));
        tap.push(&frame(TESTER, &[0x21, 6, 7, 8, 9, 10, 11, 12], 900));
        tap.push(&frame(ECU, &cts(1, 0).encode(), 1800));
        let events = tap.push(&frame(TESTER, &[0x22, 13, 14, 15, 16, 17, 18, 19], 2700));
        assert_eq!(notices(&events), []);
        assert!(tap.is_receiving(Side::A));
        let events = tap.push(&frame(OTHER, &[0xFF], 3700));
        assert_eq!(
            notices(&events),
            [(Side::A, NoticeKind::TimedOut { gap_us: N_CR_US })]
        );
    }

    #[test]
    fn a_frame_stamped_before_the_timer_started_times_nothing_out() {
        let mut tap = tap();
        tap.push(&frame(TESTER, &[0x10, 0x14, 0, 1, 2, 3, 4, 5], 5_000));
        assert_eq!(tap.push(&frame(OTHER, &[0xFF], 0)), []);
        assert!(tap.is_receiving(Side::A));
    }

    #[test]
    fn a_senders_frame_stamped_earlier_never_moves_the_timer_or_last_time_back() {
        let events = feed(
            &mut tap(),
            &[
                stamped(TESTER, &[0x10, 0x1B, 0, 1, 2, 3, 4, 5], 5_000_000),
                stamped(ECU, &cts(0, 0).encode(), 5_000_100),
                stamped(TESTER, &[0x21, 6, 7, 8, 9, 10, 11, 12], 0),
                stamped(TESTER, &[0x22, 13, 14, 15, 16, 17, 18, 19], 5_000_200),
                stamped(TESTER, &[0x23, 20, 21, 22, 23, 24, 25, 26], 1),
            ],
        );
        assert_eq!(notices(&events), []);
        let message = &messages(events)[0];
        assert_eq!(
            (message.first_at_us, message.last_at_us),
            (5_000_000, 5_000_200)
        );
    }

    #[test]
    fn a_flow_control_that_is_not_due_drops_nothing_and_counts_no_wait() {
        let waits = TapConfig::DEFAULT_WAIT_LIMIT + 1;
        let undue = [
            (vec![vec![0x32, 0, 0]], 2),
            (vec![vec![0x35, 0, 0]], 1),
            (vec![wait().encode(); waits as usize], 1 + waits),
        ];
        for (flow_controls, counted) in undue {
            let mut frames = vec![
                stamped(TESTER, &[0x10, 0x14, 0, 1, 2, 3, 4, 5], 0),
                stamped(ECU, &cts(0, 0).encode(), 100),
                stamped(TESTER, &[0x21, 6, 7, 8, 9, 10, 11, 12], 200),
            ];
            frames.extend(flow_controls.iter().map(|fc| stamped(ECU, fc, 300)));
            frames.push(stamped(TESTER, &[0x22, 13, 14, 15, 16, 17, 18, 19], 400));
            let events = feed(&mut tap(), &frames);
            assert_eq!(notices(&events), [], "{flow_controls:02x?}");
            let message = &messages(events)[0];
            assert_eq!(message.data, (0..20).collect::<Vec<u8>>());
            assert_eq!(message.flow_control_count, counted, "{flow_controls:02x?}");
        }
    }

    #[test]
    fn a_gap_just_under_n_cr_keeps_the_message() {
        let data = message(20);
        let mut frames = multi_frame(TESTER, &data, ECU, cts(0, 0), 0);
        let under = N_CR.as_millis() as u64 - 1;
        for (i, frame) in frames.iter_mut().enumerate().skip(2) {
            frame.at_us = ms(under * (i as u64 - 1));
        }
        let events = feed(&mut tap(), &frames);
        assert_eq!(notices(&events), []);
        assert_eq!(messages(events)[0].data, data);
    }

    #[test]
    fn a_new_start_supersedes_the_message_in_progress() {
        let mut tap = tap();
        tap.push(&frame(TESTER, &[0x10, 0x14, 0, 1, 2, 3, 4, 5], 0));
        let events = tap.push(&frame(TESTER, &[0x01, 0x3E], 1));
        assert_eq!(notices(&events), [(Side::A, NoticeKind::Superseded)]);
        assert_eq!(messages(events)[0].data, [0x3E]);
    }

    #[test]
    fn waits_are_reported_and_kept_with_the_message() {
        let data = message(10);
        let mut frames = multi_frame(TESTER, &data, ECU, cts(0, 0), 10);
        frames.insert(1, frame(ECU, &wait().encode(), 10));
        let events = feed(&mut tap(), &frames);
        assert_eq!(notices(&events), [(Side::A, NoticeKind::Wait)]);
        assert_eq!(messages(events)[0].flow_controls, [wait(), cts(0, 0)]);
    }

    #[test]
    fn one_wait_past_the_wait_limit_drops_the_message() {
        let mut tap = tap();
        tap.push(&frame(TESTER, &[0x10, 0x14, 0, 1, 2, 3, 4, 5], 0));
        let limit = TapConfig::DEFAULT_WAIT_LIMIT as u64;
        let waits: Vec<TimedFrame> = (1..=limit + 1)
            .map(|i| frame(ECU, &wait().encode(), i))
            .collect();
        let events = feed(&mut tap, &waits);
        let kinds: Vec<NoticeKind> = notices(&events).into_iter().map(|(_, kind)| kind).collect();
        assert_eq!(kinds.len() as u64, limit + 1);
        assert!(
            kinds[..limit as usize]
                .iter()
                .all(|&kind| kind == NoticeKind::Wait)
        );
        assert_eq!(kinds.last(), Some(&NoticeKind::TooManyWaits));
        assert!(!tap.is_receiving(Side::A));
    }

    #[test]
    fn a_continue_to_send_restarts_the_wait_count() {
        let mut tap = tap();
        tap.push(&frame(TESTER, &[0x10, 0x14, 0, 1, 2, 3, 4, 5], 0));
        let limit = TapConfig::DEFAULT_WAIT_LIMIT as u64;
        for i in 0..limit {
            tap.push(&frame(ECU, &wait().encode(), 1 + i));
        }
        tap.push(&frame(ECU, &cts(1, 0).encode(), 20));
        tap.push(&frame(TESTER, &[0x21, 6, 7, 8, 9, 10, 11, 12], 21));
        for i in 0..limit {
            let events = tap.push(&frame(ECU, &wait().encode(), 22 + i));
            assert_eq!(notices(&events), [(Side::A, NoticeKind::Wait)]);
        }
        assert!(tap.is_receiving(Side::A));
    }

    #[test]
    fn the_flow_controls_kept_per_message_are_capped_and_all_are_counted() {
        let mut tap = tap();
        tap.push(&frame(TESTER, &[0x10, 0x0D, 0, 1, 2, 3, 4, 5], 0));
        let sent = TapMessage::MAX_FLOW_CONTROLS as u64 + 36;
        for i in 0..sent {
            tap.push(&frame(ECU, &cts(0, 0).encode(), 1 + i / 100));
        }
        let events = tap.push(&frame(TESTER, &[0x21, 6, 7, 8, 9, 10, 11, 12], 2));
        let message = &messages(events)[0];
        assert_eq!(message.flow_controls.len(), TapMessage::MAX_FLOW_CONTROLS);
        assert_eq!(u64::from(message.flow_control_count), sent);
    }

    #[test]
    fn an_overflow_or_reserved_flow_status_drops_the_message() {
        for (fc, kind) in [
            ([0x32, 0, 0], NoticeKind::Overflow),
            ([0x35, 0, 0], NoticeKind::ReservedFlowStatus { status: 5 }),
        ] {
            let mut tap = tap();
            tap.push(&frame(TESTER, &[0x10, 0x14, 0, 1, 2, 3, 4, 5], 0));
            let events = tap.push(&frame(ECU, &fc, 1));
            assert_eq!(notices(&events), [(Side::A, kind)]);
            assert!(!tap.is_receiving(Side::A));
        }
    }

    #[test]
    fn joining_mid_message_skips_to_the_next_start() {
        let mut tap = tap();
        let events = feed(
            &mut tap,
            &[
                frame(TESTER, &[0x23, 1, 2, 3, 4, 5, 6, 7], 0),
                frame(TESTER, &[0x24, 1, 2], 1),
                frame(TESTER, &[0x02, 0x22, 0xF1], 2),
            ],
        );
        assert_eq!(
            notices(&events),
            [(Side::A, NoticeKind::Resynchronised { skipped: 2 })]
        );
        assert_eq!(messages(events)[0].data, [0x22, 0xF1]);
    }

    #[test]
    fn a_frame_on_the_pairs_id_with_another_address_byte_is_ignored_as_another_id_is() {
        let mut tap = extended(TESTER, ECU);
        let mut wide = frame(TESTER, &[0x10, 0x01, 0x3E], 0);
        wide.extended = true;
        assert_eq!(tap.push(&wide), []);
        assert_eq!(tap.push(&frame(OTHER, &[0x10, 0x01, 0x3E], 1)), []);
        assert_eq!(tap.push(&frame(TESTER, &[0xF1, 0x01, 0x3E], 2)), []);
        let events = tap.push(&frame(TESTER, &[0x10, 0x01, 0x3E], 3));
        assert_eq!(notices(&events), []);
        assert_eq!(messages(events)[0].data, [0x3E]);
        let events = tap.push(&frame(ECU, &[0xF1, 0x01, 0x7E], 4));
        assert_eq!(messages(events)[0].from, Side::B);
    }

    #[test]
    fn one_id_both_ways_is_told_apart_by_its_address_bytes() {
        let mut tap = extended(TESTER, TESTER);
        let events = feed(
            &mut tap,
            &[
                frame(TESTER, &[0x10, 0x02, 0x10, 0x03], 0),
                frame(TESTER, &[0xF1, 0x02, 0x50, 0x03], 1),
                frame(TESTER, &[0x55, 0x01, 0x3E], 2),
            ],
        );
        let got: Vec<(Side, Vec<u8>)> = messages(events)
            .into_iter()
            .map(|m| (m.from, m.data))
            .collect();
        assert_eq!(
            got,
            [(Side::A, vec![0x10, 0x03]), (Side::B, vec![0x50, 0x03])]
        );
    }

    #[test]
    fn a_config_whose_sides_cannot_be_told_apart_is_refused() {
        assert_eq!(
            IsoTpTap::new(TapConfig::new(TESTER, TESTER, false)).unwrap_err(),
            IndistinctSides { id: TESTER }
        );
        let mut config = TapConfig::new(TESTER, TESTER, false);
        config.framing.addressing = Addressing::Mixed { tx: 0x55, rx: 0x55 };
        assert!(IsoTpTap::new(config).is_err());
    }

    #[test]
    fn a_first_frame_over_the_cap_is_too_long_and_its_frames_are_skipped() {
        let mut config = TapConfig::new(TESTER, ECU, false);
        config.framing.max_message = 8_000;
        let mut tap = IsoTpTap::new(config).unwrap();
        let events = feed(
            &mut tap,
            &[
                frame(TESTER, &[0x10, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0, 0], 0),
                frame(TESTER, &[0x21, 0, 0, 0, 0, 0, 0, 0], 1),
                frame(TESTER, &[0x01, 0x3E], 2),
            ],
        );
        assert_eq!(
            notices(&events),
            [
                (
                    Side::A,
                    NoticeKind::TooLong {
                        len: u32::MAX as usize
                    }
                ),
                (Side::A, NoticeKind::Resynchronised { skipped: 1 }),
            ]
        );
        assert!(!tap.is_receiving(Side::A));
    }

    #[test]
    fn a_too_long_first_frame_while_lost_is_one_notice() {
        let mut config = TapConfig::new(TESTER, ECU, false);
        config.framing.max_message = 8_000;
        let mut tap = IsoTpTap::new(config).unwrap();
        tap.push(&frame(TESTER, &[0x24, 1, 2, 3], 0));
        let events = tap.push(&frame(TESTER, &[0x10, 0x00, 0, 0, 0x27, 0x10, 0, 0], 1));
        assert_eq!(
            notices(&events),
            [(Side::A, NoticeKind::TooLong { len: 10_000 })]
        );
    }

    #[test]
    fn an_announced_length_reserves_at_most_4095_bytes() {
        let mut config = TapConfig::new(TESTER, ECU, false);
        config.framing.max_message = u32::MAX;
        let mut tap = IsoTpTap::new(config).unwrap();
        tap.push(&frame(
            TESTER,
            &[0x10, 0x00, 0xFF, 0xFF, 0xFF, 0xF0, 0xAA, 0xBB],
            0,
        ));
        let receiving = tap.sides[Side::A.index()].receiving.as_ref().unwrap();
        assert_eq!(receiving.len, 0xFFFF_FFF0);
        assert!(receiving.message.capacity() <= crate::MAX_MESSAGE);
    }

    #[test]
    fn a_consecutive_frame_longer_than_the_first_frame_is_skipped() {
        let mut config = TapConfig::new(TESTER, ECU, false);
        config.framing = Framing::new(
            Addressing::Normal,
            FrameFormat::Fd {
                length: crate::FdLength::MAX,
            },
        );
        let mut tap = IsoTpTap::new(config).unwrap();
        tap.push(&frame(TESTER, &[0x10, 0x0A, 0, 1, 2, 3, 4, 5], 0));
        tap.push(&frame(
            TESTER,
            &[0x21, 6, 7, 8, 9, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC],
            1,
        ));
        assert!(tap.is_receiving(Side::A));
        let events = tap.push(&frame(TESTER, &[0x21, 6, 7, 8, 9], 2));
        assert_eq!(messages(events)[0].data, [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]);
    }

    #[test]
    fn the_skipped_count_saturates() {
        let mut tap = tap();
        tap.sides[Side::A.index()].skipped = u32::MAX;
        tap.push(&frame(TESTER, &[0x21, 0], 0));
        let events = tap.push(&frame(TESTER, &[0x01, 0x3E], 1));
        assert_eq!(
            notices(&events),
            [(Side::A, NoticeKind::Resynchronised { skipped: u32::MAX })]
        );
    }
}
