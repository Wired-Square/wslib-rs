use std::collections::HashMap;
use std::time::Duration;

use crate::flow_control::FlowStatus;
use crate::framing::{Addressing, FdLength, FrameFormat, Framing, Pdu};
use crate::pci::{CLASSIC_LEN, LOW_NIBBLE, SN_FIRST};
use crate::tap::{TimedFrame, micros};

/// How soon after a first frame, or after a wait answering it, a flow control
/// on another id must come to answer it.
pub const DEFAULT_FLOW_CONTROL_WINDOW: Duration = Duration::from_millis(100);

/// The most leading bytes an id's frames may carry and still be read as
/// extended or mixed addressing, one target per byte.
pub const MAX_ADDRESS_BYTES: usize = 8;

const MAX_CANDIDATES: usize = 4;

/// One id's frames by the kind their first byte gives them.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(rename = "IsoTpKindCounts"))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct KindCounts {
    pub single: u32,
    pub first: u32,
    pub consecutive: u32,
    pub flow_control: u32,
    /// Frames no ISO-TP frame could be: empty, of a reserved type, a flow
    /// control too short or with a reserved status.
    pub undecodable: u32,
    /// Single or first frames whose length their frame cannot carry, or a
    /// first frame whose length a single frame could have carried.
    pub bad_length: u32,
    /// Consecutive frames out of sequence, too long, or continuing nothing,
    /// and flow controls that ended up answering no completed message.
    pub sequence_breaks: u32,
}

/// What one id's frames, or one address byte's on that id, say about whether
/// they carry ISO-TP.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(rename = "IsoTpIdEvidence"))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct IdEvidence {
    pub id: u32,
    pub extended: bool,
    pub frames: u32,
    pub counts: KindCounts,
    /// The address byte these frames lead with, when the id reads as
    /// extended or mixed addressing; it is then reported once per byte.
    pub address_byte: Option<u8>,
    /// Some frame was over 8 bytes.
    pub fd: bool,
    /// Multi-frame messages these frames sent or answered with flow control,
    /// each complete and its pairing settled.
    pub exchanges: u32,
    /// Messages sent here that completed, but whose answering id could not
    /// be settled. They make no pair and no exchange.
    pub ambiguous: u32,
    /// Every frame decodes, every length fits, and an exchange completed. An
    /// id carrying only single frames is never called ISO-TP: a single
    /// frame's first byte cannot be told from a signal's.
    pub iso_tp: bool,
}

/// Two ids that completed a multi-frame exchange: a first frame on one, a
/// flow control on the other within the window, and the consecutive frames
/// that finish the message.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(rename = "IsoTpPair"))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct Pair {
    /// The lower id, or on one id the lower address byte.
    pub a_id: u32,
    pub b_id: u32,
    pub extended: bool,
    /// As side A's framing would set it.
    pub addressing: Addressing,
    pub fd: bool,
    /// Exchanges A sent and B answered.
    pub from_a: u32,
    pub from_b: u32,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(rename = "IsoTpDetection"))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct Detection {
    /// Every id, or id and address byte, in the order first seen.
    pub ids: Vec<IdEvidence>,
    /// In the order their first exchange completed.
    pub pairs: Vec<Pair>,
}

/// Which ids in `frames`, in the order seen, carry ISO-TP, and which pairs of
/// them talk.
///
/// Each id is read with normal addressing and, if its frames lead with at
/// most [`MAX_ADDRESS_BYTES`] distinct bytes, with that byte as an address;
/// it keeps the reading under which more of its exchanges complete, normal
/// on a tie. A flow control within `window` of a first frame is a candidate
/// answer to it; a wait from a candidate extends the window. Each sender's
/// answering id is settled across all its completed messages.
pub fn detect(frames: &[TimedFrame], window: Duration) -> Detection {
    let normal = Reading::run(frames, window, |_| Some(None));
    let addressable = addressable_ids(frames);
    let addressed = Reading::run(frames, window, |frame| {
        addressable
            .get(&(frame.id, frame.extended))
            .copied()
            .unwrap_or(false)
            .then(|| frame.data.first().copied())
    });
    let mut exchanges: HashMap<(u32, bool), (u32, u32)> = HashMap::new();
    for (_, evidence) in &normal.ids {
        exchanges
            .entry((evidence.id, evidence.extended))
            .or_default()
            .0 += evidence.exchanges;
    }
    for (_, evidence) in &addressed.ids {
        exchanges
            .entry((evidence.id, evidence.extended))
            .or_default()
            .1 += evidence.exchanges;
    }
    let reads_addressed = |id: u32, extended: bool| {
        exchanges
            .get(&(id, extended))
            .is_some_and(|(normal, addressed)| addressed > normal)
    };
    let mut ids = Vec::new();
    let mut pairs = Vec::new();
    for (judged, addressed) in [(normal, false), (addressed, true)] {
        ids.extend(
            judged.ids.into_iter().filter(|(_, evidence)| {
                reads_addressed(evidence.id, evidence.extended) == addressed
            }),
        );
        pairs.extend(judged.pairs.into_iter().filter(|(_, pair)| {
            reads_addressed(pair.a_id, pair.extended) == addressed
                && reads_addressed(pair.b_id, pair.extended) == addressed
        }));
    }
    ids.sort_by_key(|(first_seen, _)| *first_seen);
    pairs.sort_by_key(|(first_exchange, _)| *first_exchange);
    Detection {
        ids: ids.into_iter().map(|(_, evidence)| evidence).collect(),
        pairs: pairs.into_iter().map(|(_, pair)| pair).collect(),
    }
}

fn addressable_ids(frames: &[TimedFrame]) -> HashMap<(u32, bool), bool> {
    let mut leading: HashMap<(u32, bool), Option<Vec<u8>>> = HashMap::new();
    for frame in frames {
        let bytes = leading
            .entry((frame.id, frame.extended))
            .or_insert_with(|| Some(Vec::new()));
        let Some(seen) = bytes else {
            continue;
        };
        match frame.data.first() {
            None => *bytes = None,
            Some(byte) if seen.contains(byte) => {}
            Some(_) if seen.len() == MAX_ADDRESS_BYTES => *bytes = None,
            Some(&byte) => seen.push(byte),
        }
    }
    leading
        .into_iter()
        .map(|(id, bytes)| (id, bytes.is_some()))
        .collect()
}

fn reader(address_byte: Option<u8>) -> Framing {
    let addressing = address_byte.map_or(Addressing::Normal, |byte| Addressing::Extended {
        tx: byte,
        rx: byte,
    });
    let mut framing = Framing::new(addressing, FrameFormat::Fd(FdLength::MAX));
    framing.max_message = u32::MAX;
    framing
}

type Key = (u32, bool, Option<u8>);

struct Candidate {
    track: usize,
    flow_controls: Vec<usize>,
    alone_first: bool,
}

struct Open {
    len: usize,
    received: usize,
    next_sn: u8,
    cf_capacity: usize,
    deadline_us: u64,
    candidates: Vec<Candidate>,
    cleared: bool,
    started: bool,
}

struct Completion {
    order: usize,
    candidates: Vec<Candidate>,
}

struct Track {
    reader: Framing,
    evidence: IdEvidence,
    first_seen: usize,
    open: Option<Open>,
    completions: Vec<Completion>,
}

struct Reading {
    window_us: u64,
    index: HashMap<Key, usize>,
    tracks: Vec<Track>,
    opens: Vec<usize>,
}

struct Judged {
    ids: Vec<(usize, IdEvidence)>,
    pairs: Vec<(usize, Pair)>,
}

impl Reading {
    fn run(
        frames: &[TimedFrame],
        window: Duration,
        address_byte: impl Fn(&TimedFrame) -> Option<Option<u8>>,
    ) -> Judged {
        let mut reading = Self {
            window_us: micros(window),
            index: HashMap::new(),
            tracks: Vec::new(),
            opens: Vec::new(),
        };
        for (order, frame) in frames.iter().enumerate() {
            if let Some(byte) = address_byte(frame) {
                reading.frame(order, (frame.id, frame.extended, byte), frame);
            }
        }
        reading.settle()
    }

    fn track(&mut self, order: usize, key: Key) -> usize {
        let tracks = &mut self.tracks;
        *self.index.entry(key).or_insert_with(|| {
            let (id, extended, address_byte) = key;
            tracks.push(Track {
                reader: reader(address_byte),
                evidence: IdEvidence {
                    id,
                    extended,
                    frames: 0,
                    counts: KindCounts::default(),
                    address_byte,
                    fd: false,
                    exchanges: 0,
                    ambiguous: 0,
                    iso_tp: false,
                },
                first_seen: order,
                open: None,
                completions: Vec::new(),
            });
            tracks.len() - 1
        })
    }

    fn frame(&mut self, order: usize, key: Key, frame: &TimedFrame) {
        self.close_expired(frame.at_us);
        let at = self.track(order, key);
        let track = &mut self.tracks[at];
        track.evidence.frames += 1;
        track.evidence.fd |= frame.data.len() > CLASSIC_LEN;
        let counts = &mut track.evidence.counts;
        match track.reader.decode(&frame.data) {
            None | Some(Pdu::FlowControl(Err(_))) => {
                counts.undecodable += 1;
                track.open = None;
            }
            Some(Pdu::Single(single)) => {
                track.open = None;
                match single {
                    Some(_) => counts.single += 1,
                    None => counts.bad_length += 1,
                }
            }
            Some(Pdu::First(None)) => {
                track.open = None;
                counts.bad_length += 1;
            }
            Some(Pdu::First(Some(first))) => {
                counts.first += 1;
                if track.open.is_none() {
                    self.opens.push(at);
                }
                self.tracks[at].open = Some(Open {
                    len: first.len,
                    received: first.data.len(),
                    next_sn: SN_FIRST,
                    cf_capacity: first.cf_capacity,
                    deadline_us: frame.at_us.saturating_add(self.window_us),
                    candidates: Vec::new(),
                    cleared: false,
                    started: false,
                });
            }
            Some(Pdu::Consecutive { sn, data }) => {
                counts.consecutive += 1;
                self.consecutive(at, order, sn, data.len());
            }
            Some(Pdu::FlowControl(Ok(flow))) => {
                counts.flow_control += 1;
                self.flow_control(at, order, frame.at_us, flow.status);
            }
        }
    }

    fn close_expired(&mut self, now: u64) {
        let tracks = &mut self.tracks;
        self.opens.retain(|&at| {
            let open = &mut tracks[at].open;
            if open
                .as_ref()
                .is_some_and(|open| !open.started && now > open.deadline_us)
            {
                *open = None;
            }
            open.is_some()
        });
    }

    fn consecutive(&mut self, at: usize, order: usize, sn: u8, carried: usize) {
        let track = &mut self.tracks[at];
        let continues = track.open.as_mut().filter(|open| {
            let needed = (open.len - open.received).min(open.cf_capacity);
            open.cleared && open.next_sn == sn && (needed..=open.cf_capacity).contains(&carried)
        });
        let Some(open) = continues else {
            track.evidence.counts.sequence_breaks += 1;
            track.open = None;
            return;
        };
        open.started = true;
        open.received += open.cf_capacity;
        open.next_sn = (sn + 1) & LOW_NIBBLE;
        if open.received < open.len {
            return;
        }
        if let Some(open) = track.open.take() {
            track.completions.push(Completion {
                order,
                candidates: open.candidates,
            });
        }
    }

    fn flow_control(&mut self, answerer: usize, order: usize, now: u64, status: FlowStatus) {
        let (extended, addressed) = {
            let evidence = &self.tracks[answerer].evidence;
            (evidence.extended, evidence.address_byte.is_some())
        };
        let mut first_answered = Vec::new();
        for &sender in &self.opens {
            let track = &mut self.tracks[sender];
            let compatible = sender != answerer
                && track.evidence.extended == extended
                && track.evidence.address_byte.is_some() == addressed;
            let Some(open) = track.open.as_mut().filter(|_| compatible) else {
                continue;
            };
            let known = open.candidates.iter().position(|c| c.track == answerer);
            let candidate = match known {
                Some(known) => &mut open.candidates[known],
                None if !open.started
                    && now <= open.deadline_us
                    && open.candidates.len() < MAX_CANDIDATES =>
                {
                    if open.candidates.is_empty() {
                        first_answered.push(sender);
                    }
                    open.candidates.push(Candidate {
                        track: answerer,
                        flow_controls: Vec::new(),
                        alone_first: false,
                    });
                    open.candidates.last_mut().expect("just pushed")
                }
                None => continue,
            };
            candidate.flow_controls.push(order);
            let extends = match status {
                FlowStatus::ContinueToSend => !std::mem::replace(&mut open.cleared, true),
                FlowStatus::Wait => true,
                FlowStatus::Overflow => false,
            };
            if extends && !open.started {
                open.deadline_us = open.deadline_us.max(now.saturating_add(self.window_us));
            }
        }
        if let [sender] = first_answered[..]
            && let Some(open) = &mut self.tracks[sender].open
        {
            open.candidates[0].alone_first = true;
        }
    }

    fn settle(mut self) -> Judged {
        let clean: Vec<bool> = self
            .tracks
            .iter()
            .map(|track| track.evidence.counts.undecodable == 0)
            .collect();
        let mut credited = Vec::new();
        let mut settled = Vec::new();
        for sender in 0..self.tracks.len() {
            let completions = std::mem::take(&mut self.tracks[sender].completions);
            let winner = answering_id(&completions, &clean);
            for completion in completions {
                let won = winner.and_then(|winner| {
                    completion
                        .candidates
                        .iter()
                        .find(|candidate| candidate.track == winner)
                });
                match won {
                    Some(candidate) => {
                        credited.extend(
                            candidate
                                .flow_controls
                                .iter()
                                .map(|&fc| (candidate.track, fc)),
                        );
                        settled.push((completion.order, sender, candidate.track));
                    }
                    None => self.tracks[sender].evidence.ambiguous += 1,
                }
            }
        }
        credited.sort_unstable();
        credited.dedup();
        let mut answered = vec![0_u32; self.tracks.len()];
        for (track, _) in credited {
            answered[track] += 1;
        }
        settled.sort_by_key(|(order, ..)| *order);
        let mut pairs = Vec::new();
        for (order, sender, receiver) in settled {
            paired(&mut self.tracks, order, sender, receiver, &mut pairs);
        }
        let ids = self
            .tracks
            .into_iter()
            .zip(answered)
            .map(|(track, answered)| {
                let mut evidence = track.evidence;
                let counts = &mut evidence.counts;
                counts.sequence_breaks += counts.flow_control.saturating_sub(answered);
                evidence.iso_tp =
                    counts.undecodable == 0 && counts.bad_length == 0 && evidence.exchanges > 0;
                (track.first_seen, evidence)
            })
            .collect();
        Judged { ids, pairs }
    }
}

/// The id answering a sender's messages: among clean candidates if there are
/// any, the one in the most of them, a tie broken by the messages it answered
/// first and answered no other at once. It must beat every rival, and be in
/// more than half of them or have no rival in more than one.
fn answering_id(completions: &[Completion], clean: &[bool]) -> Option<usize> {
    let mut tally: Vec<(usize, (usize, usize))> = Vec::new();
    for candidate in completions.iter().flat_map(|c| &c.candidates) {
        let score = match tally
            .iter_mut()
            .find(|(track, _)| *track == candidate.track)
        {
            Some((_, score)) => score,
            None => {
                tally.push((candidate.track, (0, 0)));
                &mut tally.last_mut().expect("just pushed").1
            }
        };
        score.0 += 1;
        score.1 += usize::from(candidate.alone_first);
    }
    if tally.iter().any(|&(track, _)| clean[track]) {
        tally.retain(|&(track, _)| clean[track]);
    }
    tally.sort_by_key(|&(_, score)| std::cmp::Reverse(score));
    let &(top, score) = tally.first()?;
    let rival = tally.get(1).map_or((0, 0), |&(_, score)| score);
    (score > rival && (2 * score.0 > completions.len() || rival.0 <= 1)).then_some(top)
}

fn paired(
    tracks: &mut [Track],
    order: usize,
    sender: usize,
    receiver: usize,
    pairs: &mut Vec<(usize, Pair)>,
) {
    tracks[sender].evidence.exchanges += 1;
    tracks[receiver].evidence.exchanges += 1;
    let rank = |i: usize| (tracks[i].evidence.id, tracks[i].evidence.address_byte);
    let (a, b) = if rank(sender) <= rank(receiver) {
        (sender, receiver)
    } else {
        (receiver, sender)
    };
    let (a_ev, b_ev) = (&tracks[a].evidence, &tracks[b].evidence);
    let addressing = match (a_ev.address_byte, b_ev.address_byte) {
        (Some(tx), Some(rx)) => Addressing::Extended { tx, rx },
        _ => Addressing::Normal,
    };
    let position = pairs.iter().position(|(_, pair)| {
        (pair.a_id, pair.b_id, pair.extended, pair.addressing)
            == (a_ev.id, b_ev.id, a_ev.extended, addressing)
    });
    let pair = match position {
        Some(position) => &mut pairs[position].1,
        None => {
            pairs.push((
                order,
                Pair {
                    a_id: a_ev.id,
                    b_id: b_ev.id,
                    extended: a_ev.extended,
                    addressing,
                    fd: false,
                    from_a: 0,
                    from_b: 0,
                },
            ));
            &mut pairs.last_mut().expect("just pushed").1
        }
    };
    pair.fd = a_ev.fd || b_ev.fd;
    if sender == a {
        pair.from_a += 1;
    } else {
        pair.from_b += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flow_control::{FlowControl, StMin};
    use crate::segment::Segmenter;

    const TESTER: u32 = 0x7E0;
    const ECU: u32 = 0x7E8;
    const WINDOW: Duration = DEFAULT_FLOW_CONTROL_WINDOW;
    const CTS: FlowControl = FlowControl {
        status: FlowStatus::ContinueToSend,
        block_size: 0,
        st_min: StMin(0),
    };

    struct Bus {
        frames: Vec<TimedFrame>,
        now: Duration,
    }

    impl Bus {
        fn new() -> Self {
            Self {
                frames: Vec::new(),
                now: Duration::ZERO,
            }
        }

        fn send(&mut self, id: u32, data: Vec<u8>) {
            self.after(Duration::from_millis(1), id, data);
        }

        fn after(&mut self, gap: Duration, id: u32, data: Vec<u8>) {
            self.now += gap;
            self.frames.push(TimedFrame {
                id,
                extended: false,
                data,
                at_us: micros(self.now),
            });
        }

        fn exchange(&mut self, framing: &Framing, from: u32, to: u32, message: &[u8]) {
            let segmenter = Segmenter::with_framing(message, framing).unwrap();
            self.send(from, segmenter.first());
            if segmenter.is_single() {
                return;
            }
            self.send(to, framing.peer().encode_flow_control(&CTS));
            for frame in segmenter {
                self.send(from, frame);
            }
        }

        fn diagnostics(&mut self, framing: &Framing) {
            self.diagnose(framing, TESTER, ECU);
        }

        fn diagnose(&mut self, framing: &Framing, tester: u32, ecu: u32) {
            for _ in 0..3 {
                self.exchange(framing, tester, ecu, &[0x22, 0xF1, 0x90]);
                self.exchange(&framing.peer(), ecu, tester, &[0x62; 20]);
            }
        }
    }

    fn evidence(detection: &Detection, id: u32) -> &IdEvidence {
        detection.ids.iter().find(|ids| ids.id == id).unwrap()
    }

    fn extended(tx: u8, rx: u8) -> Framing {
        Framing::new(Addressing::Extended { tx, rx }, FrameFormat::Classic)
    }

    fn ecu_reply() -> (Vec<u8>, Vec<Vec<u8>>) {
        let segmenter = Segmenter::new(&[0x62; 20]).unwrap();
        (segmenter.first(), segmenter.collect())
    }

    #[test]
    fn a_completed_multi_frame_exchange_makes_both_ids_iso_tp_and_a_pair() {
        let mut bus = Bus::new();
        bus.diagnostics(&Framing::default());
        let detection = detect(&bus.frames, WINDOW);
        let ecu = evidence(&detection, ECU);
        assert!(ecu.iso_tp);
        assert_eq!(
            ecu.counts,
            KindCounts {
                first: 3,
                consecutive: 6,
                ..KindCounts::default()
            }
        );
        assert_eq!(ecu.exchanges, 3);
        let tester = evidence(&detection, TESTER);
        assert!(tester.iso_tp);
        assert_eq!((tester.counts.single, tester.counts.flow_control), (3, 3));
        assert_eq!(tester.counts.sequence_breaks, 0);
        assert_eq!(
            detection.pairs,
            [Pair {
                a_id: TESTER,
                b_id: ECU,
                extended: false,
                addressing: Addressing::Normal,
                fd: false,
                from_a: 0,
                from_b: 3,
            }]
        );
    }

    #[test]
    fn a_leading_byte_under_which_exchanges_complete_is_an_address() {
        let mut bus = Bus::new();
        bus.diagnostics(&extended(0x10, 0xF1));
        let detection = detect(&bus.frames, WINDOW);
        assert_eq!(evidence(&detection, TESTER).address_byte, Some(0x10));
        assert_eq!(evidence(&detection, ECU).address_byte, Some(0xF1));
        assert_eq!(
            detection.pairs[0].addressing,
            Addressing::Extended { tx: 0x10, rx: 0xF1 }
        );
    }

    #[test]
    fn an_address_byte_that_also_reads_as_normal_pci_is_found_from_completed_exchanges() {
        for byte in [0x12, 0x05, 0x40] {
            let mut ecu = extended(byte, 0xF1);
            ecu.padding = Some(0xFF);
            let mut bus = Bus::new();
            for _ in 0..3 {
                bus.exchange(&ecu.peer(), 0x6F1, 0x612, &[0x22, 0xF1, 0x90]);
                bus.exchange(&ecu, 0x612, 0x6F1, &[0x62; 20]);
                bus.exchange(&ecu.peer(), 0x6F1, 0x612, &[0x2E; 12]);
            }
            let detection = detect(&bus.frames, WINDOW);
            let ids: Vec<(u32, Option<u8>, bool)> = detection
                .ids
                .iter()
                .map(|ids| (ids.id, ids.address_byte, ids.iso_tp))
                .collect();
            assert_eq!(
                ids,
                [(0x6F1, Some(0xF1), true), (0x612, Some(byte), true)],
                "{byte:#04x}"
            );
            assert_eq!(
                detection.pairs,
                [Pair {
                    a_id: 0x612,
                    b_id: 0x6F1,
                    extended: false,
                    addressing: Addressing::Extended { tx: byte, rx: 0xF1 },
                    fd: false,
                    from_a: 3,
                    from_b: 3,
                }],
                "{byte:#04x}"
            );
        }
    }

    #[test]
    fn a_shared_tester_id_addressing_several_targets_pairs_each_target() {
        const SHARED: u32 = 0x6F1;
        let mut bus = Bus::new();
        bus.diagnose(&extended(0x10, 0xF1), SHARED, 0x610);
        bus.diagnose(&extended(0x20, 0xF1), SHARED, 0x620);
        let detection = detect(&bus.frames, WINDOW);
        let shared: Vec<Option<u8>> = detection
            .ids
            .iter()
            .filter(|ids| ids.id == SHARED)
            .map(|ids| ids.address_byte)
            .collect();
        assert_eq!(shared, [Some(0x10), Some(0x20)]);
        let pairs: Vec<(u32, u32, Addressing, u32)> = detection
            .pairs
            .iter()
            .map(|pair| (pair.a_id, pair.b_id, pair.addressing, pair.from_a))
            .collect();
        assert_eq!(
            pairs,
            [
                (
                    0x610,
                    SHARED,
                    Addressing::Extended { tx: 0xF1, rx: 0x10 },
                    3
                ),
                (
                    0x620,
                    SHARED,
                    Addressing::Extended { tx: 0xF1, rx: 0x20 },
                    3
                ),
            ]
        );
    }

    #[test]
    fn an_id_with_more_leading_bytes_than_the_cap_is_one_entry() {
        let mut bus = Bus::new();
        for i in 0..=255_u8 {
            bus.send(0x300, vec![i, 0x02, 0x11, 0x22, 0, 0, 0, 0]);
        }
        let detection = detect(&bus.frames, WINDOW);
        assert_eq!(detection.ids.len(), 1);
        assert_eq!(detection.ids[0].address_byte, None);
    }

    #[test]
    fn a_can_fd_conversation_is_detected_as_fd() {
        let framing = Framing::new(Addressing::Normal, FrameFormat::Fd(FdLength::MAX));
        let mut bus = Bus::new();
        bus.exchange(&framing, TESTER, ECU, &[0x36; 300]);
        let detection = detect(&bus.frames, WINDOW);
        assert!(evidence(&detection, TESTER).fd);
        assert!(detection.pairs[0].fd);
        assert_eq!(detection.pairs[0].from_a, 1);
    }

    #[test]
    fn periodic_frames_shaped_like_single_frames_are_not_iso_tp() {
        let mut bus = Bus::new();
        for i in 0..200_u8 {
            bus.after(
                Duration::from_millis(10),
                0x100,
                vec![0x03, i, 0x40, 0x11, 0, 0, 0, 0],
            );
            bus.send(0x101, vec![0x02, 0x00, i, 0, 0, 0, 0, 0]);
        }
        let detection = detect(&bus.frames, WINDOW);
        assert!(detection.ids.iter().all(|ids| !ids.iso_tp));
        assert_eq!(evidence(&detection, 0x100).counts.single, 200);
        assert_eq!(detection.pairs, []);
    }

    #[test]
    fn a_counter_in_the_first_byte_is_not_iso_tp() {
        let mut bus = Bus::new();
        for i in 0..=255_u8 {
            bus.after(
                Duration::from_millis(10),
                0x200,
                vec![i, 0x10, 0, 0, 0, 0, 0, 0],
            );
            bus.send(0x201, vec![0x30, 0x00, 0x00, 0, 0, 0, 0, 0]);
        }
        let detection = detect(&bus.frames, WINDOW);
        let counter = evidence(&detection, 0x200);
        assert!(counter.counts.undecodable > 0);
        assert!(!counter.iso_tp);
        assert!(!evidence(&detection, 0x201).iso_tp);
    }

    #[test]
    fn a_first_frame_look_alike_answered_by_a_flow_control_look_alike_is_not_iso_tp() {
        let mut bus = Bus::new();
        for _ in 0..100 {
            bus.after(
                Duration::from_millis(10),
                0x300,
                vec![0x10, 0x40, 1, 2, 3, 4, 5, 6],
            );
            bus.send(0x301, vec![0x30, 0, 0, 0, 0, 0, 0, 0]);
            bus.send(0x300, vec![0x21, 1, 2, 3, 4, 5, 6, 7]);
            bus.send(0x300, vec![0x22, 1, 2, 3, 4, 5, 6, 7]);
        }
        let detection = detect(&bus.frames, WINDOW);
        assert!(!evidence(&detection, 0x300).iso_tp);
        assert!(!evidence(&detection, 0x301).iso_tp);
        assert_eq!(detection.pairs, []);
    }

    #[test]
    fn a_flow_control_outside_the_window_answers_nothing() {
        let (first, rest) = ecu_reply();
        let mut bus = Bus::new();
        bus.send(ECU, first);
        bus.after(WINDOW + Duration::from_millis(1), TESTER, CTS.encode());
        for frame in rest {
            bus.send(ECU, frame);
        }
        let detection = detect(&bus.frames, WINDOW);
        assert_eq!(detection.pairs, []);
        assert_eq!(evidence(&detection, TESTER).counts.sequence_breaks, 1);
        assert_eq!(evidence(&detection, ECU).counts.sequence_breaks, 2);
    }

    #[test]
    fn the_window_runs_from_the_first_frame_and_flow_controls_do_not_hold_it_open() {
        let (first, rest) = ecu_reply();
        let mut bus = Bus::new();
        bus.send(ECU, first);
        for _ in 0..200 {
            bus.after(WINDOW - Duration::from_millis(1), 0x333, CTS.encode());
        }
        bus.send(TESTER, CTS.encode());
        for frame in rest {
            bus.send(ECU, frame);
        }
        let detection = detect(&bus.frames, WINDOW);
        assert_eq!(detection.pairs, []);
        assert_eq!(evidence(&detection, 0x333).counts.sequence_breaks, 200);
    }

    #[test]
    fn waits_from_a_candidate_extend_the_window() {
        let (first, rest) = ecu_reply();
        let wait = FlowControl {
            status: FlowStatus::Wait,
            ..CTS
        };
        let mut bus = Bus::new();
        bus.send(ECU, first);
        for _ in 0..5 {
            bus.after(WINDOW - Duration::from_millis(1), TESTER, wait.encode());
        }
        bus.after(WINDOW - Duration::from_millis(1), TESTER, CTS.encode());
        for frame in rest {
            bus.send(ECU, frame);
        }
        let detection = detect(&bus.frames, WINDOW);
        assert_eq!(detection.pairs.len(), 1);
        assert_eq!(evidence(&detection, TESTER).counts.sequence_breaks, 0);
    }

    #[test]
    fn real_traffic_beside_noise_is_still_found() {
        let mut bus = Bus::new();
        for i in 0..50_u8 {
            bus.after(
                Duration::from_millis(10),
                0x100,
                vec![0x03, i, 0, 0, 0, 0, 0, 0],
            );
        }
        bus.diagnostics(&Framing::default());
        let detection = detect(&bus.frames, WINDOW);
        let found: Vec<u32> = detection
            .ids
            .iter()
            .filter(|ids| ids.iso_tp)
            .map(|ids| ids.id)
            .collect();
        assert_eq!(found, [TESTER, ECU]);
    }

    #[test]
    fn two_first_frames_answered_from_two_ids_at_once_pair_neither() {
        let tick = Duration::from_micros(200);
        let (first, rest) = ecu_reply();
        let mut bus = Bus::new();
        bus.send(0x7DF, vec![0x02, 0x10, 0x03]);
        bus.send(0x7E8, first.clone());
        bus.after(tick, 0x7E9, first);
        bus.send(0x7E0, CTS.encode());
        bus.after(tick, 0x7E1, CTS.encode());
        for frame in &rest {
            bus.send(0x7E8, frame.clone());
            bus.after(tick, 0x7E9, frame.clone());
        }
        let detection = detect(&bus.frames, WINDOW);
        assert_eq!(detection.pairs, []);
        assert_eq!(evidence(&detection, 0x7E8).ambiguous, 1);
        assert_eq!(evidence(&detection, 0x7E9).ambiguous, 1);
        assert!(detection.ids.iter().all(|ids| !ids.iso_tp));
    }

    #[test]
    fn a_first_frame_look_alike_between_a_first_frame_and_its_flow_control_takes_nothing() {
        let (first, rest) = ecu_reply();
        let mut bus = Bus::new();
        bus.send(ECU, first);
        bus.send(0x100, vec![0x1A, 0x00, 1, 2, 3, 4, 5, 6]);
        bus.send(TESTER, CTS.encode());
        for frame in rest {
            bus.send(ECU, frame);
        }
        bus.send(0x100, vec![0x1A, 0x00, 1, 2, 3, 4, 5, 6]);
        let detection = detect(&bus.frames, WINDOW);
        assert_eq!(detection.pairs.len(), 1);
        assert_eq!(
            (detection.pairs[0].a_id, detection.pairs[0].b_id),
            (TESTER, ECU)
        );
        assert!(!evidence(&detection, 0x100).iso_tp);
    }

    #[test]
    fn a_stray_flow_control_once_loses_to_the_id_answering_every_message() {
        let (first, rest) = ecu_reply();
        let mut bus = Bus::new();
        for round in 0..3 {
            bus.send(TESTER, vec![0x02, 0x22, 0xF1]);
            bus.send(ECU, first.clone());
            if round == 1 {
                bus.send(0x333, vec![0x30, 0x08, 0x00, 0x9C, 0x51, 0x07, 0xE2, 0x14]);
            }
            bus.send(TESTER, CTS.encode());
            for frame in &rest {
                bus.send(ECU, frame.clone());
            }
        }
        let detection = detect(&bus.frames, WINDOW);
        assert_eq!(detection.pairs.len(), 1);
        assert_eq!(detection.pairs[0].from_b, 3);
        assert_eq!(evidence(&detection, ECU).ambiguous, 0);
        assert_eq!(evidence(&detection, 0x333).counts.sequence_breaks, 1);
    }

    #[test]
    fn a_stray_from_an_id_carrying_non_iso_tp_frames_loses_even_once() {
        let (first, rest) = ecu_reply();
        let mut bus = Bus::new();
        bus.send(0x333, vec![0xA5, 1, 2, 3, 4, 5, 6, 7]);
        bus.send(ECU, first);
        bus.send(0x333, vec![0x30, 0x08, 0x00, 0x9C, 0x51, 0x07, 0xE2, 0x14]);
        bus.send(TESTER, CTS.encode());
        for frame in rest {
            bus.send(ECU, frame);
        }
        let detection = detect(&bus.frames, WINDOW);
        assert_eq!(detection.pairs.len(), 1);
        assert_eq!(evidence(&detection, ECU).exchanges, 1);
    }

    #[test]
    fn a_flow_control_look_alike_after_the_answer_every_time_loses_to_the_answer() {
        let (first, rest) = ecu_reply();
        let mut bus = Bus::new();
        for n in 0..20_u8 {
            bus.send(TESTER, vec![0x02, 0x22, 0xF1]);
            bus.send(ECU, first.clone());
            bus.send(TESTER, CTS.encode());
            bus.send(0x100, vec![0x30, 0, 0, n, 0, 0, 0, 0]);
            for frame in &rest {
                bus.send(ECU, frame.clone());
            }
        }
        let detection = detect(&bus.frames, WINDOW);
        let pairs: Vec<(u32, u32, u32)> = detection
            .pairs
            .iter()
            .map(|pair| (pair.a_id, pair.b_id, pair.from_b))
            .collect();
        assert_eq!(pairs, [(TESTER, ECU, 20)]);
        assert_eq!(evidence(&detection, ECU).ambiguous, 0);
        assert!(!evidence(&detection, 0x100).iso_tp);
    }

    #[test]
    fn the_first_to_answer_beats_a_look_alike_that_cleared_during_its_waits() {
        let (first, rest) = ecu_reply();
        let wait = FlowControl {
            status: FlowStatus::Wait,
            ..CTS
        };
        let mut bus = Bus::new();
        for n in 0..20_u8 {
            bus.send(ECU, first.clone());
            bus.send(TESTER, wait.encode());
            bus.send(0x100, vec![0x30, 0, 0, n, 0, 0, 0, 0]);
            bus.send(TESTER, CTS.encode());
            for frame in &rest {
                bus.send(ECU, frame.clone());
            }
        }
        let detection = detect(&bus.frames, WINDOW);
        assert_eq!(detection.pairs.len(), 1);
        assert_eq!(
            (detection.pairs[0].a_id, detection.pairs[0].from_b),
            (TESTER, 20)
        );
    }

    #[test]
    fn one_flow_control_answering_two_senders_at_once_is_credited_once() {
        const ECU_2: u32 = 0x7E9;
        let (first, rest) = ecu_reply();
        let mut bus = Bus::new();
        for ecu in [ECU, ECU_2, ECU, ECU_2] {
            bus.send(ecu, first.clone());
            bus.send(TESTER, CTS.encode());
            for frame in &rest {
                bus.send(ecu, frame.clone());
            }
        }
        bus.send(ECU, first.clone());
        bus.send(ECU_2, first);
        bus.send(TESTER, CTS.encode());
        for ecu in [ECU, ECU_2] {
            for frame in &rest {
                bus.send(ecu, frame.clone());
            }
        }
        bus.after(Duration::from_secs(1), TESTER, CTS.encode());
        let detection = detect(&bus.frames, WINDOW);
        assert_eq!(evidence(&detection, ECU).exchanges, 3);
        assert_eq!(evidence(&detection, ECU_2).exchanges, 3);
        assert_eq!(evidence(&detection, TESTER).counts.sequence_breaks, 1);
    }

    #[test]
    fn a_stray_twice_does_not_hide_the_id_answering_all_but_one_message() {
        const STRAY: u32 = 0x333;
        let (first, rest) = ecu_reply();
        let mut bus = Bus::new();
        for round in 0..20 {
            bus.send(ECU, first.clone());
            bus.send(if round == 5 { STRAY } else { TESTER }, CTS.encode());
            if round == 6 {
                bus.send(STRAY, CTS.encode());
            }
            for frame in &rest {
                bus.send(ECU, frame.clone());
            }
        }
        let detection = detect(&bus.frames, WINDOW);
        let pairs: Vec<(u32, u32, u32)> = detection
            .pairs
            .iter()
            .map(|pair| (pair.a_id, pair.b_id, pair.from_b))
            .collect();
        assert_eq!(pairs, [(TESTER, ECU, 19)]);
        assert_eq!(evidence(&detection, ECU).ambiguous, 1);
    }

    #[test]
    fn a_million_frames_over_200_ids_stay_one_entry_per_id() {
        let mut frames = Vec::with_capacity(1_000_000);
        let mut seed = 0x1234_5678_u32;
        for k in 0..1_000_000_u32 {
            let id = 0x100 + k % 200;
            seed = seed.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            let [a, b, c, d] = seed.to_be_bytes();
            let data = match id % 4 {
                0 => vec![(k / 200) as u8, 0x02, 0x11, 0x22, 0, 0, 0, 0],
                1 => vec![0x30, a, b, c, d, 0, 0, 0],
                2 => vec![0x10 | (a & 0x0F), b, c, d, a, b, c, d],
                _ => vec![a, b, c, d, d, c, b, a],
            };
            frames.push(TimedFrame {
                id,
                extended: false,
                data,
                at_us: u64::from(k) * 50,
            });
        }
        let detection = detect(&frames, WINDOW);
        assert_eq!(detection.ids.len(), 200);
        assert!(detection.ids.iter().all(|ids| ids.address_byte.is_none()));
    }
}
