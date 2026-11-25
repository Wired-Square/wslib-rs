//! Finds the UDS conversations in a window of CAN frames and orients each by
//! which side sends the requests.

use std::cmp::Reverse;
use std::collections::{HashMap, HashSet};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use wslib_isotp::{
    Addressing, DEFAULT_FLOW_CONTROL_WINDOW, FdLength, FrameFormat, Framing, Pair, Reassembler,
    StMin, Step, TimedFrame, detect,
};

use crate::answer::suppresses_positive_response;
use crate::{Answer, Nrc, Request, Sender, Timing, answers, sid};

/// The most partners an id is weighed against in one role; an id answered by,
/// or answering, more than this is unsettled in that role.
pub const MAX_PARTNERS: usize = 4;

/// The longest message read; a longer one answers and opens nothing.
pub const MAX_MESSAGE_BYTES: usize = 0x1_0000;

const PENDING: Answer = Answer::Negative {
    code: Nrc::RESPONSE_PENDING,
};

/// A CAN id, and the address byte leading its frames when it reads as
/// extended or mixed addressing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(rename = "UdsEndpoint"))]
#[serde(rename_all = "camelCase")]
pub struct Endpoint {
    pub id: u32,
    pub address_byte: Option<u8>,
}

/// A tester and the ECU it talks to, with the evidence for both.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(rename = "UdsConversation"))]
#[serde(rename_all = "camelCase")]
pub struct Conversation {
    /// 29-bit ids, or 11-bit.
    pub extended: bool,
    pub tester: Endpoint,
    pub ecu: Endpoint,
    /// The tester's requests the ECU gave a final answer.
    pub exchanges: u32,
    /// Of those, the ones answered with a negative response.
    pub negative: u32,
    /// responsePending answers before those final answers.
    pub pending: u32,
    /// Multi-frame requests the ECU answered with flow control, as
    /// `wslib_isotp::detect` paired them.
    pub flow_controlled_requests: u32,
    /// Multi-frame responses the tester answered with flow control.
    pub flow_controlled_responses: u32,
}

/// An id that exchanged UDS with others, whose partner in one role could not
/// be settled.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(rename = "UdsUnsettled"))]
#[serde(rename_all = "camelCase")]
pub struct Unsettled {
    pub extended: bool,
    pub endpoint: Endpoint,
    /// Its role: `tester` when its ECU is unsettled, `ecu` when its tester is.
    pub side: Sender,
    /// The ids it exchanged UDS with in that role, most exchanges first.
    pub candidates: Vec<Endpoint>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(rename = "UdsOrientation"))]
#[serde(rename_all = "camelCase")]
pub struct Orientation {
    /// In the order their first exchange completed.
    pub conversations: Vec<Conversation>,
    /// In the order their ids were first seen.
    pub unsettled: Vec<Unsettled>,
}

/// The UDS conversations in `frames`, given in bus order, each oriented by
/// which side sends requests.
///
/// Each id's messages are reassembled, per address byte where
/// `wslib_isotp::detect` reads the id as addressed. Only a well-formed request
/// of a service ISO 14229-1 defines opens a request; a tester present or a
/// request that suppresses its positive response is held beside the open one
/// rather than replacing it. A message answers a request on another id, as
/// [`answers`] judges, when it starts after the request's last frame and within
/// P2 plus the margin of it, or of a responsePending from the same id within
/// P2* plus the margin.
///
/// An id is an ECU only if more of its messages answered a request than
/// answered nothing, and a tester only if more of its requests were answered
/// than not. An id's partner in a role is the eligible one with the most
/// exchanges, settled when every rival has at most one or an eighth as many. A
/// conversation is reported when two ids settle on each other in one
/// orientation only and `detect` pairs neither with a third id; every other
/// eligible id with an eligible candidate is [`Unsettled`] in that role.
///
/// Beyond `detect`'s record of each multi-frame message, memory grows with the
/// ids in the window: each holds a message of at most [`MAX_MESSAGE_BYTES`] in
/// reassembly, two open requests, and [`MAX_PARTNERS`] partners a role.
pub fn orient(frames: &[TimedFrame], timing: &Timing) -> Orientation {
    let detection = detect(frames, DEFAULT_FLOW_CONTROL_WINDOW);
    let addressed: HashSet<(u32, bool)> = detection
        .ids
        .iter()
        .filter(|evidence| evidence.address_byte.is_some())
        .map(|evidence| (evidence.id, evidence.extended))
        .collect();
    let mut reading = Reading {
        reply_within_us: micros(timing.p2.saturating_add(timing.margin)),
        pending_within_us: micros(timing.p2_star.saturating_add(timing.margin)),
        index: HashMap::new(),
        tracks: Vec::new(),
    };
    for (order, frame) in frames.iter().enumerate() {
        let address_byte = match frame.data.first() {
            Some(&byte) if addressed.contains(&(frame.id, frame.extended)) => Some(byte),
            None if addressed.contains(&(frame.id, frame.extended)) => continue,
            _ => None,
        };
        reading.frame(order, (frame.id, frame.extended, address_byte), frame);
    }
    reading.settle(&detection.pairs)
}

fn micros(span: Duration) -> u64 {
    u64::try_from(span.as_micros()).unwrap_or(u64::MAX)
}

type Key = (u32, bool, Option<u8>);

fn endpoint((id, _, address_byte): Key) -> Endpoint {
    Endpoint { id, address_byte }
}

fn reassembler(address_byte: Option<u8>) -> Reassembler {
    let addressing = address_byte.map_or(Addressing::Normal, |byte| Addressing::Extended {
        tx: byte,
        rx: byte,
    });
    let mut framing = Framing::new(
        addressing,
        FrameFormat::Fd {
            length: FdLength::MAX,
        },
    );
    framing.max_message = MAX_MESSAGE_BYTES as u32;
    Reassembler::with_framing(0, StMin(0), framing)
}

fn opens_request(message: &[u8]) -> bool {
    message
        .first()
        .is_some_and(|&service| sid::name(service).is_some())
        && Request::decode(message).is_ok()
}

struct Open {
    data: Vec<u8>,
    end_us: u64,
    owed: bool,
    answered: bool,
    replies: Vec<Reply>,
}

struct Reply {
    from: usize,
    pending: u32,
    last_pending_us: Option<u64>,
    done: bool,
}

struct Tally {
    partner: usize,
    first: usize,
    exchanges: u32,
    negative: u32,
    pending: u32,
}

#[derive(Default)]
struct Partners {
    tallies: Vec<Tally>,
    crowded: bool,
}

impl Partners {
    fn credit(&mut self, partner: usize, order: usize) -> Option<&mut Tally> {
        let at = match self.tallies.iter().position(|t| t.partner == partner) {
            Some(at) => at,
            None if self.tallies.len() < MAX_PARTNERS => {
                self.tallies.push(Tally {
                    partner,
                    first: order,
                    exchanges: 0,
                    negative: 0,
                    pending: 0,
                });
                self.tallies.len() - 1
            }
            None => {
                self.crowded = true;
                return None;
            }
        };
        Some(&mut self.tallies[at])
    }

    /// The eligible partner with the most exchanges, if every eligible rival
    /// has at most one or an eighth as many.
    fn settled(&self, eligible: impl Fn(&Tally) -> bool) -> Option<&Tally> {
        if self.crowded {
            return None;
        }
        let mut ranked = self.ranked(eligible);
        let leader = ranked.next()?;
        let rival = ranked.next().map_or(0, |rival| rival.exchanges);
        let outweighed = rival <= 1 || rival.saturating_mul(8) <= leader.exchanges;
        (rival < leader.exchanges && outweighed).then_some(leader)
    }

    fn ranked(&self, keep: impl Fn(&Tally) -> bool) -> impl Iterator<Item = &Tally> {
        let mut tallies: Vec<&Tally> = self.tallies.iter().filter(|t| keep(t)).collect();
        tallies.sort_by_key(|tally| (Reverse(tally.exchanges), tally.first));
        tallies.into_iter()
    }
}

struct Track {
    key: Key,
    reassembler: Reassembler,
    started_us: Option<u64>,
    /// The latest request, and a tester present or suppressed request since.
    open: [Option<Open>; 2],
    as_tester: Partners,
    as_ecu: Partners,
    requests_answered: u32,
    unanswered: u32,
    answers: u32,
    answering_nothing: u32,
}

impl Track {
    fn new(key: Key) -> Self {
        Self {
            key,
            reassembler: reassembler(key.2),
            started_us: None,
            open: [None, None],
            as_tester: Partners::default(),
            as_ecu: Partners::default(),
            requests_answered: 0,
            unanswered: 0,
            answers: 0,
            answering_nothing: 0,
        }
    }

    fn compatible(&self, other: &Self) -> bool {
        self.key.1 == other.key.1 && self.key.2.is_some() == other.key.2.is_some()
    }

    fn open(&mut self, data: Vec<u8>, end_us: u64) {
        let owed = !suppresses_positive_response(&data);
        let aside = !owed || data.first() == Some(&sid::TESTER_PRESENT);
        let slot = usize::from(aside);
        for closing in slot..self.open.len() {
            self.close(closing);
        }
        self.open[slot] = Some(Open {
            data,
            end_us,
            owed,
            answered: false,
            replies: Vec::new(),
        });
    }

    fn close(&mut self, slot: usize) {
        if let Some(open) = self.open[slot].take()
            && open.owed
            && !open.answered
        {
            self.unanswered = self.unanswered.saturating_add(1);
        }
    }

    fn eligible_tester(&self) -> bool {
        self.requests_answered > self.unanswered
    }

    fn eligible_ecu(&self) -> bool {
        self.answers > self.answering_nothing
    }
}

struct Reading {
    reply_within_us: u64,
    pending_within_us: u64,
    index: HashMap<Key, usize>,
    tracks: Vec<Track>,
}

impl Reading {
    fn frame(&mut self, order: usize, key: Key, frame: &TimedFrame) {
        let tracks = &mut self.tracks;
        let at = *self.index.entry(key).or_insert_with(|| {
            tracks.push(Track::new(key));
            tracks.len() - 1
        });
        let track = &mut self.tracks[at];
        let outcome = track.reassembler.on_frame(&frame.data);
        if outcome.aborted.is_some() {
            track.started_us = None;
        }
        match outcome.step {
            Step::SendFlowControl(_) => {
                track.started_us = track.reassembler.is_receiving().then_some(frame.at_us);
            }
            Step::Message(message) => {
                let start_us = track.started_us.take().unwrap_or(frame.at_us);
                self.message(order, at, message, start_us, frame.at_us);
            }
            Step::Accepted | Step::Nothing => {}
        }
    }

    /// Each other id with an open request `message` from `from` answers in
    /// time, the latest request before one held beside it.
    fn answered(&self, from: usize, message: &[u8], start_us: u64) -> Vec<(usize, usize, Answer)> {
        let sender = &self.tracks[from];
        self.tracks
            .iter()
            .enumerate()
            .filter(|(at, track)| *at != from && track.compatible(sender))
            .filter_map(|(at, track)| {
                track.open.iter().enumerate().find_map(|(slot, open)| {
                    let open = open.as_ref()?;
                    let reply = open.replies.iter().find(|reply| reply.from == from);
                    let (since_us, within_us) = match reply {
                        Some(reply) if reply.done => return None,
                        Some(Reply {
                            last_pending_us: Some(pending_us),
                            ..
                        }) => (*pending_us, self.pending_within_us),
                        _ => (open.end_us, self.reply_within_us),
                    };
                    if start_us.checked_sub(since_us)? > within_us {
                        return None;
                    }
                    Some((at, slot, answers(&open.data, message)?))
                })
            })
            .collect()
    }

    fn message(&mut self, order: usize, from: usize, message: Vec<u8>, start_us: u64, end_us: u64) {
        let mut taken = None;
        for (tester, slot, answer) in self.answered(from, &message, start_us) {
            if self.reply(order, (tester, slot), from, answer, start_us) {
                taken = Some(answer);
            }
        }
        let sender = &mut self.tracks[from];
        match taken {
            None => sender.answering_nothing = sender.answering_nothing.saturating_add(1),
            Some(answer) if answer != PENDING => sender.answers = sender.answers.saturating_add(1),
            Some(_) => {}
        }
        if opens_request(&message) {
            sender.open(message, end_us);
        }
    }

    /// Records `ecu`'s answer to a tester's open request, unless the request
    /// already has [`MAX_PARTNERS`] others answering it.
    fn reply(
        &mut self,
        order: usize,
        (tester, slot): (usize, usize),
        ecu: usize,
        answer: Answer,
        at_us: u64,
    ) -> bool {
        let track = &mut self.tracks[tester];
        let Some(open) = track.open[slot].as_mut() else {
            return false;
        };
        let at = match open.replies.iter().position(|reply| reply.from == ecu) {
            Some(at) => at,
            None if open.replies.len() < MAX_PARTNERS => {
                open.replies.push(Reply {
                    from: ecu,
                    pending: 0,
                    last_pending_us: None,
                    done: false,
                });
                open.replies.len() - 1
            }
            None => return false,
        };
        let reply = &mut open.replies[at];
        if answer == PENDING {
            reply.pending = reply.pending.saturating_add(1);
            reply.last_pending_us = Some(at_us);
            return true;
        }
        reply.done = true;
        let pending_before = reply.pending;
        if !std::mem::replace(&mut open.answered, true) {
            track.requests_answered = track.requests_answered.saturating_add(1);
        }
        if let Some(tally) = track.as_tester.credit(ecu, order) {
            tally.exchanges = tally.exchanges.saturating_add(1);
            tally.pending = tally.pending.saturating_add(pending_before);
            if matches!(answer, Answer::Negative { .. }) {
                tally.negative = tally.negative.saturating_add(1);
            }
        }
        if let Some(tally) = self.tracks[ecu].as_ecu.credit(tester, order) {
            tally.exchanges = tally.exchanges.saturating_add(1);
        }
        true
    }

    fn settle(mut self, pairs: &[Pair]) -> Orientation {
        for track in &mut self.tracks {
            track.close(0);
            track.close(1);
        }
        let tracks = &self.tracks;
        let is_ecu = |tally: &Tally| tracks[tally.partner].eligible_ecu();
        let is_tester = |tally: &Tally| tracks[tally.partner].eligible_tester();
        let ecu_of: Vec<Option<&Tally>> = tracks
            .iter()
            .map(|tester| (tester.as_tester.settled(is_ecu)).filter(|_| tester.eligible_tester()))
            .collect();
        let tester_of: Vec<Option<usize>> = tracks
            .iter()
            .map(|ecu| {
                let tester = ecu.as_ecu.settled(is_tester).filter(|_| ecu.eligible_ecu());
                tester.map(|tally| tally.partner)
            })
            .collect();

        let detected = detected_partners(pairs);
        let detected_only_with = |key: Key, partner: Key| {
            detected
                .get(&key)
                .is_none_or(|paired| paired.iter().all(|(other, ..)| *other == partner))
        };
        let mut paired = vec![[false; 2]; tracks.len()];
        let mut conversations = Vec::new();
        for (tester, tally) in ecu_of.iter().enumerate() {
            let Some(tally) = tally else {
                continue;
            };
            let ecu = tally.partner;
            let (tester_key, ecu_key) = (tracks[tester].key, tracks[ecu].key);
            if tester_of[ecu] != Some(tester)
                || ecu_of[ecu].is_some_and(|back| back.partner == tester)
                || !detected_only_with(tester_key, ecu_key)
                || !detected_only_with(ecu_key, tester_key)
            {
                continue;
            }
            paired[tester][0] = true;
            paired[ecu][1] = true;
            let (flow_controlled_requests, flow_controlled_responses) = detected
                .get(&tester_key)
                .and_then(|paired| paired.first())
                .map_or((0, 0), |&(_, requests, responses)| (requests, responses));
            conversations.push((
                tally.first,
                Conversation {
                    extended: tester_key.1,
                    tester: endpoint(tester_key),
                    ecu: endpoint(ecu_key),
                    exchanges: tally.exchanges,
                    negative: tally.negative,
                    pending: tally.pending,
                    flow_controlled_requests,
                    flow_controlled_responses,
                },
            ));
        }
        conversations.sort_by_key(|(first, _)| *first);

        let mut unsettled = Vec::new();
        for (track, [as_tester, as_ecu]) in tracks.iter().zip(paired) {
            let unsettled_as = |side, partners: &Partners, eligible: &dyn Fn(&Tally) -> bool| {
                let candidates: Vec<Endpoint> = partners
                    .ranked(eligible)
                    .map(|tally| endpoint(tracks[tally.partner].key))
                    .collect();
                (!candidates.is_empty()).then(|| Unsettled {
                    extended: track.key.1,
                    endpoint: endpoint(track.key),
                    side,
                    candidates,
                })
            };
            if !as_tester && track.eligible_tester() {
                unsettled.extend(unsettled_as(Sender::Tester, &track.as_tester, &is_ecu));
            }
            if !as_ecu && track.eligible_ecu() {
                unsettled.extend(unsettled_as(Sender::Ecu, &track.as_ecu, &is_tester));
            }
        }
        Orientation {
            conversations: conversations.into_iter().map(|(_, c)| c).collect(),
            unsettled,
        }
    }
}

/// Each id `detect` paired, with its partner and the exchanges each way.
fn detected_partners(pairs: &[Pair]) -> HashMap<Key, Vec<(Key, u32, u32)>> {
    let mut detected: HashMap<Key, Vec<(Key, u32, u32)>> = HashMap::new();
    for pair in pairs {
        let (a_byte, b_byte) = match pair.addressing {
            Addressing::Normal => (None, None),
            Addressing::Extended { tx, rx } | Addressing::Mixed { tx, rx } => (Some(tx), Some(rx)),
        };
        let a = (pair.a_id, pair.extended, a_byte);
        let b = (pair.b_id, pair.extended, b_byte);
        detected
            .entry(a)
            .or_default()
            .push((b, pair.from_a, pair.from_b));
        detected
            .entry(b)
            .or_default()
            .push((a, pair.from_b, pair.from_a));
    }
    detected
}
