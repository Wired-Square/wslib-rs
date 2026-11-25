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
use crate::{Answer, Nrc, Sender, Timing, answers};

/// The most partners an id is weighed against in one role; an id answered by,
/// or answering, more than this is unsettled in that role.
pub const MAX_PARTNERS: usize = 4;

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
/// Each id's frames are reassembled with normal addressing, or per leading
/// byte where `wslib_isotp::detect` (over [`DEFAULT_FLOW_CONTROL_WINDOW`])
/// reads the id as addressed, so a conversation of single frames alone is
/// found. A message answers the latest request on another id, as [`answers`]
/// judges, when it starts after the request's last frame and within P2 plus
/// the margin of it, or of a responsePending from its own id within P2* plus
/// the margin; a request that suppresses its positive response opens none.
/// Order of arrival decides nothing more.
///
/// An id is an ECU only if no more of its messages answered nothing than
/// answered a request, and a tester only if no more of its requests went
/// unanswered than were answered, so a periodic look-alike is neither. Each
/// tester's ECU is settled across the window as `detect` settles an answering
/// id: the id answering strictly the most of its requests, in more than half
/// of them or with no rival in more than one; each ECU's tester likewise over
/// its answers. A conversation is reported only when both agree and `detect`
/// pairs neither with a third id; otherwise each id that could not be settled
/// is [`Unsettled`].
///
/// Memory grows with the ids in the window, not its length: each keeps one
/// message in reassembly, its latest request, and [`MAX_PARTNERS`] partners a
/// role.
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
    let framing = Framing::new(addressing, FrameFormat::Fd(FdLength::MAX));
    Reassembler::with_framing(0, StMin(0), framing)
}

struct Request {
    data: Vec<u8>,
    end_us: u64,
    replies: Vec<Reply>,
    answered: bool,
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

    /// Of the partners `eligible` keeps, the one credited more than any
    /// rival, and in more than half of `total` or with no rival credited more
    /// than once.
    fn settled(&self, total: u32, eligible: impl Fn(&Tally) -> bool) -> Option<&Tally> {
        if self.crowded {
            return None;
        }
        let mut ranked = self.ranked(eligible);
        let top = ranked.next()?;
        let rival_seen = ranked.next().map_or(0, |rival| rival.exchanges);
        let majority = u64::from(top.exchanges) * 2 > u64::from(total);
        (top.exchanges > rival_seen && (majority || rival_seen <= 1)).then_some(top)
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
    open: Option<Request>,
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
            open: None,
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

    fn close_request(&mut self, next: Option<Request>) {
        if let Some(old) = std::mem::replace(&mut self.open, next)
            && !old.answered
        {
            self.unanswered = self.unanswered.saturating_add(1);
        }
    }

    fn eligible_tester(&self) -> bool {
        self.unanswered <= self.requests_answered
    }

    fn eligible_ecu(&self) -> bool {
        self.answering_nothing <= self.answers
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

    /// The other ids whose open request `message` from `from` answers in time.
    fn answered(&self, from: usize, message: &[u8], start_us: u64) -> Vec<(usize, Answer)> {
        let sender = &self.tracks[from];
        self.tracks
            .iter()
            .enumerate()
            .filter(|(at, track)| *at != from && track.compatible(sender))
            .filter_map(|(at, track)| {
                let request = track.open.as_ref()?;
                let reply = request.replies.iter().find(|reply| reply.from == from);
                let (since_us, within_us) = match reply {
                    Some(reply) if reply.done => return None,
                    Some(Reply {
                        last_pending_us: Some(pending_us),
                        ..
                    }) => (*pending_us, self.pending_within_us),
                    _ => (request.end_us, self.reply_within_us),
                };
                if start_us.checked_sub(since_us)? > within_us {
                    return None;
                }
                Some((at, answers(&request.data, message)?))
            })
            .collect()
    }

    fn message(&mut self, order: usize, from: usize, message: Vec<u8>, start_us: u64, end_us: u64) {
        let answered = self.answered(from, &message, start_us);
        let sender = &mut self.tracks[from];
        match answered.first() {
            None => sender.answering_nothing = sender.answering_nothing.saturating_add(1),
            Some((_, answer)) if *answer != PENDING => {
                sender.answers = sender.answers.saturating_add(1);
            }
            Some(_) => {}
        }
        for (tester, answer) in answered {
            self.reply(order, tester, from, answer, start_us);
        }
        let sender = &mut self.tracks[from];
        if !suppresses_positive_response(&message) {
            sender.close_request(Some(Request {
                data: message,
                end_us,
                replies: Vec::new(),
                answered: false,
            }));
        }
    }

    fn reply(&mut self, order: usize, tester: usize, ecu: usize, answer: Answer, at_us: u64) {
        let track = &mut self.tracks[tester];
        let Some(request) = track.open.as_mut() else {
            return;
        };
        let at = match request.replies.iter().position(|reply| reply.from == ecu) {
            Some(at) => at,
            None if request.replies.len() < MAX_PARTNERS => {
                request.replies.push(Reply {
                    from: ecu,
                    pending: 0,
                    last_pending_us: None,
                    done: false,
                });
                request.replies.len() - 1
            }
            None => return,
        };
        let reply = &mut request.replies[at];
        if answer == PENDING {
            reply.pending = reply.pending.saturating_add(1);
            reply.last_pending_us = Some(at_us);
            return;
        }
        reply.done = true;
        let pending_before = reply.pending;
        if !std::mem::replace(&mut request.answered, true) {
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
    }

    fn settle(mut self, pairs: &[Pair]) -> Orientation {
        for track in &mut self.tracks {
            track.close_request(None);
        }
        let tracks = &self.tracks;
        let is_ecu = |tally: &Tally| tracks[tally.partner].eligible_ecu();
        let is_tester = |tally: &Tally| tracks[tally.partner].eligible_tester();
        let ecu_of: Vec<Option<&Tally>> = tracks
            .iter()
            .map(|tester| {
                let ecu = tester.as_tester.settled(tester.requests_answered, is_ecu)?;
                tester.eligible_tester().then_some(ecu)
            })
            .collect();
        let tester_of: Vec<Option<usize>> = tracks
            .iter()
            .map(|ecu| {
                let tester = ecu.as_ecu.settled(ecu.answers, is_tester)?;
                ecu.eligible_ecu().then_some(tester.partner)
            })
            .collect();
        let mut unsettled_as: Vec<[bool; 2]> = tracks
            .iter()
            .enumerate()
            .map(|(at, track)| {
                [
                    ecu_of[at].is_none()
                        && track.eligible_tester()
                        && track.as_tester.tallies.iter().any(is_ecu),
                    tester_of[at].is_none()
                        && track.eligible_ecu()
                        && track.as_ecu.tallies.iter().any(is_tester),
                ]
            })
            .collect();

        let detected = detected_partners(pairs);
        let detected_only_with = |key: Key, partner: Key| {
            detected
                .get(&key)
                .is_none_or(|paired| paired.iter().all(|(other, ..)| *other == partner))
        };
        let mut conversations = Vec::new();
        for (tester, tally) in ecu_of.iter().enumerate() {
            let Some(tally) = tally else {
                continue;
            };
            let ecu = tally.partner;
            if tester_of[ecu] != Some(tester) {
                continue;
            }
            let (tester_key, ecu_key) = (tracks[tester].key, tracks[ecu].key);
            if !detected_only_with(tester_key, ecu_key) || !detected_only_with(ecu_key, tester_key)
            {
                unsettled_as[tester][0] = true;
                unsettled_as[ecu][1] = true;
                continue;
            }
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
        for (track, [as_tester, as_ecu]) in tracks.iter().zip(unsettled_as) {
            let entry = |side, partners: &Partners, keep: &dyn Fn(&Tally) -> bool| Unsettled {
                extended: track.key.1,
                endpoint: endpoint(track.key),
                side,
                candidates: partners
                    .ranked(keep)
                    .map(|tally| endpoint(tracks[tally.partner].key))
                    .collect(),
            };
            if as_tester {
                unsettled.push(entry(Sender::Tester, &track.as_tester, &is_ecu));
            }
            if as_ecu {
                unsettled.push(entry(Sender::Ecu, &track.as_ecu, &is_tester));
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
