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

/// A tester's track, the slot of its request, and how a message answers it.
type Found = (usize, usize, Answer);

/// Indices into a track's roles.
const TESTER: usize = 0;
const ECU: usize = 1;

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
    /// The tester's typed requests the ECU gave a final answer.
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
    /// In the order their ids were first seen, an id's tester role first.
    pub unsettled: Vec<Unsettled>,
}

/// The UDS conversations in `frames`, given in bus order, each oriented by
/// which side sends requests.
///
/// Messages are reassembled per id, and per address byte where
/// `wslib_isotp::detect` reads one; a single frame not padded with one value
/// is no message. A message answers another id's request, as [`answers`]
/// judges, starting after it and within P2 plus the margin, or P2* plus the
/// margin after a responsePending from the same id; a positive answer to a
/// suppressed request with no responsePending first answers nothing. Any other
/// message opens a request, a tester present or suppressed one beside the
/// latest. A request decoding as a typed [`Request`], not `Request::Other`,
/// counts: its final answer is an exchange, its silence unanswered. An answer
/// to any other request counts for nothing.
///
/// A [`Conversation`] is two ids leading each other's exchanges, every rival
/// on either side with at most an eighth as many, as are the ECU's messages
/// answering nothing and the tester's unanswered requests; `detect` pairs
/// neither with a third id, and neither has the other role elsewhere. Every
/// other id with an exchange is [`Unsettled`]. Two periodic ids at about one
/// rate whose frames are a typed request and its answer, uniformly padded,
/// look like a conversation.
///
/// Time is the frames times the ids with a request open. Memory per id and
/// address byte: an open first frame's reservation of up to 4095 bytes, two
/// requests of up to [`MAX_MESSAGE_BYTES`], [`MAX_PARTNERS`] partners a role;
/// and `detect`'s record of each multi-frame message.
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
        ..Reading::default()
    };
    for (order, frame) in frames.iter().enumerate() {
        let address_byte = frame
            .data
            .first()
            .filter(|_| addressed.contains(&(frame.id, frame.extended)))
            .copied();
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

/// Whether a single frame's bytes after its `len` bytes of message are all one
/// value. A PCI low nibble of zero is the escaped form, with a length byte.
fn uniformly_padded(frame: &[u8], addressed: bool, len: usize) -> bool {
    let pci_at = usize::from(addressed);
    let header = pci_at + if frame[pci_at] & 0x0F == 0 { 2 } else { 1 };
    frame
        .get(header + len..)
        .is_none_or(|padding| padding.windows(2).all(|pair| pair[0] == pair[1]))
}

struct Open {
    data: Vec<u8>,
    end_us: u64,
    owed: bool,
    counted: bool,
    replies: Vec<Reply>,
}

impl Open {
    fn deadline_us(&self, reply_within_us: u64, pending_within_us: u64) -> u64 {
        self.replies
            .iter()
            .filter_map(|reply| reply.last_pending_us)
            .map(|pending_us| pending_us.saturating_add(pending_within_us))
            .fold(self.end_us.saturating_add(reply_within_us), u64::max)
    }
}

#[derive(Default)]
struct Reply {
    from: usize,
    pending: u32,
    last_pending_us: Option<u64>,
    done: bool,
}

/// The counted requests one tester's ECU answered.
#[derive(Default)]
struct Exchanges {
    /// The tester's track and the ECU's, indexed by role.
    ids: [usize; 2],
    first: usize,
    count: u32,
    negative: u32,
    pending: u32,
}

impl Exchanges {
    fn roles(&self) -> impl Iterator<Item = (usize, usize)> {
        self.ids.into_iter().zip([TESTER, ECU])
    }
}

#[derive(Default)]
struct Track {
    key: Key,
    /// The latest request, and a tester present or suppressed request since.
    open: [Option<Open>; 2],
    listed: bool,
    /// Indices into the reading's exchanges, as tester and as ECU.
    roles: [Vec<usize>; 2],
    crowded: [bool; 2],
    unanswered: u32,
    unsolicited: u32,
}

impl Track {
    fn close(&mut self, slot: usize) {
        if let Some(open) = self.open[slot].take()
            && open.owed
            && open.counted
            && !open.replies.iter().any(|reply| reply.done)
        {
            self.unanswered = self.unanswered.saturating_add(1);
        }
    }
}

#[derive(Default)]
struct Reading {
    reply_within_us: u64,
    pending_within_us: u64,
    index: HashMap<Key, usize>,
    tracks: Vec<Track>,
    /// Each track's reassembler, and when its multi-frame message started.
    readers: Vec<(Reassembler, Option<u64>)>,
    /// The tracks holding a request that may still be answered.
    listed: Vec<usize>,
    exchanges: Vec<Exchanges>,
    known: HashMap<[usize; 2], usize>,
}

impl Reading {
    fn frame(&mut self, order: usize, key: Key, frame: &TimedFrame) {
        let (tracks, readers) = (&mut self.tracks, &mut self.readers);
        let at = *self.index.entry(key).or_insert_with(|| {
            tracks.push(Track {
                key,
                ..Track::default()
            });
            readers.push((reassembler(key.2), None));
            tracks.len() - 1
        });
        let (reassembler, started_us) = &mut self.readers[at];
        let outcome = reassembler.on_frame(&frame.data);
        if outcome.aborted.is_some() {
            *started_us = None;
        }
        match outcome.step {
            Step::SendFlowControl(_) => {
                *started_us = reassembler.is_receiving().then_some(frame.at_us);
            }
            Step::Message(message) => match started_us.take() {
                Some(start_us) => self.message(order, at, message, start_us, frame.at_us),
                None if uniformly_padded(&frame.data, key.2.is_some(), message.len()) => {
                    self.message(order, at, message, frame.at_us, frame.at_us);
                }
                None => self.unsolicited(at),
            },
            Step::Accepted | Step::Nothing => {}
        }
    }

    /// Each other track with a request `message` answers in time, and which:
    /// its latest request if `message` answers that one, else the one held
    /// beside it.
    fn answered(&mut self, from: usize, message: &[u8], start_us: u64) -> Vec<Found> {
        let (reply_within_us, pending_within_us) = (self.reply_within_us, self.pending_within_us);
        let tracks = &mut self.tracks;
        self.listed.retain(|&at| {
            let track = &mut tracks[at];
            track.listed = track
                .open
                .iter()
                .flatten()
                .any(|open| open.deadline_us(reply_within_us, pending_within_us) >= start_us);
            track.listed
        });
        let sender = &self.tracks[from];
        self.listed
            .iter()
            .map(|&at| (at, &self.tracks[at]))
            .filter(|(at, track)| {
                *at != from
                    && track.key.1 == sender.key.1
                    && track.key.2.is_some() == sender.key.2.is_some()
            })
            .filter_map(|(at, track)| {
                track.open.iter().enumerate().find_map(|(slot, open)| {
                    let open = open.as_ref()?;
                    let reply = open.replies.iter().find(|reply| reply.from == from);
                    let (since_us, within_us) = match reply {
                        Some(reply) if reply.done => return None,
                        Some(Reply {
                            last_pending_us: Some(pending_us),
                            ..
                        }) => (*pending_us, pending_within_us),
                        _ => (open.end_us, reply_within_us),
                    };
                    if start_us.checked_sub(since_us)? > within_us {
                        return None;
                    }
                    let answer = answers(&open.data, message)?;
                    let unasked = !open.owed && answer == Answer::Positive;
                    let pended = reply.is_some_and(|reply| reply.pending > 0);
                    (!unasked || pended).then_some((at, slot, answer))
                })
            })
            .collect()
    }

    fn unsolicited(&mut self, at: usize) {
        let track = &mut self.tracks[at];
        track.unsolicited = track.unsolicited.saturating_add(1);
    }

    /// A message answering nothing is unsolicited and opens a request.
    fn message(&mut self, order: usize, from: usize, message: Vec<u8>, start_us: u64, end_us: u64) {
        let mut answered_any = false;
        if message[0] >= sid::POSITIVE_OFFSET {
            for found in self.answered(from, &message, start_us) {
                answered_any |= self.reply(order, found, from, start_us);
            }
        }
        if !answered_any {
            self.unsolicited(from);
            self.open(from, message, end_us);
        }
    }

    fn open(&mut self, at: usize, data: Vec<u8>, end_us: u64) {
        let track = &mut self.tracks[at];
        let owed = !suppresses_positive_response(&data);
        let slot = usize::from(!owed || data[0] == sid::TESTER_PRESENT);
        for closing in slot..track.open.len() {
            track.close(closing);
        }
        let counted = !matches!(Request::decode(&data), Err(_) | Ok(Request::Other { .. }));
        track.open[slot] = Some(Open {
            counted,
            data,
            end_us,
            owed,
            replies: Vec::new(),
        });
        if !std::mem::replace(&mut track.listed, true) {
            self.listed.push(at);
        }
    }

    /// Records `ecu`'s answer to a tester's open request, unless the request
    /// already has [`MAX_PARTNERS`] others answering it.
    fn reply(&mut self, order: usize, found: Found, ecu: usize, at_us: u64) -> bool {
        let (tester, slot, answer) = found;
        let open = self.tracks[tester].open[slot]
            .as_mut()
            .expect("answered found the request open");
        let at = match open.replies.iter().position(|reply| reply.from == ecu) {
            Some(at) => at,
            None if open.replies.len() < MAX_PARTNERS => {
                open.replies.push(Reply {
                    from: ecu,
                    ..Reply::default()
                });
                open.replies.len() - 1
            }
            None => return false,
        };
        let reply = &mut open.replies[at];
        if answer == PENDING {
            reply.pending = reply.pending.saturating_add(1);
            reply.last_pending_us = Some(at_us);
        } else {
            reply.done = true;
            if open.counted {
                let negative = matches!(answer, Answer::Negative { .. });
                let pending = reply.pending;
                self.credit(order, [tester, ecu], negative, pending);
            }
        }
        true
    }

    /// Counts a final answer to a counted request. A pair is listed on each
    /// side with room for it; a side without room is crowded.
    fn credit(&mut self, order: usize, ids: [usize; 2], negative: bool, pending: u32) {
        let at = match self.known.get(&ids) {
            Some(&at) => at,
            None => {
                let at = self.exchanges.len();
                let mut listed = false;
                for (role, &id) in ids.iter().enumerate() {
                    let track = &mut self.tracks[id];
                    if track.roles[role].len() < MAX_PARTNERS {
                        track.roles[role].push(at);
                        listed = true;
                    } else {
                        track.crowded[role] = true;
                    }
                }
                if !listed {
                    return;
                }
                self.known.insert(ids, at);
                self.exchanges.push(Exchanges {
                    ids,
                    first: order,
                    ..Exchanges::default()
                });
                at
            }
        };
        let exchanges = &mut self.exchanges[at];
        exchanges.count = exchanges.count.saturating_add(1);
        exchanges.negative = exchanges.negative.saturating_add(u32::from(negative));
        exchanges.pending = exchanges.pending.saturating_add(pending);
    }

    /// A track's exchanges in a role, most first.
    fn ranked(&self, track: &Track, role: usize) -> Vec<usize> {
        let mut ranked = track.roles[role].clone();
        ranked.sort_by_key(|&at| (Reverse(self.exchanges[at].count), self.exchanges[at].first));
        ranked
    }

    /// The exchanges leading a track's role, if every rival has at most an
    /// eighth as many.
    fn leader(&self, at: usize, role: usize) -> Option<usize> {
        let track = &self.tracks[at];
        let ranked = self.ranked(track, role);
        let (&leader, rivals) = ranked.split_first()?;
        let count = self.exchanges[leader].count;
        let outweighs = rivals
            .iter()
            .all(|&rival| self.exchanges[rival].count.saturating_mul(8) <= count);
        (!track.crowded[role] && outweighs).then_some(leader)
    }

    fn settle(mut self, pairs: &[Pair]) -> Orientation {
        for track in &mut self.tracks {
            track.close(0);
            track.close(1);
        }
        let detected = detected_partners(pairs);
        let detected_only_with = |key: Key, partner: Key| {
            detected
                .get(&key)
                .is_none_or(|paired| paired.iter().all(|(other, ..)| *other == partner))
        };
        let mut confident: Vec<usize> = (0..self.tracks.len())
            .filter_map(|tester| self.leader(tester, TESTER))
            .filter(|&at| {
                let pair = &self.exchanges[at];
                let [tester, ecu] = pair.ids.map(|id| &self.tracks[id]);
                self.leader(pair.ids[ECU], ECU) == Some(at)
                    && ecu.unsolicited.saturating_mul(8) <= pair.count
                    && tester.unanswered.saturating_mul(8) <= pair.count
                    && detected_only_with(tester.key, ecu.key)
                    && detected_only_with(ecu.key, tester.key)
            })
            .collect();
        let taken: HashSet<(usize, usize)> = confident
            .iter()
            .flat_map(|&at| self.exchanges[at].roles())
            .collect();
        confident.retain(|&at| {
            let [tester, ecu] = self.exchanges[at].ids;
            !taken.contains(&(tester, ECU)) && !taken.contains(&(ecu, TESTER))
        });
        confident.sort_by_key(|&at| self.exchanges[at].first);
        let paired: HashSet<(usize, usize)> = confident
            .iter()
            .flat_map(|&at| self.exchanges[at].roles())
            .collect();

        let conversations = confident
            .iter()
            .map(|&at| {
                let pair = &self.exchanges[at];
                let [tester, ecu] = pair.ids.map(|id| self.tracks[id].key);
                let (flow_controlled_requests, flow_controlled_responses) = detected
                    .get(&tester)
                    .and_then(|paired| paired.first())
                    .map_or((0, 0), |&(_, requests, responses)| (requests, responses));
                Conversation {
                    extended: tester.1,
                    tester: endpoint(tester),
                    ecu: endpoint(ecu),
                    exchanges: pair.count,
                    negative: pair.negative,
                    pending: pair.pending,
                    flow_controlled_requests,
                    flow_controlled_responses,
                }
            })
            .collect();

        let mut unsettled = Vec::new();
        for (at, track) in self.tracks.iter().enumerate() {
            for (role, side) in [(TESTER, Sender::Tester), (ECU, Sender::Ecu)] {
                if track.roles[role].is_empty() || paired.contains(&(at, role)) {
                    continue;
                }
                unsettled.push(Unsettled {
                    extended: track.key.1,
                    endpoint: endpoint(track.key),
                    side,
                    candidates: self
                        .ranked(track, role)
                        .into_iter()
                        .map(|at| endpoint(self.tracks[self.exchanges[at].ids[1 - role]].key))
                        .collect(),
                });
            }
        }
        Orientation {
            conversations,
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
        for (key, partner) in [
            (a, (b, pair.from_a, pair.from_b)),
            (b, (a, pair.from_b, pair.from_a)),
        ] {
            detected.entry(key).or_default().push(partner);
        }
    }
    detected
}
