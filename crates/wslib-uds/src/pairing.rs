//! Pairs a capture's requests with their responses, for one tester and one
//! ECU; the caller separates conversations by address.

use serde::{Deserialize, Serialize};

use crate::answer::suppresses_positive_response;
use crate::{Answer, Nrc, Response, answers, sid};

/// Which side sent an observed message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(rename = "UdsSender"))]
#[serde(rename_all = "camelCase")]
pub enum Sender {
    Tester,
    Ecu,
}

/// A request and how it ended. Times are the capture's, in microseconds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(rename = "UdsTransaction"))]
#[serde(rename_all = "camelCase")]
pub struct Transaction {
    pub request: Vec<u8>,
    #[cfg_attr(feature = "ts", ts(type = "number"))]
    pub requested_at_us: u64,
    /// responsePending answers before the end.
    pub pending_responses: u32,
    pub outcome: Outcome,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(rename = "UdsOutcome"))]
#[serde(tag = "kind", rename_all = "camelCase")]
#[serde(rename_all_fields = "camelCase")]
pub enum Outcome {
    /// The final response, positive or negative.
    Answered {
        response: Vec<u8>,
        #[cfg_attr(feature = "ts", ts(type = "number"))]
        latency_us: u64,
    },
    /// A positive answer that fails strict decoding.
    Malformed {
        response: Vec<u8>,
        #[cfg_attr(feature = "ts", ts(type = "number"))]
        latency_us: u64,
    },
    /// The request asked for no positive response, and no negative one came.
    Suppressed,
    /// Another request came first.
    Superseded,
    TimedOut,
    /// The capture ended first.
    Unfinished,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(rename = "UdsObserved"))]
#[serde(tag = "kind", rename_all = "camelCase")]
#[serde(rename_all_fields = "camelCase")]
pub enum Observed {
    Transaction(Transaction),
    /// An ECU message that answers no open request.
    Unsolicited {
        response: Vec<u8>,
        #[cfg_attr(feature = "ts", ts(type = "number"))]
        at_us: u64,
    },
}

/// P2* at its usual 5 s, so a request quiet that long after its last answer is over.
pub const DEFAULT_TIMEOUT_US: u64 = 5_000_000;

/// How many requests a [`Tracker`] holds open; a new one beyond it supersedes
/// the oldest, which can only be a suppressed request still within its timeout.
pub const MAX_OPEN_REQUESTS: usize = 32;

#[derive(Debug, Clone)]
pub struct Tracker {
    timeout_us: u64,
    /// Oldest first.
    open: Vec<Open>,
}

#[derive(Debug, Clone)]
struct Open {
    request: Vec<u8>,
    at_us: u64,
    last_us: u64,
    pending: u32,
    suppressed: bool,
}

impl Open {
    fn new(request: &[u8], at_us: u64) -> Self {
        Self {
            request: request.to_vec(),
            at_us,
            last_us: at_us,
            pending: 0,
            suppressed: suppresses_positive_response(request),
        }
    }

    fn close(self, outcome: Outcome) -> Observed {
        Observed::Transaction(Transaction {
            request: self.request,
            requested_at_us: self.at_us,
            pending_responses: self.pending,
            outcome,
        })
    }

    fn owed_a_response(&self) -> bool {
        !self.suppressed || self.pending > 0
    }

    fn close_unanswered(self, outcome: Outcome) -> Observed {
        let outcome = if self.owed_a_response() {
            outcome
        } else {
            Outcome::Suppressed
        };
        self.close(outcome)
    }
}

impl Default for Tracker {
    fn default() -> Self {
        Self::new()
    }
}

impl Tracker {
    pub fn new() -> Self {
        Self {
            timeout_us: DEFAULT_TIMEOUT_US,
            open: Vec::new(),
        }
    }

    pub fn with_timeout_us(mut self, timeout_us: u64) -> Self {
        self.timeout_us = timeout_us;
        self
    }

    /// Feeds one message, first ending the open requests that `at_us` shows
    /// have timed out; an empty message is ignored. A new request supersedes
    /// any request owed a response; one that suppressed its positive response
    /// stays open to its timeout, so a late refusal still pairs with it, until
    /// [`MAX_OPEN_REQUESTS`] newer ones supersede it. A response goes to the
    /// newest open request it answers that is owed one, or failing that to
    /// the newest suppressed one. A suppressed tester present while a request
    /// is owed a response is a keep-alive: it is reported at once as
    /// suppressed and leaves the open requests alone.
    pub fn observe(&mut self, sender: Sender, message: &[u8], at_us: u64) -> Vec<Observed> {
        if message.is_empty() {
            return Vec::new();
        }
        let mut seen = self.expire(at_us);
        let keep_alive = Open::new(message, at_us);
        match sender {
            Sender::Tester
                if message == [sid::TESTER_PRESENT, 0x80]
                    && self.open.iter().any(Open::owed_a_response) =>
            {
                seen.push(keep_alive.close(Outcome::Suppressed))
            }
            Sender::Tester => seen.extend(self.request(keep_alive)),
            Sender::Ecu => seen.extend(self.response(message, at_us)),
        }
        seen
    }

    /// Ends the open requests quiet for the timeout, for a caller with no
    /// further traffic to observe.
    pub fn expire(&mut self, now_us: u64) -> Vec<Observed> {
        let timeout_us = self.timeout_us;
        self.open
            .extract_if(.., |o| now_us.saturating_sub(o.last_us) >= timeout_us)
            .map(|o| o.close_unanswered(Outcome::TimedOut))
            .collect()
    }

    /// Ends the open requests at the end of the capture.
    pub fn finish(&mut self) -> Vec<Observed> {
        self.open
            .drain(..)
            .map(|o| o.close_unanswered(Outcome::Unfinished))
            .collect()
    }

    fn request(&mut self, open: Open) -> Vec<Observed> {
        let mut superseded: Vec<Observed> = self
            .open
            .extract_if(.., |o| o.owed_a_response())
            .map(|o| o.close(Outcome::Superseded))
            .collect();
        if self.open.len() == MAX_OPEN_REQUESTS {
            superseded.push(self.open.remove(0).close(Outcome::Superseded));
        }
        self.open.push(open);
        superseded
    }

    /// The newest open request this answers that is owed a response, or
    /// failing that the newest suppressed one it answers.
    fn answered(&self, message: &[u8]) -> Option<(usize, Answer)> {
        let answering = || {
            self.open
                .iter()
                .enumerate()
                .rev()
                .filter_map(|(i, o)| Some((i, answers(&o.request, message)?, o)))
        };
        answering()
            .find(|(_, _, o)| o.owed_a_response())
            .or_else(|| answering().next())
            .map(|(i, a, _)| (i, a))
    }

    fn response(&mut self, message: &[u8], at_us: u64) -> Option<Observed> {
        let Some((i, answer)) = self.answered(message) else {
            return Some(Observed::Unsolicited {
                response: message.to_vec(),
                at_us,
            });
        };
        if answer
            == (Answer::Negative {
                code: Nrc::RESPONSE_PENDING,
            })
        {
            let open = &mut self.open[i];
            open.pending = open.pending.saturating_add(1);
            open.last_us = at_us;
            return None;
        }
        let open = self.open.remove(i);
        let response = message.to_vec();
        let latency_us = at_us.saturating_sub(open.at_us);
        Some(open.close(match (answer, Response::decode(message)) {
            (Answer::Positive, Err(_)) => Outcome::Malformed {
                response,
                latency_us,
            },
            _ => Outcome::Answered {
                response,
                latency_us,
            },
        }))
    }
}
