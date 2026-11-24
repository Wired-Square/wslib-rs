//! Pairs a capture's requests with their responses, for one tester and one
//! ECU; the caller separates conversations by address.

use serde::{Deserialize, Serialize};

use crate::answer::suppresses_positive_response;
use crate::{Answer, Nrc, Response, answers, sid};

/// Which side sent an observed message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(rename = "UdsSender"))]
#[serde(rename_all = "snake_case")]
pub enum Sender {
    Tester,
    Ecu,
}

/// A request and how it ended. Times are the capture's, in microseconds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(rename = "UdsTransaction"))]
pub struct Transaction {
    pub request: Vec<u8>,
    pub requested_at_us: u64,
    /// responsePending answers before the end.
    pub pending_responses: u32,
    pub outcome: Outcome,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(rename = "UdsOutcome"))]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Outcome {
    /// The final response, positive or negative.
    Answered {
        response: Vec<u8>,
        latency_us: u64,
    },
    /// A positive answer that fails strict decoding.
    Malformed {
        response: Vec<u8>,
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
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Observed {
    Transaction(Transaction),
    /// An ECU message that answers no open request.
    Unsolicited {
        response: Vec<u8>,
        at_us: u64,
    },
}

/// P2* at its usual 5 s, so a request quiet that long after its last answer is over.
pub const DEFAULT_TIMEOUT_US: u64 = 5_000_000;

#[derive(Debug, Clone)]
pub struct Tracker {
    timeout_us: u64,
    open: Option<Open>,
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
            open: None,
        }
    }

    pub fn with_timeout_us(mut self, timeout_us: u64) -> Self {
        self.timeout_us = timeout_us;
        self
    }

    /// Feeds one message, first ending an open request that `at_us` shows
    /// has timed out; an empty message is ignored. A suppressed tester
    /// present while a request is owed a response is a keep-alive: it is
    /// reported at once as suppressed and leaves the open request alone.
    pub fn observe(&mut self, sender: Sender, message: &[u8], at_us: u64) -> Vec<Observed> {
        if message.is_empty() {
            return Vec::new();
        }
        let mut seen: Vec<Observed> = self.expire(at_us).into_iter().collect();
        let keep_alive = Open::new(message, at_us);
        seen.extend(match sender {
            Sender::Tester
                if message == [sid::TESTER_PRESENT, 0x80]
                    && self.open.as_ref().is_some_and(Open::owed_a_response) =>
            {
                Some(keep_alive.close(Outcome::Suppressed))
            }
            Sender::Tester => self.request(keep_alive),
            Sender::Ecu => self.response(message, at_us),
        });
        seen
    }

    /// Ends the open request if it has been quiet for the timeout, for a
    /// caller with no further traffic to observe.
    pub fn expire(&mut self, now_us: u64) -> Option<Observed> {
        let timeout_us = self.timeout_us;
        let open = self
            .open
            .take_if(|o| now_us.saturating_sub(o.last_us) >= timeout_us)?;
        Some(open.close_unanswered(Outcome::TimedOut))
    }

    /// Ends the open request at the end of the capture.
    pub fn finish(&mut self) -> Option<Observed> {
        Some(self.open.take()?.close_unanswered(Outcome::Unfinished))
    }

    fn request(&mut self, open: Open) -> Option<Observed> {
        Some(
            self.open
                .replace(open)?
                .close_unanswered(Outcome::Superseded),
        )
    }

    fn response(&mut self, message: &[u8], at_us: u64) -> Option<Observed> {
        let unsolicited = || Observed::Unsolicited {
            response: message.to_vec(),
            at_us,
        };
        let Some(open) = self.open.as_mut() else {
            return Some(unsolicited());
        };
        let Some(answer) = answers(&open.request, message) else {
            return Some(unsolicited());
        };
        if answer
            == (Answer::Negative {
                code: Nrc::RESPONSE_PENDING,
            })
        {
            open.pending += 1;
            open.last_us = at_us;
            return None;
        }
        let open = self.open.take()?;
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
