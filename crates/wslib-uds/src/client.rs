//! A tester's side of one conversation, sans-IO: the caller moves the bytes
//! and supplies the time.

use std::time::{Duration, Instant};

#[cfg(feature = "write")]
use crate::Safety;
use crate::answer::suppresses_positive_response;
use crate::codec::DEFAULT_SESSION;
use crate::{Answer, Nrc, ReadOnly, Request, Response, SessionTiming, answers, sid};

/// The timers a client runs to. P2 and P2* are the server's, and are replaced
/// by the values a positive session-control response reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Timing {
    pub p2: Duration,
    pub p2_star: Duration,
    pub s3: Duration,
    /// How long the client stays quiet in a non-default session before it
    /// sends a tester present; `None` or zero sends none.
    pub keep_alive: Option<Duration>,
    /// Added to P2 and P2* for the transport's own delay.
    pub margin: Duration,
}

impl Default for Timing {
    fn default() -> Self {
        Self {
            p2: Duration::from_millis(50),
            p2_star: Duration::from_millis(5000),
            s3: Duration::from_millis(5000),
            keep_alive: Some(Duration::from_millis(2000)),
            margin: Duration::from_millis(50),
        }
    }
}

impl Timing {
    fn answer_within(&self, limit: Duration, since: Instant) -> Wait {
        Wait {
            since,
            length: limit.saturating_add(self.margin),
        }
    }
}

/// What a received message or the passing of time meant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    Positive(Response),
    Negative {
        service: u8,
        code: Nrc,
    },
    /// responsePending: the deadline has moved to P2*, or is `None` when P2*
    /// is too long for an `Instant` to hold. There is no cap on how many may
    /// come; [`Client::abandon`] gives up.
    Pending {
        deadline: Option<Instant>,
    },
    /// A request that suppressed its positive response drew no negative one by P2.
    Suppressed {
        service: u8,
    },
    Timeout {
        service: u8,
    },
    /// A positive answer to the outstanding request that fails strict decoding.
    Malformed(Vec<u8>),
    /// A message that answers no outstanding request; it changes nothing.
    Unexpected(Vec<u8>),
    /// Send these bytes: a tester present to hold the session.
    TesterPresent(Vec<u8>),
    /// The server refused the keep-alive tester present.
    KeepAliveRefused {
        code: Nrc,
    },
    /// responsePending to the keep-alive: its final answer may still come up
    /// to P2* from now.
    KeepAlivePending,
    /// The keep-alive's final positive answer, after its responsePending.
    KeepAliveAnswered,
    /// S3 ran out, so the server has returned to the default session.
    SessionExpired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("a request is still outstanding")]
pub struct Busy;

/// Why [`Client::send`] sent nothing.
#[cfg(feature = "write")]
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SendError {
    #[error("a request is still outstanding")]
    Busy,
    #[error("a {safety:?} request is above the client's ceiling of {ceiling:?}")]
    AboveCeiling {
        request: Request,
        safety: Safety,
        ceiling: Safety,
    },
}

const TESTER_PRESENT_SUPPRESSED: [u8; 2] = [sid::TESTER_PRESENT, 0x80];

#[derive(Debug, Clone)]
pub struct Client {
    defaults: Timing,
    timing: Timing,
    #[cfg(feature = "write")]
    ceiling: Safety,
    session: Option<u8>,
    security_level: Option<u8>,
    outstanding: Option<Outstanding>,
    keep_alive: Option<KeepAlive>,
    last_activity: Option<Instant>,
}

#[derive(Debug, Clone)]
struct Outstanding {
    request: Vec<u8>,
    wait: Wait,
    pending: bool,
}

#[derive(Debug, Clone, Copy)]
struct KeepAlive {
    window: Wait,
    pending: bool,
}

/// A wait too long for an `Instant` to hold never ends.
#[derive(Debug, Clone, Copy)]
struct Wait {
    since: Instant,
    length: Duration,
}

impl Wait {
    fn is_over(self, now: Instant) -> bool {
        now.saturating_duration_since(self.since) >= self.length
    }

    fn deadline(self) -> Option<Instant> {
        self.since.checked_add(self.length)
    }
}

impl Client {
    /// A client that sends only read-only requests; `timing`'s P2 and P2* are
    /// also the defaults it returns to.
    pub fn new(timing: Timing) -> Self {
        Self {
            defaults: timing,
            timing,
            #[cfg(feature = "write")]
            ceiling: Safety::ReadOnly,
            session: Some(DEFAULT_SESSION),
            security_level: None,
            outstanding: None,
            keep_alive: None,
            last_activity: None,
        }
    }

    /// A client whose [`Client::send`] refuses any request above `ceiling`.
    #[cfg(feature = "write")]
    pub fn up_to(timing: Timing, ceiling: Safety) -> Self {
        Self {
            ceiling,
            ..Self::new(timing)
        }
    }

    /// `None` after a session change or reset timed out or was abandoned: the
    /// server may have acted on it. An answer to it arriving later is
    /// [`Event::Unexpected`] and changes nothing; the session stays unknown
    /// until the next answered session change or reset, or S3.
    pub fn session(&self) -> Option<u8> {
        self.session
    }

    /// The request-seed sub-function of the level unlocked, if any.
    pub fn security_level(&self) -> Option<u8> {
        self.security_level
    }

    pub fn timing(&self) -> Timing {
        self.timing
    }

    pub fn is_busy(&self) -> bool {
        self.outstanding.is_some()
    }

    /// The bytes to send for a read-only request.
    pub fn send_read_only(&mut self, request: ReadOnly, now: Instant) -> Result<Vec<u8>, Busy> {
        self.start(request.into_request(), now)
    }

    /// The bytes to send for a request no higher than the client's ceiling.
    #[cfg(feature = "write")]
    pub fn send(&mut self, request: Request, now: Instant) -> Result<Vec<u8>, SendError> {
        let safety = request.safety();
        if safety > self.ceiling {
            return Err(SendError::AboveCeiling {
                request,
                safety,
                ceiling: self.ceiling,
            });
        }
        self.start(request, now).map_err(|Busy| SendError::Busy)
    }

    fn start(&mut self, request: Request, now: Instant) -> Result<Vec<u8>, Busy> {
        if self.outstanding.is_some() {
            return Err(Busy);
        }
        let bytes = request.encode();
        if bytes[0] == sid::TESTER_PRESENT {
            self.keep_alive.take_if(|k| k.pending);
        }
        self.last_activity = Some(now);
        self.outstanding = Some(Outstanding {
            request: bytes.clone(),
            wait: self.timing.answer_within(self.timing.p2, now),
            pending: false,
        });
        Ok(bytes)
    }

    /// Gives up on the outstanding request and returns it; S3 counts from `now`.
    pub fn abandon(&mut self, now: Instant) -> Option<Vec<u8>> {
        let abandoned = self.outstanding.take()?;
        self.last_activity = Some(now);
        self.unanswered(&abandoned.request);
        Some(abandoned.request)
    }

    /// A refusal of a tester present goes to the keep-alive within P2 plus the
    /// margin of its sending, since it always went before any caller request.
    /// After a responsePending to it, its final answer, refusal or positive,
    /// is awaited for P2* plus the margin, until the caller sends a tester
    /// present of its own.
    pub fn receive(&mut self, message: &[u8], now: Instant) -> Event {
        let unexpected = || Event::Unexpected(message.to_vec());
        if let Some(answer) = answers(&TESTER_PRESENT_SUPPRESSED, message)
            && let Some(keep_alive) = self.keep_alive.filter(|k| !k.window.is_over(now))
            && (keep_alive.pending || matches!(answer, Answer::Negative { .. }))
        {
            self.keep_alive = None;
            return match answer {
                Answer::Negative {
                    code: Nrc::RESPONSE_PENDING,
                } => {
                    self.keep_alive = Some(KeepAlive {
                        window: self.timing.answer_within(self.timing.p2_star, now),
                        pending: true,
                    });
                    Event::KeepAlivePending
                }
                Answer::Negative { code } => Event::KeepAliveRefused { code },
                Answer::Positive => Event::KeepAliveAnswered,
            };
        }
        let Some(outstanding) = self.outstanding.as_mut() else {
            return unexpected();
        };
        let Some(answer) = answers(&outstanding.request, message) else {
            return unexpected();
        };
        let service = outstanding.request[0];
        self.last_activity = Some(now);
        match answer {
            Answer::Negative {
                code: Nrc::RESPONSE_PENDING,
            } => {
                outstanding.wait = self.timing.answer_within(self.timing.p2_star, now);
                outstanding.pending = true;
                Event::Pending {
                    deadline: outstanding.wait.deadline(),
                }
            }
            Answer::Negative { code } => {
                self.outstanding = None;
                Event::Negative { service, code }
            }
            Answer::Positive => {
                self.outstanding = None;
                match Response::decode(message) {
                    Ok(response) => {
                        self.apply(&response);
                        Event::Positive(response)
                    }
                    Err(_) => {
                        match (service, message.get(1)) {
                            (sid::DIAGNOSTIC_SESSION_CONTROL, Some(session)) => {
                                self.enter_session(Some(*session), None)
                            }
                            (sid::ECU_RESET, _) => self.enter_session(Some(DEFAULT_SESSION), None),
                            _ => {}
                        }
                        Event::Malformed(message.to_vec())
                    }
                }
            }
        }
    }

    /// A timeout, a suppressed request's end, S3's expiry or a due tester present.
    pub fn poll(&mut self, now: Instant) -> Option<Event> {
        if let Some(done) = self.outstanding.take_if(|o| o.wait.is_over(now)) {
            self.last_activity = Some(now);
            let service = done.request[0];
            if done.pending || !suppresses_positive_response(&done.request) {
                self.unanswered(&done.request);
                return Some(Event::Timeout { service });
            }
            match done.request[..] {
                [sid::DIAGNOSTIC_SESSION_CONTROL, sub, ..] => {
                    self.enter_session(Some(sub & 0x7F), None)
                }
                [sid::ECU_RESET, ..] => self.enter_session(Some(DEFAULT_SESSION), None),
                [sid::SECURITY_ACCESS, ..] => self.security_level = None,
                _ => {}
            }
            return Some(Event::Suppressed { service });
        }
        if self.outstanding.is_some() || self.session == Some(DEFAULT_SESSION) {
            return None;
        }
        if self.s3()?.is_over(now) {
            self.enter_session(Some(DEFAULT_SESSION), None);
            return Some(Event::SessionExpired);
        }
        if self.keep_alive_after()?.is_over(now) {
            self.last_activity = Some(now);
            self.keep_alive = Some(KeepAlive {
                window: self.timing.answer_within(self.timing.p2, now),
                pending: false,
            });
            return Some(Event::TesterPresent(TESTER_PRESENT_SUPPRESSED.to_vec()));
        }
        None
    }

    /// When [`Client::poll`] next has something to say; `None` also when the
    /// only wait left is too long for an `Instant` to hold.
    pub fn next_deadline(&self) -> Option<Instant> {
        if let Some(o) = &self.outstanding {
            return o.wait.deadline();
        }
        if self.session == Some(DEFAULT_SESSION) {
            return None;
        }
        [self.s3(), self.keep_alive_after()]
            .into_iter()
            .flatten()
            .filter_map(Wait::deadline)
            .min()
    }

    fn s3(&self) -> Option<Wait> {
        Some(Wait {
            since: self.last_activity?,
            length: self.timing.s3,
        })
    }

    /// No keep-alive holds a session the client does not know it is in.
    fn keep_alive_after(&self) -> Option<Wait> {
        Some(Wait {
            since: self.last_activity?,
            length: self
                .timing
                .keep_alive
                .filter(|k| !k.is_zero() && self.session.is_some())?,
        })
    }

    /// Locks security; P2 and P2* become the reported ones, or the defaults.
    fn enter_session(&mut self, session: Option<u8>, reported: Option<SessionTiming>) {
        self.session = session;
        self.security_level = None;
        (self.timing.p2, self.timing.p2_star) = match reported {
            Some(t) => (t.p2(), t.p2_star()),
            None => (self.defaults.p2, self.defaults.p2_star),
        };
    }

    /// The server may have acted on a request it never answered.
    fn unanswered(&mut self, request: &[u8]) {
        match request.first() {
            Some(&(sid::DIAGNOSTIC_SESSION_CONTROL | sid::ECU_RESET)) => {
                self.enter_session(None, None)
            }
            Some(&sid::SECURITY_ACCESS) => self.security_level = None,
            _ => {}
        }
    }

    fn apply(&mut self, response: &Response) {
        match response {
            Response::DiagnosticSessionControl { session, timing } => {
                self.enter_session(Some(*session), *timing)
            }
            Response::EcuReset { .. } => self.enter_session(Some(DEFAULT_SESSION), None),
            Response::SecurityAccess { sub_function, .. } if sub_function % 2 == 0 => {
                self.security_level = sub_function.checked_sub(1);
            }
            Response::SecurityAccess { sub_function, data }
                if !data.is_empty() && data.iter().all(|b| *b == 0) =>
            {
                self.security_level = Some(*sub_function);
            }
            _ => {}
        }
    }
}
