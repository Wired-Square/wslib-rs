//! A tester's side of one conversation, sans-IO: the caller moves the bytes
//! and supplies the time.

use std::time::{Duration, Instant};

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
    /// sends a tester present; `None` sends none.
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

/// What a received message or the passing of time meant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    Positive(Response),
    Negative {
        service: u8,
        code: Nrc,
    },
    /// responsePending: the deadline has moved to P2*. There is no cap on how
    /// many may come; [`Client::abandon`] gives up.
    Pending {
        deadline: Instant,
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
    /// S3 ran out, so the server has returned to the default session.
    SessionExpired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("a request is still outstanding")]
pub struct Busy;

const TESTER_PRESENT_SUPPRESSED: [u8; 2] = [sid::TESTER_PRESENT, 0x80];

#[derive(Debug, Clone)]
pub struct Client {
    defaults: Timing,
    timing: Timing,
    session: u8,
    security_level: Option<u8>,
    outstanding: Option<Outstanding>,
    keep_alive_sent: Option<Instant>,
    last_activity: Option<Instant>,
}

#[derive(Debug, Clone)]
struct Outstanding {
    request: Vec<u8>,
    deadline: Instant,
    pending: bool,
}

impl Client {
    /// `timing`'s P2 and P2* are also the defaults the client returns to.
    pub fn new(timing: Timing) -> Self {
        Self {
            defaults: timing,
            timing,
            session: DEFAULT_SESSION,
            security_level: None,
            outstanding: None,
            keep_alive_sent: None,
            last_activity: None,
        }
    }

    pub fn session(&self) -> u8 {
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

    /// The bytes to send for any request.
    #[cfg(feature = "write")]
    pub fn send(&mut self, request: Request, now: Instant) -> Result<Vec<u8>, Busy> {
        self.start(request, now)
    }

    fn start(&mut self, request: Request, now: Instant) -> Result<Vec<u8>, Busy> {
        if self.outstanding.is_some() {
            return Err(Busy);
        }
        let bytes = request.encode();
        self.last_activity = Some(now);
        self.outstanding = Some(Outstanding {
            request: bytes.clone(),
            deadline: now + self.timing.p2 + self.timing.margin,
            pending: false,
        });
        Ok(bytes)
    }

    /// Gives up on the outstanding request and returns it; S3 counts from `now`.
    pub fn abandon(&mut self, now: Instant) -> Option<Vec<u8>> {
        let abandoned = self.outstanding.take()?;
        self.last_activity = Some(now);
        Some(abandoned.request)
    }

    /// A refusal of a tester present goes to the keep-alive while one is
    /// within P2 of being sent: it always went before any caller request.
    pub fn receive(&mut self, message: &[u8], now: Instant) -> Event {
        let unexpected = || Event::Unexpected(message.to_vec());
        let keep_alive_deadline = self.timing.p2 + self.timing.margin;
        if let Some(Answer::Negative { code }) = answers(&TESTER_PRESENT_SUPPRESSED, message)
            && self
                .keep_alive_sent
                .take_if(|sent| now < *sent + keep_alive_deadline)
                .is_some()
        {
            return Event::KeepAliveRefused { code };
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
                let deadline = now + self.timing.p2_star + self.timing.margin;
                outstanding.deadline = deadline;
                outstanding.pending = true;
                Event::Pending { deadline }
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
                                self.enter_session(*session, None)
                            }
                            (sid::ECU_RESET, _) => self.enter_session(DEFAULT_SESSION, None),
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
        if let Some(done) = self.outstanding.take_if(|o| now >= o.deadline) {
            self.last_activity = Some(now);
            let service = done.request[0];
            if done.pending || !suppresses_positive_response(&done.request) {
                return Some(Event::Timeout { service });
            }
            match done.request[..] {
                [sid::DIAGNOSTIC_SESSION_CONTROL, sub, ..] => self.enter_session(sub & 0x7F, None),
                [sid::ECU_RESET, ..] => self.enter_session(DEFAULT_SESSION, None),
                _ => {}
            }
            return Some(Event::Suppressed { service });
        }
        if self.outstanding.is_some() || self.session == DEFAULT_SESSION {
            return None;
        }
        let last = self.last_activity?;
        if now >= last + self.timing.s3 {
            self.enter_session(DEFAULT_SESSION, None);
            return Some(Event::SessionExpired);
        }
        if now >= last + self.timing.keep_alive? {
            self.last_activity = Some(now);
            self.keep_alive_sent = Some(now);
            return Some(Event::TesterPresent(TESTER_PRESENT_SUPPRESSED.to_vec()));
        }
        None
    }

    /// When [`Client::poll`] next has something to say.
    pub fn next_deadline(&self) -> Option<Instant> {
        if let Some(o) = &self.outstanding {
            return Some(o.deadline);
        }
        if self.session == DEFAULT_SESSION {
            return None;
        }
        let last = self.last_activity?;
        let expiry = last + self.timing.s3;
        Some(
            self.timing
                .keep_alive
                .map_or(expiry, |k| expiry.min(last + k)),
        )
    }

    /// Locks security; P2 and P2* become the reported ones, or the defaults.
    fn enter_session(&mut self, session: u8, reported: Option<SessionTiming>) {
        self.session = session;
        self.security_level = None;
        (self.timing.p2, self.timing.p2_star) = match reported {
            Some(t) => (t.p2(), t.p2_star()),
            None => (self.defaults.p2, self.defaults.p2_star),
        };
    }

    fn apply(&mut self, response: &Response) {
        match response {
            Response::DiagnosticSessionControl { session, timing } => {
                self.enter_session(*session, *timing)
            }
            Response::EcuReset { .. } => self.enter_session(DEFAULT_SESSION, None),
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
