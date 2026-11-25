//! Scans as plans the caller drives: take the next probe, send it, report the
//! final reply or `None` for silence. Waiting and pending answers are the
//! caller's. No plan searches for a security key.

use std::ops::RangeInclusive;

use serde::{Deserialize, Serialize};

use crate::codec::{NonEmpty, SubFunction};
use crate::{Answer, Nrc, ReadOnly, Request, Safety, answers, sid};

/// How many times a plan re-offers a probe answered busyRepeatRequest.
pub const DEFAULT_BUSY_RETRIES: u32 = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(rename = "UdsScanProgress"))]
#[serde(rename_all = "camelCase")]
pub struct ScanProgress {
    pub done: u32,
    pub total: u32,
    pub found: u32,
    /// The plan stopped on a finding that ends it, and offers no more probes.
    pub stopped_early: bool,
}

#[derive(Debug, Clone)]
struct Plan<T, F> {
    items: Vec<T>,
    next: usize,
    findings: Vec<F>,
    found: u32,
    busy_retries: u32,
    busy_run: u32,
    stopped: bool,
}

impl<T: Copy, F> Plan<T, F> {
    fn new(items: impl IntoIterator<Item = T>) -> Self {
        Self {
            items: items.into_iter().collect(),
            next: 0,
            findings: Vec::new(),
            found: 0,
            busy_retries: DEFAULT_BUSY_RETRIES,
            busy_run: 0,
            stopped: false,
        }
    }

    fn current(&self) -> Option<T> {
        if self.stopped {
            return None;
        }
        self.items.get(self.next).copied()
    }

    fn record(&mut self, finding: F, busy: bool, found: bool) {
        if busy && self.busy_run < self.busy_retries {
            self.busy_run += 1;
            return;
        }
        self.busy_run = 0;
        self.next += 1;
        self.found += u32::from(found);
        self.findings.push(finding);
    }

    #[cfg(feature = "write")]
    fn stop(&mut self, finding: F) {
        self.findings.push(finding);
        self.stopped = true;
    }

    fn progress(&self) -> ScanProgress {
        let count = |n: usize| u32::try_from(n).unwrap_or(u32::MAX);
        ScanProgress {
            done: count(self.next),
            total: count(self.items.len()),
            found: self.found,
            stopped_early: self.stopped,
        }
    }
}

/// A tester present to one candidate address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AddressProbe {
    pub address: u32,
}

impl AddressProbe {
    pub fn request(&self) -> ReadOnly {
        let tester_present = Request::TesterPresent {
            sub_function: SubFunction::new(0),
        };
        ReadOnly::new(tester_present).expect("tester present is read-only")
    }

    pub fn safety(&self) -> Safety {
        self.request().request().safety()
    }
}

/// A positive or negative answer to the tester present probe means an ECU.
pub fn ecu_answered(reply: Option<&[u8]>) -> bool {
    reply.is_some_and(|r| answers(&[sid::TESTER_PRESENT, 0x00], r).is_some())
}

/// Which addresses answer a tester present.
#[derive(Debug, Clone)]
pub struct AddressScan(Plan<u32, bool>);

impl AddressScan {
    pub fn new(addresses: impl IntoIterator<Item = u32>) -> Self {
        Self(Plan::new(addresses))
    }

    /// 11-bit request ids 0x700 to 0x7FF.
    pub fn eleven_bit() -> Self {
        Self::new(0x700..=0x7FF)
    }

    /// 29-bit normal fixed addressing: 0x18DA, then each target address, then `tester`.
    pub fn normal_fixed(tester: u8) -> Self {
        Self::new((0..=0xFF).map(|target: u32| 0x18DA_0000 | target << 8 | u32::from(tester)))
    }

    /// The same probe until it is reported.
    pub fn next_probe(&self) -> Option<AddressProbe> {
        self.0.current().map(|address| AddressProbe { address })
    }

    /// `None` when the scan is done.
    pub fn report(&mut self, reply: Option<&[u8]>) -> Option<bool> {
        self.0.current()?;
        let answered = ecu_answered(reply);
        self.0.record(answered, false, answered);
        Some(answered)
    }

    pub fn progress(&self) -> ScanProgress {
        self.0.progress()
    }

    pub fn found(&self) -> Vec<u32> {
        let answered = self.0.items.iter().zip(&self.0.findings);
        answered
            .filter(|(_, a)| **a)
            .map(|(address, _)| *address)
            .collect()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(rename = "UdsServiceVerdict"))]
#[serde(tag = "kind", rename_all = "camelCase")]
#[serde(rename_all_fields = "camelCase")]
pub enum ServiceVerdict {
    /// `code` is the refusal that proved it.
    Present {
        code: Nrc,
    },
    Absent,
    /// serviceNotSupportedInActiveSession.
    NotInSession,
    Busy,
    /// A positive answer: the server acted on a bare service id.
    Executed,
    Inconclusive,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(rename = "UdsServiceFinding"))]
#[serde(rename_all = "camelCase")]
pub struct ServiceFinding {
    pub service: u8,
    pub verdict: ServiceVerdict,
}

/// A bare service id, of the class its service has with the sub-function unknown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServiceProbe {
    service: u8,
}

impl ServiceProbe {
    pub fn service(&self) -> u8 {
        self.service
    }

    /// Without `write`, every probe a plan offers passes [`ReadOnly::new`].
    pub fn request(&self) -> Request {
        Request::Other {
            service: self.service,
            data: Vec::new(),
        }
    }

    pub fn safety(&self) -> Safety {
        Safety::of(&[self.service])
    }
}

pub fn service_verdict(service: u8, reply: Option<&[u8]>) -> ServiceVerdict {
    match reply.and_then(|r| answers(&[service], r)) {
        Some(Answer::Positive) => ServiceVerdict::Executed,
        Some(Answer::Negative { code }) => match code {
            Nrc::SERVICE_NOT_SUPPORTED => ServiceVerdict::Absent,
            Nrc::SERVICE_NOT_SUPPORTED_IN_ACTIVE_SESSION => ServiceVerdict::NotInSession,
            Nrc::BUSY_REPEAT_REQUEST => ServiceVerdict::Busy,
            Nrc::RESPONSE_PENDING => ServiceVerdict::Inconclusive,
            code => ServiceVerdict::Present { code },
        },
        None => ServiceVerdict::Inconclusive,
    }
}

/// Which ISO services a server has, probed by bare id; it stops at the first
/// bare id above read-only that the server acts on. RequestTransferExit, whose
/// bare id is a whole request, and the vendor ranges are not probed.
#[derive(Debug, Clone)]
pub struct ServiceScan(Plan<u8, ServiceFinding>);

impl Default for ServiceScan {
    fn default() -> Self {
        Self::new()
    }
}

impl ServiceScan {
    /// Only the services whose bare id is read-only.
    pub fn new() -> Self {
        Self::over(Safety::ReadOnly)
    }

    /// The services whose bare id is at most `highest`.
    #[cfg(feature = "write")]
    pub fn up_to(highest: Safety) -> Self {
        Self::over(highest)
    }

    fn over(highest: Safety) -> Self {
        let services =
            sid::iso().filter(|s| *s != sid::REQUEST_TRANSFER_EXIT && Safety::of(&[*s]) <= highest);
        Self(Plan::new(services))
    }

    pub fn with_busy_retries(mut self, retries: u32) -> Self {
        self.0.busy_retries = retries;
        self
    }

    /// The same probe until it is reported, and again after a busy answer.
    pub fn next_probe(&self) -> Option<ServiceProbe> {
        self.0.current().map(|service| ServiceProbe { service })
    }

    /// `None` when the scan is done.
    pub fn report(&mut self, reply: Option<&[u8]>) -> Option<ServiceVerdict> {
        let service = self.0.current()?;
        let verdict = service_verdict(service, reply);
        let found = matches!(
            verdict,
            ServiceVerdict::Present { .. }
                | ServiceVerdict::NotInSession
                | ServiceVerdict::Executed
        );
        let finding = ServiceFinding { service, verdict };
        self.0
            .record(finding, verdict == ServiceVerdict::Busy, found);
        self.0.stopped =
            verdict == ServiceVerdict::Executed && Safety::of(&[service]) > Safety::ReadOnly;
        Some(verdict)
    }

    pub fn progress(&self) -> ScanProgress {
        self.0.progress()
    }

    pub fn findings(&self) -> &[ServiceFinding] {
        &self.0.findings
    }
}

/// A bare service id whose class is read-only, from a [`ReadOnlyServiceScan`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReadOnlyServiceProbe {
    service: u8,
}

impl ReadOnlyServiceProbe {
    pub fn service(&self) -> u8 {
        self.service
    }

    pub fn request(&self) -> ReadOnly {
        let bare = Request::Other {
            service: self.service,
            data: Vec::new(),
        };
        ReadOnly::new(bare).expect("a read-only scan offers only read-only bare ids")
    }
}

/// [`ServiceScan::new`]'s scan, whose probes are already [`ReadOnly`] for a
/// client's `send_read_only`.
#[derive(Debug, Clone, Default)]
pub struct ReadOnlyServiceScan(ServiceScan);

impl ReadOnlyServiceScan {
    pub fn new() -> Self {
        Self(ServiceScan::new())
    }

    pub fn with_busy_retries(self, retries: u32) -> Self {
        Self(self.0.with_busy_retries(retries))
    }

    /// The same probe until it is reported, and again after a busy answer.
    pub fn next_probe(&self) -> Option<ReadOnlyServiceProbe> {
        let service = self.0.next_probe()?.service;
        Some(ReadOnlyServiceProbe { service })
    }

    /// `None` when the scan is done.
    pub fn report(&mut self, reply: Option<&[u8]>) -> Option<ServiceVerdict> {
        self.0.report(reply)
    }

    pub fn progress(&self) -> ScanProgress {
        self.0.progress()
    }

    pub fn findings(&self) -> &[ServiceFinding] {
        self.0.findings()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(rename = "UdsDidVerdict"))]
#[serde(tag = "kind", rename_all = "camelCase")]
#[serde(rename_all_fields = "camelCase")]
pub enum DidVerdict {
    Present {
        length: u32,
    },
    /// requestOutOfRange.
    Absent,
    /// securityAccessDenied.
    Locked,
    /// serviceNotSupportedInActiveSession.
    NotInSession,
    Busy,
    /// Any other refusal, or `None` for silence or an answer to something else.
    Inconclusive {
        code: Option<Nrc>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(rename = "UdsDidFinding"))]
#[serde(rename_all = "camelCase")]
pub struct DidFinding {
    pub did: u16,
    pub verdict: DidVerdict,
}

/// A ReadDataByIdentifier for one DID.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DidProbe {
    pub did: u16,
}

impl DidProbe {
    pub fn request(&self) -> ReadOnly {
        let read = Request::ReadDataByIdentifier {
            dids: NonEmpty::one(self.did),
        };
        ReadOnly::new(read).expect("ReadDataByIdentifier is read-only")
    }

    pub fn safety(&self) -> Safety {
        self.request().request().safety()
    }
}

pub fn did_verdict(did: u16, reply: Option<&[u8]>) -> DidVerdict {
    let [hi, lo] = did.to_be_bytes();
    let Some(reply) = reply else {
        return DidVerdict::Inconclusive { code: None };
    };
    match answers(&[sid::READ_DATA_BY_IDENTIFIER, hi, lo], reply) {
        Some(Answer::Positive) => DidVerdict::Present {
            length: u32::try_from(reply.len() - 3).unwrap_or(u32::MAX),
        },
        Some(Answer::Negative { code }) => match code {
            Nrc::REQUEST_OUT_OF_RANGE => DidVerdict::Absent,
            Nrc::SECURITY_ACCESS_DENIED => DidVerdict::Locked,
            Nrc::SERVICE_NOT_SUPPORTED_IN_ACTIVE_SESSION => DidVerdict::NotInSession,
            Nrc::BUSY_REPEAT_REQUEST => DidVerdict::Busy,
            code => DidVerdict::Inconclusive { code: Some(code) },
        },
        None => DidVerdict::Inconclusive { code: None },
    }
}

/// Which DIDs a server reads, one per request.
#[derive(Debug, Clone)]
pub struct DidScan(Plan<u16, DidFinding>);

impl DidScan {
    pub fn new(dids: RangeInclusive<u16>) -> Self {
        Self(Plan::new(dids))
    }

    pub fn with_busy_retries(mut self, retries: u32) -> Self {
        self.0.busy_retries = retries;
        self
    }

    /// The same probe until it is reported, and again after a busy answer.
    pub fn next_probe(&self) -> Option<DidProbe> {
        self.0.current().map(|did| DidProbe { did })
    }

    /// `None` when the scan is done.
    pub fn report(&mut self, reply: Option<&[u8]>) -> Option<DidVerdict> {
        let did = self.0.current()?;
        let verdict = did_verdict(did, reply);
        let found = matches!(verdict, DidVerdict::Present { .. });
        self.0.record(
            DidFinding { did, verdict },
            verdict == DidVerdict::Busy,
            found,
        );
        Some(verdict)
    }

    pub fn progress(&self) -> ScanProgress {
        self.0.progress()
    }

    pub fn findings(&self) -> &[DidFinding] {
        &self.0.findings
    }
}

#[cfg(feature = "write")]
pub use session::*;

#[cfg(feature = "write")]
mod session {
    use std::ops::RangeInclusive;

    use serde::{Deserialize, Serialize};

    use super::Plan;
    use crate::codec::{DEFAULT_SESSION, PROGRAMMING_SESSION, SessionTiming, SubFunction};
    use crate::{Answer, Nrc, Request, Response, Safety, ScanProgress, answers, sid};

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
    #[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(rename = "UdsSessionVerdict"))]
    #[serde(tag = "kind", rename_all = "camelCase")]
    #[serde(rename_all_fields = "camelCase")]
    pub enum SessionVerdict {
        /// `timing` is `None` when the answer did not report one or failed strict decoding.
        Supported {
            timing: Option<SessionTiming>,
        },
        /// subFunctionNotSupported.
        Unsupported,
        /// subFunctionNotSupportedInActiveSession: it may exist, but not from the default session.
        NotFromThisSession,
        ConditionsNotCorrect,
        Locked,
        Busy,
        Inconclusive {
            code: Option<Nrc>,
        },
        /// The return to the default session after probing this one was
        /// refused with `code`, or went unanswered: the ECU may still be in
        /// this session, and the plan has stopped.
        NotRestored {
            code: Option<Nrc>,
        },
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
    #[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(rename = "UdsSessionFinding"))]
    #[serde(rename_all = "camelCase")]
    pub struct SessionFinding {
        pub session: u8,
        pub verdict: SessionVerdict,
    }

    /// A session-control request; `restore` is the return to the default
    /// session after a probe that may have left it.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct SessionProbe {
        pub session: u8,
        pub restore: bool,
    }

    impl SessionProbe {
        pub fn request(&self) -> Request {
            Request::DiagnosticSessionControl {
                sub_function: SubFunction::new(self.session),
            }
        }

        pub fn safety(&self) -> Safety {
            self.request().safety()
        }
    }

    fn answer(session: u8, reply: Option<&[u8]>) -> Option<Answer> {
        answers(&[sid::DIAGNOSTIC_SESSION_CONTROL, session], reply?)
    }

    pub fn session_verdict(session: u8, reply: Option<&[u8]>) -> SessionVerdict {
        match answer(session, reply) {
            Some(Answer::Positive) => SessionVerdict::Supported {
                timing: match reply.map(Response::decode) {
                    Some(Ok(Response::DiagnosticSessionControl { timing, .. })) => timing,
                    _ => None,
                },
            },
            Some(Answer::Negative { code }) => match code {
                Nrc::SUB_FUNCTION_NOT_SUPPORTED => SessionVerdict::Unsupported,
                Nrc::SUB_FUNCTION_NOT_SUPPORTED_IN_ACTIVE_SESSION => {
                    SessionVerdict::NotFromThisSession
                }
                Nrc::CONDITIONS_NOT_CORRECT => SessionVerdict::ConditionsNotCorrect,
                Nrc::SECURITY_ACCESS_DENIED => SessionVerdict::Locked,
                Nrc::BUSY_REPEAT_REQUEST => SessionVerdict::Busy,
                code => SessionVerdict::Inconclusive { code: Some(code) },
            },
            None => SessionVerdict::Inconclusive { code: None },
        }
    }

    /// Which sessions a server enters from the default one. After any probe
    /// of a non-default session that did not end in a definite refusal, it
    /// returns to the default session, and stops if that return is not
    /// answered positively. The programming session is skipped unless asked
    /// for.
    #[derive(Debug, Clone)]
    pub struct SessionScan {
        plan: Plan<u8, SessionFinding>,
        restore_from: Option<u8>,
    }

    impl SessionScan {
        pub fn new(sessions: RangeInclusive<u8>) -> Self {
            Self::over(sessions.filter(|s| *s != PROGRAMMING_SESSION))
        }

        pub fn including_programming(sessions: RangeInclusive<u8>) -> Self {
            Self::over(sessions)
        }

        fn over(sessions: impl Iterator<Item = u8>) -> Self {
            Self {
                plan: Plan::new(sessions.filter(|s| *s <= 0x7F)),
                restore_from: None,
            }
        }

        pub fn with_busy_retries(mut self, retries: u32) -> Self {
            self.plan.busy_retries = retries;
            self
        }

        /// The same probe until it is reported, and again after a busy answer.
        pub fn next_probe(&self) -> Option<SessionProbe> {
            if self.restore_from.is_some() {
                return Some(SessionProbe {
                    session: DEFAULT_SESSION,
                    restore: true,
                });
            }
            self.plan.current().map(|session| SessionProbe {
                session,
                restore: false,
            })
        }

        /// `None` for a restore that succeeded, or when the scan is done.
        pub fn report(&mut self, reply: Option<&[u8]>) -> Option<SessionVerdict> {
            if let Some(session) = self.restore_from.take() {
                let code = match answer(DEFAULT_SESSION, reply) {
                    Some(Answer::Positive) => return None,
                    Some(Answer::Negative { code }) => Some(code),
                    None => None,
                };
                let verdict = SessionVerdict::NotRestored { code };
                self.plan.stop(SessionFinding { session, verdict });
                return Some(verdict);
            }
            let session = self.plan.current()?;
            let verdict = session_verdict(session, reply);
            let refused = matches!(
                answer(session, reply),
                Some(Answer::Negative { code }) if code != Nrc::RESPONSE_PENDING
            );
            self.restore_from = (session != DEFAULT_SESSION && !refused).then_some(session);
            let supported = matches!(verdict, SessionVerdict::Supported { .. });
            let finding = SessionFinding { session, verdict };
            self.plan
                .record(finding, verdict == SessionVerdict::Busy, supported);
            Some(verdict)
        }

        pub fn progress(&self) -> ScanProgress {
            self.plan.progress()
        }

        pub fn findings(&self) -> &[SessionFinding] {
            &self.plan.findings
        }
    }
}
