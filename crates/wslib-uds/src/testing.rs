//! A simulated ECU, sans-IO: it answers one request at a time.

use std::collections::BTreeMap;

use crate::codec::{DEFAULT_SESSION, DtcRequest, DtcResponse, DtcStatus, SessionTiming};
use crate::{Nrc, Request, Response, sid};

/// The timing every session-control answer reports: P2 50 ms, P2* 5 s.
pub const TIMING: SessionTiming = SessionTiming {
    p2_server_max_ms: 50,
    p2_star_server_max_10ms: 500,
};

const AVAILABILITY_MASK: u8 = 0xFF;
const ISO_14229_1_DTC_FORMAT: u8 = 0x01;

const SUPPORTED: [u8; 11] = [
    sid::DIAGNOSTIC_SESSION_CONTROL,
    sid::ECU_RESET,
    sid::CLEAR_DIAGNOSTIC_INFORMATION,
    sid::READ_DTC_INFORMATION,
    sid::READ_DATA_BY_IDENTIFIER,
    sid::SECURITY_ACCESS,
    sid::COMMUNICATION_CONTROL,
    sid::WRITE_DATA_BY_IDENTIFIER,
    sid::ROUTINE_CONTROL,
    sid::TESTER_PRESENT,
    sid::CONTROL_DTC_SETTING,
];

const NON_DEFAULT_SESSION_ONLY: [u8; 3] = [
    sid::SECURITY_ACCESS,
    sid::COMMUNICATION_CONTROL,
    sid::CONTROL_DTC_SETTING,
];

/// A DID the ECU holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Did {
    value: Vec<u8>,
    writable: bool,
    sessions: Vec<u8>,
    needs_security: bool,
}

impl Did {
    pub fn readable(value: impl Into<Vec<u8>>) -> Self {
        Self {
            value: value.into(),
            writable: false,
            sessions: Vec::new(),
            needs_security: false,
        }
    }

    /// Readable too; a write must keep the value's length.
    pub fn writable(value: impl Into<Vec<u8>>) -> Self {
        Self {
            writable: true,
            ..Self::readable(value)
        }
    }

    /// Visible only in these sessions; out of them it answers requestOutOfRange.
    pub fn in_sessions(mut self, sessions: &[u8]) -> Self {
        self.sessions = sessions.to_vec();
        self
    }

    /// Answers securityAccessDenied until the security level is unlocked.
    pub fn needs_security(mut self) -> Self {
        self.needs_security = true;
        self
    }
}

type KeyCheck = Box<dyn FnMut(&[u8], &[u8]) -> bool + Send>;

struct Security {
    level: u8,
    seed: Vec<u8>,
    key_check: KeyCheck,
    seed_issued: bool,
}

struct Routine {
    id: u16,
    result: Vec<u8>,
    started: bool,
    running: bool,
}

/// Answers serviceNotSupported for every service it does not simulate.
pub struct Ecu {
    dids: BTreeMap<u16, Did>,
    sessions: Vec<u8>,
    session: u8,
    security: Option<Security>,
    unlocked: bool,
    dtcs: Vec<DtcStatus>,
    routine: Option<Routine>,
    pending: BTreeMap<u8, u32>,
}

impl Default for Ecu {
    fn default() -> Self {
        Self::new()
    }
}

impl Ecu {
    /// The default session only, and nothing configured.
    pub fn new() -> Self {
        Self {
            dids: BTreeMap::new(),
            sessions: vec![DEFAULT_SESSION],
            session: DEFAULT_SESSION,
            security: None,
            unlocked: false,
            dtcs: Vec::new(),
            routine: None,
            pending: BTreeMap::new(),
        }
    }

    pub fn with_did(mut self, did: u16, entry: Did) -> Self {
        self.dids.insert(did, entry);
        self
    }

    pub fn with_session(mut self, session: u8) -> Self {
        self.sessions.push(session);
        self
    }

    /// One security level, opened by request-seed sub-function `level` (odd)
    /// and `level + 1` with a key that `key_check(seed, key)` accepts; offered
    /// in non-default sessions only.
    pub fn with_security(
        mut self,
        level: u8,
        seed: impl Into<Vec<u8>>,
        key_check: impl FnMut(&[u8], &[u8]) -> bool + Send + 'static,
    ) -> Self {
        self.security = Some(Security {
            level,
            seed: seed.into(),
            key_check: Box::new(key_check),
            seed_issued: false,
        });
        self
    }

    pub fn with_dtc(mut self, dtc: u32, status: u8) -> Self {
        self.dtcs.push(DtcStatus { dtc, status });
        self
    }

    /// A routine whose results request answers `result` once it has started.
    pub fn with_routine(mut self, id: u16, result: impl Into<Vec<u8>>) -> Self {
        self.routine = Some(Routine {
            id,
            result: result.into(),
            started: false,
            running: false,
        });
        self
    }

    /// Precede every answer to `service` with `count` responsePending answers.
    pub fn with_pending(mut self, service: u8, count: u32) -> Self {
        self.pending.insert(service, count);
        self
    }

    pub fn active_session(&self) -> u8 {
        self.session
    }

    pub fn is_unlocked(&self) -> bool {
        self.unlocked
    }

    pub fn did(&self, did: u16) -> Option<&[u8]> {
        self.dids.get(&did).map(|d| d.value.as_slice())
    }

    pub fn dtcs(&self) -> &[DtcStatus] {
        &self.dtcs
    }

    /// The responses to one request, any responsePending ones first; empty
    /// when the positive response is suppressed.
    pub fn answer(&mut self, request: &[u8]) -> Vec<Vec<u8>> {
        let Some(&service) = request.first() else {
            return Vec::new();
        };
        let pending = self.pending.get(&service).copied().unwrap_or(0);
        let mut out: Vec<Vec<u8>> = (0..pending)
            .map(|_| negative(service, Nrc::RESPONSE_PENDING))
            .collect();
        match self.respond(service, request) {
            Ok((response, suppressed)) if !suppressed || pending > 0 => out.push(response.encode()),
            Ok(_) => {}
            Err(code) => out.push(negative(service, code)),
        }
        out
    }

    fn respond(&mut self, service: u8, message: &[u8]) -> Result<(Response, bool), Nrc> {
        if !SUPPORTED.contains(&service) {
            return Err(Nrc::SERVICE_NOT_SUPPORTED);
        }
        if NON_DEFAULT_SESSION_ONLY.contains(&service) && self.session == DEFAULT_SESSION {
            return Err(Nrc::SERVICE_NOT_SUPPORTED_IN_ACTIVE_SESSION);
        }
        if message.len() < minimum_length(service) {
            return Err(Nrc::INCORRECT_MESSAGE_LENGTH);
        }
        if sid::has_sub_function(service) && !self.offers(service, message[1] & 0x7F) {
            return Err(Nrc::SUB_FUNCTION_NOT_SUPPORTED);
        }
        let request = Request::decode(message).map_err(|_| Nrc::INCORRECT_MESSAGE_LENGTH)?;
        let suppressed = request.suppress_positive_response();
        let response = match request {
            Request::DiagnosticSessionControl { sub_function } => {
                let session = sub_function.value();
                self.enter_session(session);
                Response::DiagnosticSessionControl {
                    session,
                    timing: Some(TIMING),
                }
            }
            Request::EcuReset { sub_function } => {
                self.enter_session(DEFAULT_SESSION);
                Response::EcuReset {
                    reset_type: sub_function.value(),
                    power_down_time: None,
                }
            }
            Request::ClearDiagnosticInformation { group, .. } => {
                let before = self.dtcs.len();
                self.dtcs.retain(|d| group != 0xFF_FFFF && d.dtc != group);
                if group != 0xFF_FFFF && self.dtcs.len() == before {
                    return Err(Nrc::REQUEST_OUT_OF_RANGE);
                }
                Response::ClearDiagnosticInformation
            }
            Request::ReadDtcInformation { report, .. } => Response::ReadDtcInformation {
                report: self.dtc_report(&report)?,
            },
            Request::ReadDataByIdentifier { dids } => self.read_dids(&dids)?,
            Request::SecurityAccess { sub_function, data } => {
                self.security_access(sub_function.value(), &data)?
            }
            Request::CommunicationControl { sub_function, .. } => Response::CommunicationControl {
                control_type: sub_function.value(),
            },
            Request::WriteDataByIdentifier { did, data } => self.write_did(did, data)?,
            Request::RoutineControl {
                sub_function,
                routine,
                ..
            } => self.routine_control(sub_function.value(), routine)?,
            Request::TesterPresent { .. } => Response::TesterPresent { sub_function: 0 },
            Request::ControlDtcSetting { sub_function, .. } => Response::ControlDtcSetting {
                setting: sub_function.value(),
            },
            _ => return Err(Nrc::SERVICE_NOT_SUPPORTED),
        };
        Ok((response, suppressed))
    }

    fn offers(&self, service: u8, sub_function: u8) -> bool {
        match service {
            sid::DIAGNOSTIC_SESSION_CONTROL => self.sessions.contains(&sub_function),
            sid::ECU_RESET => matches!(sub_function, 0x01 | 0x03),
            sid::READ_DTC_INFORMATION => matches!(sub_function, 0x01 | 0x02 | 0x0A),
            sid::SECURITY_ACCESS => self.security.as_ref().is_some_and(|s| {
                sub_function == s.level || Some(sub_function) == s.level.checked_add(1)
            }),
            sid::COMMUNICATION_CONTROL => sub_function <= 0x03,
            sid::ROUTINE_CONTROL => matches!(sub_function, 0x01..=0x03),
            sid::TESTER_PRESENT => sub_function == 0,
            sid::CONTROL_DTC_SETTING => matches!(sub_function, 0x01 | 0x02),
            _ => true,
        }
    }

    fn enter_session(&mut self, session: u8) {
        self.session = session;
        self.unlocked = false;
        if let Some(security) = &mut self.security {
            security.seed_issued = false;
        }
    }

    fn visible(&self, did: u16) -> Option<&Did> {
        self.dids
            .get(&did)
            .filter(|d| d.sessions.is_empty() || d.sessions.contains(&self.session))
    }

    fn dtc_report(&self, report: &DtcRequest) -> Result<DtcResponse, Nrc> {
        let by_mask = |mask: u8| self.dtcs.iter().filter(move |d| d.status & mask != 0);
        Ok(match report {
            DtcRequest::NumberByStatusMask { status_mask } => DtcResponse::NumberByStatusMask {
                availability_mask: AVAILABILITY_MASK,
                format: ISO_14229_1_DTC_FORMAT,
                count: u16::try_from(by_mask(*status_mask).count()).unwrap_or(u16::MAX),
            },
            DtcRequest::ByStatusMask { status_mask } => DtcResponse::ByStatusMask {
                availability_mask: AVAILABILITY_MASK,
                dtcs: by_mask(*status_mask).copied().collect(),
            },
            DtcRequest::SupportedDtcs => DtcResponse::SupportedDtcs {
                availability_mask: AVAILABILITY_MASK,
                dtcs: self.dtcs.clone(),
            },
            _ => return Err(Nrc::SUB_FUNCTION_NOT_SUPPORTED),
        })
    }

    fn read_dids(&self, dids: &[u16]) -> Result<Response, Nrc> {
        let mut records = Vec::new();
        for &did in dids {
            let Some(entry) = self.visible(did) else {
                continue;
            };
            if entry.needs_security && !self.unlocked {
                return Err(Nrc::SECURITY_ACCESS_DENIED);
            }
            records.push((did, &entry.value));
        }
        let ((first, value), rest) = records.split_first().ok_or(Nrc::REQUEST_OUT_OF_RANGE)?;
        let mut data = value.to_vec();
        for (did, value) in rest {
            data.extend(did.to_be_bytes());
            data.extend(value.iter());
        }
        Ok(Response::ReadDataByIdentifier { did: *first, data })
    }

    fn write_did(&mut self, did: u16, data: Vec<u8>) -> Result<Response, Nrc> {
        let entry = self
            .visible(did)
            .filter(|d| d.writable)
            .ok_or(Nrc::REQUEST_OUT_OF_RANGE)?;
        if entry.needs_security && !self.unlocked {
            return Err(Nrc::SECURITY_ACCESS_DENIED);
        }
        if entry.value.len() != data.len() {
            return Err(Nrc::INCORRECT_MESSAGE_LENGTH);
        }
        if let Some(entry) = self.dids.get_mut(&did) {
            entry.value = data;
        }
        Ok(Response::WriteDataByIdentifier { did })
    }

    fn security_access(&mut self, sub_function: u8, key: &[u8]) -> Result<Response, Nrc> {
        let security = self
            .security
            .as_mut()
            .ok_or(Nrc::SUB_FUNCTION_NOT_SUPPORTED)?;
        let data = if sub_function == security.level {
            if self.unlocked {
                vec![0; security.seed.len()]
            } else {
                security.seed_issued = true;
                security.seed.clone()
            }
        } else if Some(sub_function) == security.level.checked_add(1) {
            if !std::mem::take(&mut security.seed_issued) {
                return Err(Nrc::REQUEST_SEQUENCE_ERROR);
            }
            if !(security.key_check)(&security.seed, key) {
                return Err(Nrc::INVALID_KEY);
            }
            self.unlocked = true;
            Vec::new()
        } else {
            return Err(Nrc::SUB_FUNCTION_NOT_SUPPORTED);
        };
        Ok(Response::SecurityAccess { sub_function, data })
    }

    fn routine_control(&mut self, sub_function: u8, id: u16) -> Result<Response, Nrc> {
        let routine = self
            .routine
            .as_mut()
            .filter(|r| r.id == id)
            .ok_or(Nrc::REQUEST_OUT_OF_RANGE)?;
        let data = match sub_function {
            0x01 => {
                routine.started = true;
                routine.running = true;
                Vec::new()
            }
            0x02 if routine.running => {
                routine.running = false;
                Vec::new()
            }
            0x03 if routine.started => routine.result.clone(),
            0x02 | 0x03 => return Err(Nrc::REQUEST_SEQUENCE_ERROR),
            _ => return Err(Nrc::SUB_FUNCTION_NOT_SUPPORTED),
        };
        Ok(Response::RoutineControl {
            sub_function,
            routine: id,
            data,
        })
    }
}

fn minimum_length(service: u8) -> usize {
    match service {
        sid::CLEAR_DIAGNOSTIC_INFORMATION
        | sid::WRITE_DATA_BY_IDENTIFIER
        | sid::ROUTINE_CONTROL => 4,
        sid::READ_DATA_BY_IDENTIFIER | sid::COMMUNICATION_CONTROL => 3,
        _ => 2,
    }
}

fn negative(service: u8, code: Nrc) -> Vec<u8> {
    Response::Negative { service, code }.encode()
}
