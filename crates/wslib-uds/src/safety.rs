use serde::{Deserialize, Serialize};

use crate::{PROGRAMMING_SESSION, Request, sid};

/// What sending a request may do to the ECU, least to most; see the crate
/// docs for the table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(rename = "UdsSafety"))]
#[serde(rename_all = "camelCase")]
pub enum Safety {
    ReadOnly,
    StateChanging,
    Destructive,
}

impl Safety {
    /// The class of a whole request message; a bare service id has its
    /// service's class with the sub-function unknown.
    pub fn of(request: &[u8]) -> Self {
        let Some((&service, rest)) = request.split_first() else {
            return Self::Destructive;
        };
        match (service, rest.first().map(|b| b & 0x7F)) {
            (sid::READ_DTC_INFORMATION | sid::READ_DATA_BY_IDENTIFIER | sid::TESTER_PRESENT, _) => {
                Self::ReadOnly
            }
            (sid::ROUTINE_CONTROL, Some(REQUEST_ROUTINE_RESULTS)) => Self::ReadOnly,
            (sid::DIAGNOSTIC_SESSION_CONTROL, Some(PROGRAMMING_SESSION) | None) => {
                Self::Destructive
            }
            (
                sid::DIAGNOSTIC_SESSION_CONTROL
                | sid::ECU_RESET
                | sid::READ_MEMORY_BY_ADDRESS
                | sid::SECURITY_ACCESS
                | sid::COMMUNICATION_CONTROL
                | sid::CONTROL_DTC_SETTING,
                _,
            ) => Self::StateChanging,
            _ => Self::Destructive,
        }
    }
}

const REQUEST_ROUTINE_RESULTS: u8 = 0x03;

/// A request whose class is [`Safety::ReadOnly`], the only kind a client
/// sends without the `write` feature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadOnly(Request);

impl ReadOnly {
    pub fn new(request: Request) -> Result<Self, NotReadOnly> {
        match request.safety() {
            Safety::ReadOnly => Ok(Self(request)),
            safety => Err(NotReadOnly { request, safety }),
        }
    }

    pub fn request(&self) -> &Request {
        &self.0
    }

    pub fn into_request(self) -> Request {
        self.0
    }
}

impl TryFrom<Request> for ReadOnly {
    type Error = NotReadOnly;

    fn try_from(request: Request) -> Result<Self, NotReadOnly> {
        Self::new(request)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("a {safety:?} request is not read-only")]
pub struct NotReadOnly {
    pub request: Request,
    pub safety: Safety,
}
