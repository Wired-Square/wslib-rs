use std::fmt;

use serde::{Deserialize, Serialize};

use crate::codec::{MemoryRange, Reader};
use crate::sid;

/// A request named from its leading bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(rename = "UdsIdentity"))]
#[serde(rename_all = "camelCase")]
pub struct Identity {
    pub service: u8,
    pub detail: Option<Detail>,
}

/// What a request addresses, when its leading bytes say.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(rename = "UdsDetail"))]
#[serde(tag = "kind", rename_all = "camelCase")]
#[serde(rename_all_fields = "camelCase")]
pub enum Detail {
    Session { session: u8 },
    Reset { reset_type: u8 },
    DtcGroup { group: u32 },
    DtcReport { report_type: u8 },
    Dids { dids: Vec<u16> },
    Memory { address: u64, size: u64 },
    SecurityAccess { sub_function: u8 },
    Communication { control_type: u8 },
    Routine { routine: u16, sub_function: u8 },
    Block { sequence: u8 },
    DtcSetting { setting: u8 },
}

/// Names a request from as many of its bytes as are at hand; `None` when empty.
pub fn identify(request: &[u8]) -> Option<Identity> {
    let (&service, rest) = request.split_first()?;
    let sub = rest.first().map(|b| b & 0x7F);
    let did = |b: &[u8]| u16::from_be_bytes([b[0], b[1]]);
    let detail = match service {
        sid::DIAGNOSTIC_SESSION_CONTROL => sub.map(|session| Detail::Session { session }),
        sid::ECU_RESET => sub.map(|reset_type| Detail::Reset { reset_type }),
        sid::CLEAR_DIAGNOSTIC_INFORMATION => rest.get(..3).map(|b| Detail::DtcGroup {
            group: u32::from_be_bytes([0, b[0], b[1], b[2]]),
        }),
        sid::READ_DTC_INFORMATION => sub.map(|report_type| Detail::DtcReport { report_type }),
        sid::READ_DATA_BY_IDENTIFIER => {
            let dids: Vec<u16> = rest.as_chunks::<2>().0.iter().map(|d| did(d)).collect();
            (!dids.is_empty()).then_some(Detail::Dids { dids })
        }
        sid::WRITE_DATA_BY_IDENTIFIER | sid::INPUT_OUTPUT_CONTROL_BY_IDENTIFIER => {
            rest.get(..2).map(|b| Detail::Dids { dids: vec![did(b)] })
        }
        sid::READ_MEMORY_BY_ADDRESS => memory(service, rest),
        sid::REQUEST_DOWNLOAD | sid::REQUEST_UPLOAD => {
            rest.get(1..).and_then(|range| memory(service, range))
        }
        sid::SECURITY_ACCESS => sub.map(|sub_function| Detail::SecurityAccess { sub_function }),
        sid::COMMUNICATION_CONTROL => {
            sub.map(|control_type| Detail::Communication { control_type })
        }
        sid::ROUTINE_CONTROL => rest.get(..3).map(|b| Detail::Routine {
            routine: did(&b[1..]),
            sub_function: b[0] & 0x7F,
        }),
        sid::TRANSFER_DATA => rest.first().map(|&sequence| Detail::Block { sequence }),
        sid::CONTROL_DTC_SETTING => sub.map(|setting| Detail::DtcSetting { setting }),
        _ => None,
    };
    Some(Identity { service, detail })
}

fn memory(service: u8, rest: &[u8]) -> Option<Detail> {
    let range = MemoryRange::read(&mut Reader { service, rest }).ok()?;
    Some(Detail::Memory {
        address: range.address(),
        size: range.size(),
    })
}

impl fmt::Display for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match sid::name(self.service) {
            Some(name) => f.write_str(name)?,
            None => write!(f, "service 0x{:02X}", self.service)?,
        }
        match &self.detail {
            Some(detail) => write!(f, " {detail}"),
            None => Ok(()),
        }
    }
}

impl fmt::Display for Detail {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Session { session } => write!(f, "session 0x{session:02X}"),
            Self::Reset { reset_type } => write!(f, "reset 0x{reset_type:02X}"),
            Self::DtcGroup { group } => write!(f, "group 0x{group:06X}"),
            Self::DtcReport { report_type } => write!(f, "report 0x{report_type:02X}"),
            Self::Dids { dids } => {
                f.write_str(if dids.len() == 1 { "DID" } else { "DIDs" })?;
                for (i, did) in dids.iter().enumerate() {
                    write!(f, "{} 0x{did:04X}", if i == 0 { "" } else { "," })?;
                }
                Ok(())
            }
            Self::Memory { address, size } => write!(f, "address 0x{address:X} size 0x{size:X}"),
            Self::SecurityAccess { sub_function } if sub_function % 2 == 1 => {
                write!(f, "seed 0x{sub_function:02X}")
            }
            Self::SecurityAccess { sub_function } => write!(f, "key 0x{sub_function:02X}"),
            Self::Communication { control_type } => write!(f, "control 0x{control_type:02X}"),
            Self::Routine {
                routine,
                sub_function,
            } => {
                write!(f, "routine 0x{routine:04X} ")?;
                match sub_function {
                    0x01 => f.write_str("start"),
                    0x02 => f.write_str("stop"),
                    0x03 => f.write_str("results"),
                    other => write!(f, "0x{other:02X}"),
                }
            }
            Self::Block { sequence } => write!(f, "block 0x{sequence:02X}"),
            Self::DtcSetting { setting } => write!(f, "setting 0x{setting:02X}"),
        }
    }
}
