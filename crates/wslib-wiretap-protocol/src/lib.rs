//! The vocabulary captures share: protocols, frame identities, selections and
//! inventory rows.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

mod selection;

pub use selection::{FrameSelection, InventoryRow, PayloadQuery, ProtocolFrames, Sampling};

/// The `protocol` a stored Modbus RTU row carries; its frame id is
/// `unit << 8 | function`, its payload the whole message.
pub const MODBUS_RTU_PROTOCOL: &str = "modbus_rtu";

/// A protocol as an archive stores it. Its serde spelling is the query one
/// (`modbus`); its stored tag, [`as_str`](Self::as_str) and `Display`, is `modbus_rtu`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(rename = "ArchiveProtocol"))]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Can,
    #[serde(rename = "modbus", alias = "modbus_rtu")]
    ModbusRtu,
    Serial,
}

impl Protocol {
    pub const ALL: [Self; 3] = [Self::Can, Self::ModbusRtu, Self::Serial];

    /// The stored tag.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Can => "can",
            Self::ModbusRtu => MODBUS_RTU_PROTOCOL,
            Self::Serial => "serial",
        }
    }
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Reads the stored names, and `modbus`, which rows written before Modbus RTU
/// was named carry.
impl FromStr for Protocol {
    type Err = UnknownProtocol;

    fn from_str(name: &str) -> Result<Self, Self::Err> {
        match name {
            "modbus" => Ok(Self::ModbusRtu),
            _ => Self::ALL
                .into_iter()
                .find(|p| p.as_str() == name)
                .ok_or_else(|| UnknownProtocol(name.into())),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownProtocol(pub String);

impl fmt::Display for UnknownProtocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unknown protocol '{}'", self.0)
    }
}

impl std::error::Error for UnknownProtocol {}

/// Which frame a payload belongs to: a standard and an extended id sharing a
/// number are different frames.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(rename_all = "camelCase")]
pub struct FrameKey {
    pub frame_id: u32,
    pub is_extended: bool,
}

impl FrameKey {
    pub fn new(frame_id: u32, is_extended: bool) -> Self {
        Self {
            frame_id,
            is_extended,
        }
    }
}

/// `0x` and upper-case hex, padded to 3 digits for a standard id and 8 for an
/// extended one.
pub fn format_frame_id(id: u32, extended: bool) -> String {
    let width = if extended { 8 } else { 3 };
    format!("0x{id:0width$X}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_frame_id_is_padded_to_its_kind_s_width_and_never_cut() {
        assert_eq!(format_frame_id(0x7B, false), "0x07B");
        assert_eq!(format_frame_id(0x7B, true), "0x0000007B");
        assert_eq!(format_frame_id(0x18FF50E5, true), "0x18FF50E5");
        assert_eq!(format_frame_id(0x1234, false), "0x1234");
    }

    #[test]
    fn a_protocol_parses_its_stored_tag_and_displays_it() {
        for p in Protocol::ALL {
            assert_eq!(p.as_str().parse(), Ok(p));
            assert_eq!(p.to_string(), p.as_str());
        }
        assert_eq!(Protocol::ModbusRtu.to_string(), "modbus_rtu");
    }

    #[test]
    fn modbus_rtu_is_modbus_in_serde_and_modbus_rtu_when_stored() {
        let spelt: Vec<_> = Protocol::ALL
            .into_iter()
            .map(|p| serde_json::to_value(p).unwrap())
            .collect();
        assert_eq!(spelt, ["can", "modbus", "serial"]);
        for name in [r#""modbus""#, r#""modbus_rtu""#] {
            assert_eq!(
                serde_json::from_str::<Protocol>(name).unwrap(),
                Protocol::ModbusRtu
            );
        }
        assert_eq!(Protocol::ModbusRtu.as_str(), MODBUS_RTU_PROTOCOL);
        assert_eq!("modbus".parse(), Ok(Protocol::ModbusRtu));
    }

    #[test]
    fn an_unknown_name_is_refused() {
        assert_eq!(
            "canfd".parse::<Protocol>(),
            Err(UnknownProtocol("canfd".into()))
        );
        assert!(serde_json::from_str::<Protocol>(r#""Can""#).is_err());
    }

    #[test]
    fn a_frame_key_is_camel_case() {
        assert_eq!(
            serde_json::to_value(FrameKey::new(0x100, true)).unwrap(),
            serde_json::json!({ "frameId": 256, "isExtended": true })
        );
    }
}
