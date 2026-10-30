//! Bridges: frames forwarded from one interface to another through filters.
//!
//! BRIDGE_ADD (0x70):
//!   `bridge_id(u16 LE) source_iface(u8) dest_iface(u8)
//!    interface_type(u8) enabled(u8) default_action(u8) num_filters(u8)
//!    [filters: type(u8) ide(u8) a(u32 LE) b(u32 LE)]...`
//!
//!   default_action:
//!     0 (Pass)  forward unmatched frames; filters list IDs to drop (denylist).
//!     1 (Block) drop unmatched frames; filters list IDs to forward (allowlist).
//!
//!   Per filter:
//!     type=0 (Mask):  `a` = `can_id`, `b` = `mask`
//!                      match if `(id & mask) == (can_id & mask)`
//!     type=1 (Range): `a` = `lo`,     `b` = `hi`
//!                      match if `lo <= id <= hi` (inclusive)
//!     ide=0 any, ide=1 std-only, ide=2 ext-only
//!     `a` and `b` carry CAN IDs only (≤ 29 bits); high bits are reserved.
//!
//! BRIDGE_REMOVE (0x71): `bridge_id(u16 LE)`
//! BRIDGE_LIST (0x72): empty payload
//! BRIDGE_ENABLE (0x74): `bridge_id(u16 LE) enabled(u8)`

use crate::{Error, types};
use serde::{Deserialize, Serialize};

/// A filter word carries a CAN id; bits above 29 are reserved.
pub const CAN_ID_MASK_29: u32 = 0x1FFF_FFFF;

const HDR_OFF_BRIDGE_ID: usize = 0; // u16 LE
const HDR_OFF_SOURCE_IFACE: usize = 2; // u8
const HDR_OFF_DEST_IFACE: usize = 3; // u8
const HDR_OFF_INTERFACE_TYPE: usize = 4; // u8
const HDR_OFF_ENABLED: usize = 5; // u8
const HDR_OFF_DEFAULT_ACTION: usize = 6; // u8
const HDR_OFF_NUM_FILTERS: usize = 7; // u8
const HDR_LEN: usize = 8;

const FILTER_OFF_TYPE: usize = 0; // u8
const FILTER_OFF_IDE: usize = 1; // u8
const FILTER_OFF_A: usize = 2; // u32 LE
const FILTER_OFF_B: usize = 6; // u32 LE
const FILTER_WIRE_LEN: usize = 10;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[repr(u8)]
pub enum BridgeFilterType {
    /// `(id & mask) == (can_id & mask)`
    Mask = 0,
    /// `lo <= id <= hi` inclusive
    Range = 1,
}

impl BridgeFilterType {
    fn from_u8(v: u8) -> Result<Self, Error> {
        match v {
            0 => Ok(Self::Mask),
            1 => Ok(Self::Range),
            _ => Err(Error::InvalidPayload("bridge filter type")),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Mask => "mask",
            Self::Range => "range",
        }
    }

    pub fn from_name(s: &str) -> Option<Self> {
        match s {
            "mask" => Some(Self::Mask),
            "range" => Some(Self::Range),
            _ => None,
        }
    }
}

/// Which frames a filter applies to, by their IDE flag.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[non_exhaustive]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[repr(u8)]
pub enum BridgeFilterIde {
    #[default]
    #[serde(rename = "any")]
    Any = 0,
    #[serde(rename = "std")]
    StdOnly = 1,
    #[serde(rename = "ext")]
    ExtOnly = 2,
}

impl BridgeFilterIde {
    fn from_u8(v: u8) -> Result<Self, Error> {
        match v {
            0 => Ok(Self::Any),
            1 => Ok(Self::StdOnly),
            2 => Ok(Self::ExtOnly),
            _ => Err(Error::InvalidPayload("bridge filter ide")),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Any => "any",
            Self::StdOnly => "std",
            Self::ExtOnly => "ext",
        }
    }

    pub fn from_name(s: &str) -> Option<Self> {
        match s {
            "any" => Some(Self::Any),
            "std" => Some(Self::StdOnly),
            "ext" => Some(Self::ExtOnly),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub struct BridgeFilter {
    pub kind: BridgeFilterType,
    pub ide: BridgeFilterIde,
    /// Mask: `can_id`. Range: inclusive `lo`.
    pub a: u32,
    /// Mask: `mask`. Range: inclusive `hi`.
    pub b: u32,
}

impl BridgeFilter {
    pub fn mask(can_id: u32, mask: u32) -> Self {
        Self {
            kind: BridgeFilterType::Mask,
            ide: BridgeFilterIde::Any,
            a: can_id,
            b: mask,
        }
    }

    pub fn range(lo: u32, hi: u32) -> Self {
        Self {
            kind: BridgeFilterType::Range,
            ide: BridgeFilterIde::Any,
            a: lo,
            b: hi,
        }
    }
}

/// What happens to a frame no filter matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[non_exhaustive]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(rename_all = "lowercase")]
#[repr(u8)]
pub enum BridgeDefaultAction {
    /// Forward it; the filters list what to drop.
    #[default]
    Pass = 0,
    /// Drop it; the filters list what to forward.
    Block = 1,
}

impl BridgeDefaultAction {
    fn from_u8(v: u8) -> Result<Self, Error> {
        match v {
            0 => Ok(Self::Pass),
            1 => Ok(Self::Block),
            _ => Err(Error::InvalidPayload("bridge default action")),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Block => "block",
        }
    }

    pub fn from_name(s: &str) -> Option<Self> {
        match s {
            "pass" => Some(Self::Pass),
            "block" => Some(Self::Block),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub struct BridgeInfo {
    pub bridge_id: u16,
    pub source_interface: u8,
    pub dest_interface: u8,
    #[serde(serialize_with = "types::ser_interface_name")]
    #[cfg_attr(feature = "ts", ts(type = "string"))]
    pub interface_type: u8,
    pub enabled: bool,
    pub default_action: BridgeDefaultAction,
    pub filters: Vec<BridgeFilter>,
}

pub fn build_bridge_add(info: &BridgeInfo) -> Vec<u8> {
    let mut buf = Vec::with_capacity(HDR_LEN + info.filters.len() * FILTER_WIRE_LEN);
    buf.extend_from_slice(&info.bridge_id.to_le_bytes());
    buf.push(info.source_interface);
    buf.push(info.dest_interface);
    buf.push(info.interface_type);
    buf.push(u8::from(info.enabled));
    buf.push(info.default_action as u8);
    buf.push(info.filters.len() as u8);
    debug_assert_eq!(buf.len(), HDR_LEN);
    for f in &info.filters {
        buf.push(f.kind as u8);
        buf.push(f.ide as u8);
        buf.extend_from_slice(&f.a.to_le_bytes());
        buf.extend_from_slice(&f.b.to_le_bytes());
    }
    buf
}

pub fn build_bridge_remove(bridge_id: u16) -> Vec<u8> {
    bridge_id.to_le_bytes().to_vec()
}

pub fn build_bridge_list() -> Vec<u8> {
    Vec::new()
}

pub fn build_bridge_enable(bridge_id: u16, enabled: bool) -> Vec<u8> {
    crate::build_enable(bridge_id, enabled)
}

pub fn parse_bridge_resp(payload: &[u8]) -> Result<BridgeInfo, Error> {
    if payload.len() < HDR_LEN {
        return Err(Error::InvalidPayload("bridge resp too short"));
    }

    let bridge_id =
        u16::from_le_bytes([payload[HDR_OFF_BRIDGE_ID], payload[HDR_OFF_BRIDGE_ID + 1]]);
    let source_interface = payload[HDR_OFF_SOURCE_IFACE];
    let dest_interface = payload[HDR_OFF_DEST_IFACE];
    let interface_type = payload[HDR_OFF_INTERFACE_TYPE];
    let enabled = payload[HDR_OFF_ENABLED] != 0;
    let default_action = BridgeDefaultAction::from_u8(payload[HDR_OFF_DEFAULT_ACTION])?;
    let num_filters = payload[HDR_OFF_NUM_FILTERS] as usize;

    if payload.len() < HDR_LEN + num_filters * FILTER_WIRE_LEN {
        return Err(Error::InvalidPayload("bridge resp truncated"));
    }

    let mut filters = Vec::with_capacity(num_filters);
    for i in 0..num_filters {
        let entry = &payload[HDR_LEN + i * FILTER_WIRE_LEN..];
        let kind = BridgeFilterType::from_u8(entry[FILTER_OFF_TYPE])?;
        let ide = BridgeFilterIde::from_u8(entry[FILTER_OFF_IDE])?;
        let a = u32::from_le_bytes(entry[FILTER_OFF_A..FILTER_OFF_A + 4].try_into().unwrap());
        let b = u32::from_le_bytes(entry[FILTER_OFF_B..FILTER_OFF_B + 4].try_into().unwrap());
        filters.push(BridgeFilter { kind, ide, a, b });
    }

    Ok(BridgeInfo {
        bridge_id,
        source_interface,
        dest_interface,
        interface_type,
        enabled,
        default_action,
        filters,
    })
}

pub fn next_available_id(existing: &[BridgeInfo]) -> u16 {
    crate::next_free_id(existing.iter().map(|b| b.bridge_id))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn next_available_id_empty() {
        assert_eq!(next_available_id(&[]), 0);
    }

    #[test]
    fn build_bridge_add_no_filters() {
        let info = BridgeInfo {
            bridge_id: 1,
            source_interface: 0,
            dest_interface: 1,
            interface_type: 0x01,
            enabled: true,
            default_action: BridgeDefaultAction::Pass,
            filters: vec![],
        };
        let payload = build_bridge_add(&info);
        assert_eq!(payload.len(), HDR_LEN);
        assert_eq!(
            u16::from_le_bytes([payload[HDR_OFF_BRIDGE_ID], payload[HDR_OFF_BRIDGE_ID + 1],]),
            1,
        );
        assert_eq!(payload[HDR_OFF_SOURCE_IFACE], 0);
        assert_eq!(payload[HDR_OFF_DEST_IFACE], 1);
        assert_eq!(payload[HDR_OFF_INTERFACE_TYPE], 0x01);
        assert_eq!(payload[HDR_OFF_ENABLED], 1);
        assert_eq!(
            payload[HDR_OFF_DEFAULT_ACTION],
            BridgeDefaultAction::Pass as u8
        );
        assert_eq!(payload[HDR_OFF_NUM_FILTERS], 0);
    }

    #[test]
    fn build_bridge_add_with_filters() {
        let info = BridgeInfo {
            bridge_id: 0x0100,
            source_interface: 0,
            dest_interface: 2,
            interface_type: 0x01,
            enabled: false,
            default_action: BridgeDefaultAction::Block,
            filters: vec![
                BridgeFilter::mask(0x100, 0x7FF),
                BridgeFilter::range(0x11E, 0x300),
            ],
        };
        let payload = build_bridge_add(&info);
        assert_eq!(payload.len(), HDR_LEN + 2 * FILTER_WIRE_LEN);
        assert_eq!(
            payload[HDR_OFF_DEFAULT_ACTION],
            BridgeDefaultAction::Block as u8,
        );
        assert_eq!(payload[HDR_OFF_NUM_FILTERS], 2);

        let read_u32 = |entry: &[u8], off: usize| -> u32 {
            u32::from_le_bytes(entry[off..off + 4].try_into().unwrap())
        };

        // Filter 0: mask, any, a=0x100, b=0x7FF
        let f0 = &payload[HDR_LEN..HDR_LEN + FILTER_WIRE_LEN];
        assert_eq!(f0[FILTER_OFF_TYPE], BridgeFilterType::Mask as u8);
        assert_eq!(f0[FILTER_OFF_IDE], BridgeFilterIde::Any as u8);
        assert_eq!(read_u32(f0, FILTER_OFF_A), 0x100);
        assert_eq!(read_u32(f0, FILTER_OFF_B), 0x7FF);

        // Filter 1: range, any, lo=0x11E, hi=0x300
        let f1 = &payload[HDR_LEN + FILTER_WIRE_LEN..HDR_LEN + 2 * FILTER_WIRE_LEN];
        assert_eq!(f1[FILTER_OFF_TYPE], BridgeFilterType::Range as u8);
        assert_eq!(f1[FILTER_OFF_IDE], BridgeFilterIde::Any as u8);
        assert_eq!(read_u32(f1, FILTER_OFF_A), 0x11E);
        assert_eq!(read_u32(f1, FILTER_OFF_B), 0x300);
    }

    #[test]
    fn bridge_remove_payload() {
        let payload = build_bridge_remove(42);
        assert_eq!(payload, 42u16.to_le_bytes().to_vec());
    }

    #[test]
    fn bridge_enable_payload() {
        let payload = build_bridge_enable(7, true);
        assert_eq!(payload.len(), 3);
        assert_eq!(u16::from_le_bytes([payload[0], payload[1]]), 7);
        assert_eq!(payload[2], 1);

        let payload = build_bridge_enable(7, false);
        assert_eq!(payload[2], 0);
    }

    #[test]
    fn parse_bridge_resp_roundtrip() {
        let info = BridgeInfo {
            bridge_id: 5,
            source_interface: 0,
            dest_interface: 1,
            interface_type: 0x01,
            enabled: true,
            default_action: BridgeDefaultAction::Block,
            filters: vec![
                BridgeFilter {
                    kind: BridgeFilterType::Mask,
                    ide: BridgeFilterIde::ExtOnly,
                    a: 0x18FF00FE,
                    b: 0x1FFFFFFF,
                },
                BridgeFilter {
                    kind: BridgeFilterType::Range,
                    ide: BridgeFilterIde::StdOnly,
                    a: 0x11E,
                    b: 0x300,
                },
            ],
        };
        let payload = build_bridge_add(&info);
        let parsed = parse_bridge_resp(&payload).unwrap();
        assert_eq!(parsed.bridge_id, 5);
        assert_eq!(parsed.source_interface, 0);
        assert_eq!(parsed.dest_interface, 1);
        assert_eq!(parsed.interface_type, 0x01);
        assert!(parsed.enabled);
        assert_eq!(parsed.default_action, BridgeDefaultAction::Block);
        assert_eq!(parsed.filters.len(), 2);
        assert_eq!(parsed.filters[0].kind, BridgeFilterType::Mask);
        assert_eq!(parsed.filters[0].ide, BridgeFilterIde::ExtOnly);
        assert_eq!(parsed.filters[0].a, 0x18FF00FE);
        assert_eq!(parsed.filters[0].b, 0x1FFFFFFF);
        assert_eq!(parsed.filters[1].kind, BridgeFilterType::Range);
        assert_eq!(parsed.filters[1].ide, BridgeFilterIde::StdOnly);
        assert_eq!(parsed.filters[1].a, 0x11E);
        assert_eq!(parsed.filters[1].b, 0x300);
    }

    #[test]
    fn parse_bridge_resp_too_short() {
        let buf = vec![0u8; HDR_LEN - 1];
        assert!(parse_bridge_resp(&buf).is_err());
    }

    /// Build a minimal valid header with the supplied default_action and
    /// num_filters fields. Other header bytes are arbitrary but valid.
    fn make_header(default_action: u8, num_filters: u8) -> Vec<u8> {
        let mut buf = vec![0u8; HDR_LEN];
        buf[HDR_OFF_BRIDGE_ID] = 0x01; // little-endian low byte
        buf[HDR_OFF_INTERFACE_TYPE] = 0x01;
        buf[HDR_OFF_ENABLED] = 1;
        buf[HDR_OFF_DEFAULT_ACTION] = default_action;
        buf[HDR_OFF_NUM_FILTERS] = num_filters;
        buf
    }

    #[test]
    fn parse_bridge_resp_truncated_filters() {
        let mut payload = make_header(BridgeDefaultAction::Pass as u8, 2);
        payload.extend_from_slice(&[0; FILTER_WIRE_LEN]); // claims 2, supplies 1
        assert!(parse_bridge_resp(&payload).is_err());
    }

    /// Append one filter entry with the supplied type/ide bytes.
    fn append_filter_entry(buf: &mut Vec<u8>, type_byte: u8, ide_byte: u8) {
        buf.push(type_byte);
        buf.push(ide_byte);
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes());
    }

    #[test]
    fn parse_rejects_invalid_type_or_ide() {
        const INVALID_TYPE: u8 = 2;
        const INVALID_IDE: u8 = 3;

        let mut payload = make_header(BridgeDefaultAction::Pass as u8, 1);
        append_filter_entry(&mut payload, INVALID_TYPE, BridgeFilterIde::Any as u8);
        assert!(parse_bridge_resp(&payload).is_err());

        let mut payload = make_header(BridgeDefaultAction::Pass as u8, 1);
        append_filter_entry(&mut payload, BridgeFilterType::Mask as u8, INVALID_IDE);
        assert!(parse_bridge_resp(&payload).is_err());
    }

    #[test]
    fn parse_rejects_invalid_default_action() {
        const INVALID_DEFAULT_ACTION: u8 = 2;
        let payload = make_header(INVALID_DEFAULT_ACTION, 0);
        assert!(parse_bridge_resp(&payload).is_err());
    }

    #[test]
    fn serialise_bridge_info_uses_names_and_numbers() {
        let info = BridgeInfo {
            bridge_id: 5,
            source_interface: 0,
            dest_interface: 1,
            interface_type: 0x01,
            enabled: true,
            default_action: BridgeDefaultAction::Block,
            filters: vec![BridgeFilter::mask(0x100, 0x7FF)],
        };
        let v = serde_json::to_value(&info).unwrap();
        assert_eq!(v["interface_type"], "CAN");
        assert_eq!(v["default_action"], "block");
        assert!(v["bridge_id"].is_number());
        assert!(v["source_interface"].is_number());
        assert_eq!(v["filters"][0]["kind"], "mask");
        assert_eq!(v["filters"][0]["ide"], "any");
        assert_eq!(v["filters"][0]["a"], 0x100);
        assert!(v["filters"][0]["b"].is_number());
    }
}
