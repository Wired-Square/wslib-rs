//! Capabilities: a device's interfaces, peripherals and static metadata. A
//! target's signals come from DSIG_LIST, keyed by `(target_type,
//! target_index)`; declaring a signal declares the capability.
//!
//! ```text
//! num_device_meta (u8) | [id(u8) quantity(u8) len(u8) value(1-4 LE int, raw bytes otherwise)]...
//! num_interfaces  (u8) | [index(u8) type(u8) num_meta(u8) meta...]...
//! num_peripherals (u8) | [index(u8) kind(u8) num_meta(u8) meta...]...
//! ```

use std::fmt;

use serde::ser::SerializeStruct;
use serde::{Serialize, Serializer};

use crate::{Error, types, xform};

/// An integer when 1, 2 or 4 bytes long and not a string; bytes otherwise.
#[derive(Debug, Clone)]
#[non_exhaustive]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(type = "number | string"))]
pub enum MetaValue {
    Integer(u32),
    Bytes(Vec<u8>),
}

impl Serialize for MetaValue {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            MetaValue::Integer(v) => serializer.serialize_u32(*v),
            MetaValue::Bytes(b) => serializer.serialize_str(&bytes_repr(b)),
        }
    }
}

/// One static-metadata entry. It serialises as its name and value, the
/// supported functions as their names.
#[derive(Debug, Clone)]
#[cfg_attr(
    feature = "ts",
    derive(ts_rs::TS),
    ts(type = "{ name: string, value: number | string | Array<string> }")
)]
pub struct Meta {
    /// A `types::META_*`.
    pub id: u8,
    /// A `types::QTY_*`, typing the value.
    pub quantity: u8,
    pub value: MetaValue,
}

impl Serialize for Meta {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut st = serializer.serialize_struct("Meta", 2)?;
        st.serialize_field("name", types::meta_name(self.id))?;
        match supported_function_names(self) {
            Some(names) => st.serialize_field("value", &names)?,
            None => st.serialize_field("value", &self.value)?,
        }
        st.end()
    }
}

fn hex_string(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}

/// The text when it is UTF-8 without control characters, else lowercase hex;
/// JSON and `Display` both use it.
fn bytes_repr(bytes: &[u8]) -> String {
    match std::str::from_utf8(bytes) {
        Ok(s) if !s.chars().any(|c| c.is_control()) => s.to_string(),
        _ => hex_string(bytes),
    }
}

/// The function names of a `SUPPORTED_FUNCTIONS` entry.
fn supported_function_names(meta: &Meta) -> Option<Vec<&'static str>> {
    match &meta.value {
        MetaValue::Bytes(bytes) if meta.id == types::META_SUPPORTED_FUNCTIONS => {
            Some(bytes.iter().map(|b| xform::function_name(*b)).collect())
        }
        _ => None,
    }
}

fn meta_value_display(meta: &Meta) -> String {
    match supported_function_names(meta) {
        Some(names) => names.join(", "),
        None => meta.value.to_string(),
    }
}

impl Meta {
    /// 0 for a byte-array entry.
    pub fn as_u32(&self) -> u32 {
        match &self.value {
            MetaValue::Integer(v) => *v,
            MetaValue::Bytes(_) => 0,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match &self.value {
            MetaValue::Bytes(b) => std::str::from_utf8(b).ok(),
            MetaValue::Integer(_) => None,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub struct Interface {
    pub index: u8,
    #[serde(rename = "type", serialize_with = "types::ser_interface_name")]
    #[cfg_attr(feature = "ts", ts(type = "string"))]
    pub iface_type: u8,
    pub meta: Vec<Meta>,
}

#[derive(Debug, Clone, Serialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub struct Peripheral {
    pub index: u8,
    #[serde(serialize_with = "types::ser_peripheral_kind_name")]
    #[cfg_attr(feature = "ts", ts(type = "string"))]
    pub kind: u8,
    pub meta: Vec<Meta>,
}

#[derive(Debug, Clone, Serialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub struct Capabilities {
    pub device_meta: Vec<Meta>,
    pub interfaces: Vec<Interface>,
    pub peripherals: Vec<Peripheral>,
}

impl Capabilities {
    fn device_meta_entry(&self, id: u8) -> Option<&Meta> {
        self.device_meta.iter().find(|m| m.id == id)
    }

    pub fn board_name(&self) -> Option<&str> {
        self.device_meta_entry(types::META_BOARD_NAME)
            .and_then(|m| m.as_str())
    }

    pub fn board_revision(&self) -> Option<&str> {
        self.device_meta_entry(types::META_BOARD_REVISION)
            .and_then(|m| m.as_str())
    }

    /// The device's unique id, such as `"WiredFlexLink-9D04"`.
    pub fn device_id(&self) -> Option<&str> {
        self.device_meta_entry(types::META_DEVICE_ID)
            .and_then(|m| m.as_str())
    }

    pub fn tx_queue_depth(&self) -> Option<u16> {
        self.device_meta_entry(types::META_TX_QUEUE_DEPTH)
            .map(|m| m.as_u32() as u16)
    }

    /// `None`: the device has no file transfer, not an unlimited chunk.
    pub fn max_file_chunk(&self) -> Option<u32> {
        self.device_meta_entry(types::META_MAX_FILE_CHUNK)
            .map(|m| m.as_u32())
    }

    pub fn iface_type(&self, iface_index: u8) -> Option<u8> {
        self.interfaces
            .iter()
            .find(|i| i.index == iface_index)
            .map(|i| i.iface_type)
    }

    pub fn iface_can_max_dlc(&self, iface_index: u8) -> Option<u8> {
        self.interfaces
            .iter()
            .find(|i| i.index == iface_index)
            .and_then(|i| i.meta.iter().find(|m| m.id == types::META_CAN_MAX_DLC))
            .map(|m| m.as_u32() as u8)
    }
}

pub fn decode_capabilities(payload: &[u8]) -> Result<Capabilities, Error> {
    let mut pos = 0;
    let device_meta = decode_metas(payload, &mut pos, "truncated: missing device meta count")?;
    let interfaces = decode_targets(
        payload,
        &mut pos,
        "truncated: missing interface count",
        "truncated: interface header",
    )?
    .into_iter()
    .map(|(index, iface_type, meta)| Interface {
        index,
        iface_type,
        meta,
    })
    .collect();
    let peripherals = decode_targets(
        payload,
        &mut pos,
        "truncated: missing peripheral count",
        "truncated: peripheral header",
    )?
    .into_iter()
    .map(|(index, kind, meta)| Peripheral { index, kind, meta })
    .collect();
    Ok(Capabilities {
        device_meta,
        interfaces,
        peripherals,
    })
}

fn decode_metas(
    payload: &[u8],
    pos: &mut usize,
    missing_count: &'static str,
) -> Result<Vec<Meta>, Error> {
    let count = *payload
        .get(*pos)
        .ok_or(Error::InvalidPayload(missing_count))?;
    *pos += 1;
    (0..count)
        .map(|_| {
            let (meta, consumed) = decode_meta(&payload[*pos..])?;
            *pos += consumed;
            Ok(meta)
        })
        .collect()
}

/// Each target's index, type or kind, and metadata.
fn decode_targets(
    payload: &[u8],
    pos: &mut usize,
    missing_count: &'static str,
    truncated: &'static str,
) -> Result<Vec<(u8, u8, Vec<Meta>)>, Error> {
    let count = *payload
        .get(*pos)
        .ok_or(Error::InvalidPayload(missing_count))?;
    *pos += 1;
    (0..count)
        .map(|_| {
            let header = payload
                .get(*pos..*pos + 2)
                .ok_or(Error::InvalidPayload(truncated))?;
            let (index, kind) = (header[0], header[1]);
            *pos += 2;
            let meta = decode_metas(payload, pos, truncated)?;
            Ok((index, kind, meta))
        })
        .collect()
}

/// One entry and the bytes it took.
fn decode_meta(data: &[u8]) -> Result<(Meta, usize), Error> {
    const META_TLV_HDR_SIZE: usize = 3;

    if data.len() < META_TLV_HDR_SIZE {
        return Err(Error::InvalidPayload("truncated: meta header"));
    }

    let id = data[0];
    let quantity = data[1];
    let len = data[2] as usize;

    if data.len() < META_TLV_HDR_SIZE + len {
        return Err(Error::InvalidPayload("truncated: meta value"));
    }

    let raw = &data[META_TLV_HDR_SIZE..META_TLV_HDR_SIZE + len];
    let is_array = quantity & types::QTY_BASE_MASK == types::QTY_STRING
        || id == types::META_SUPPORTED_FUNCTIONS;

    let value = if is_array {
        MetaValue::Bytes(raw.to_vec())
    } else {
        match len {
            1 => MetaValue::Integer(raw[0] as u32),
            2 => MetaValue::Integer(u16::from_le_bytes([raw[0], raw[1]]) as u32),
            4 => MetaValue::Integer(u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]])),
            _ => MetaValue::Bytes(raw.to_vec()),
        }
    };

    Ok((
        Meta {
            id,
            quantity,
            value,
        },
        META_TLV_HDR_SIZE + len,
    ))
}

impl fmt::Display for MetaValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MetaValue::Integer(v) => write!(f, "{v}"),
            MetaValue::Bytes(b) => write!(f, "{}", bytes_repr(b)),
        }
    }
}

impl fmt::Display for Capabilities {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Device Metadata:")?;
        for meta in &self.device_meta {
            writeln!(
                f,
                "  {:<24} {}",
                types::meta_name(meta.id),
                meta_value_display(meta)
            )?;
        }

        writeln!(f, "\nInterfaces ({}):", self.interfaces.len())?;
        for (i, iface) in self.interfaces.iter().enumerate() {
            writeln!(
                f,
                "  {}. {} [index {}]",
                i + 1,
                types::interface_name(iface.iface_type),
                iface.index
            )?;
            for meta in &iface.meta {
                writeln!(
                    f,
                    "     {:<24} {}",
                    types::meta_name(meta.id),
                    meta_value_display(meta)
                )?;
            }
        }

        writeln!(f, "\nPeripherals ({}):", self.peripherals.len())?;
        for (i, periph) in self.peripherals.iter().enumerate() {
            writeln!(
                f,
                "  {}. {} [index {}]",
                i + 1,
                types::peripheral_kind_name(periph.kind),
                periph.index
            )?;
            for meta in &periph.meta {
                writeln!(
                    f,
                    "     {:<24} {}",
                    types::meta_name(meta.id),
                    meta_value_display(meta)
                )?;
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn push_meta_int(buf: &mut Vec<u8>, id: u8, quantity: u8, len: u8, value: u32) {
        buf.extend_from_slice(&[id, quantity, len]);
        match len {
            1 => buf.push(value as u8),
            2 => buf.extend_from_slice(&(value as u16).to_le_bytes()),
            4 => buf.extend_from_slice(&value.to_le_bytes()),
            _ => panic!("integer meta len must be 1/2/4"),
        }
    }

    fn push_meta_bytes(buf: &mut Vec<u8>, id: u8, quantity: u8, value: &[u8]) {
        buf.extend_from_slice(&[id, quantity, value.len() as u8]);
        buf.extend_from_slice(value);
    }

    fn build_test_payload() -> Vec<u8> {
        let mut buf = Vec::new();

        // 2 device meta entries
        buf.push(2);
        push_meta_int(
            &mut buf,
            types::META_MAX_FRAME_DEFS,
            types::QTY_COUNT,
            2,
            16,
        );
        push_meta_int(
            &mut buf,
            types::META_MAX_SIGNAL_STORE,
            types::QTY_COUNT,
            2,
            128,
        );

        // 1 interface: CAN at index 0 with a CAN_MAX_DLC entry
        buf.push(1);
        buf.extend_from_slice(&[0, types::IFACE_CAN, 1]);
        push_meta_int(&mut buf, types::META_CAN_MAX_DLC, types::QTY_COUNT, 1, 8);

        // 1 peripheral: actuator at index 0, no metadata
        buf.push(1);
        buf.extend_from_slice(&[0, types::PERIPH_KIND_ACTUATOR, 0]);

        buf
    }

    #[test]
    fn decode_test_payload() {
        let payload = build_test_payload();
        let caps = decode_capabilities(&payload).unwrap();

        assert_eq!(caps.device_meta.len(), 2);
        assert_eq!(caps.device_meta[0].id, types::META_MAX_FRAME_DEFS);
        assert_eq!(caps.device_meta[0].quantity, types::QTY_COUNT);
        assert_eq!(caps.device_meta[0].as_u32(), 16);
        assert_eq!(caps.device_meta[1].id, types::META_MAX_SIGNAL_STORE);
        assert_eq!(caps.device_meta[1].as_u32(), 128);

        assert_eq!(caps.interfaces.len(), 1);
        assert_eq!(caps.interfaces[0].index, 0);
        assert_eq!(caps.interfaces[0].iface_type, types::IFACE_CAN);
        assert_eq!(caps.interfaces[0].meta[0].id, types::META_CAN_MAX_DLC);
        assert_eq!(caps.iface_can_max_dlc(0), Some(8));

        assert_eq!(caps.peripherals.len(), 1);
        assert_eq!(caps.peripherals[0].index, 0);
        assert_eq!(caps.peripherals[0].kind, types::PERIPH_KIND_ACTUATOR);
        assert!(caps.peripherals[0].meta.is_empty());
    }

    #[test]
    fn display_capabilities() {
        let payload = build_test_payload();
        let caps = decode_capabilities(&payload).unwrap();
        let output = caps.to_string();
        assert!(output.contains("Max Frame Defs"));
        assert!(output.contains("CAN"));
        assert!(output.contains("Actuator"));
    }

    #[test]
    fn decode_string_metadata() {
        let mut buf = Vec::new();

        // 2 device meta entries: board name + board revision (STRING-typed)
        buf.push(2);
        push_meta_bytes(
            &mut buf,
            types::META_BOARD_NAME,
            types::QTY_STRING,
            b"wiredflexlink",
        );
        push_meta_bytes(
            &mut buf,
            types::META_BOARD_REVISION,
            types::QTY_STRING,
            b"esp32c6-v1.0",
        );

        // 0 interfaces, 0 peripherals
        buf.push(0);
        buf.push(0);

        let caps = decode_capabilities(&buf).unwrap();
        assert_eq!(caps.board_name(), Some("wiredflexlink"));
        assert_eq!(caps.board_revision(), Some("esp32c6-v1.0"));
    }

    #[test]
    fn short_string_metadata_stays_bytes() {
        // A 4-byte STRING value must not decode as an integer.
        let mut buf = Vec::new();
        buf.push(1);
        push_meta_bytes(&mut buf, types::META_DEVICE_ID, types::QTY_STRING, b"9D04");
        buf.push(0);
        buf.push(0);

        let caps = decode_capabilities(&buf).unwrap();
        assert_eq!(caps.device_id(), Some("9D04"));
    }

    #[test]
    fn decode_supported_functions_as_bytes() {
        let mut buf = Vec::new();

        // 1 device meta entry: SUPPORTED_FUNCTIONS = [0x10, 0x11, 0x12, 0x13]
        buf.push(1);
        push_meta_bytes(
            &mut buf,
            types::META_SUPPORTED_FUNCTIONS,
            types::QTY_RAW,
            &[0x10, 0x11, 0x12, 0x13],
        );

        // 0 interfaces, 0 peripherals
        buf.push(0);
        buf.push(0);

        let caps = decode_capabilities(&buf).unwrap();
        assert_eq!(caps.device_meta.len(), 1);
        match &caps.device_meta[0].value {
            MetaValue::Bytes(b) => assert_eq!(b, &[0x10, 0x11, 0x12, 0x13]),
            MetaValue::Integer(v) => panic!("expected Bytes, got Integer({v})"),
        }
    }

    #[test]
    fn serialise_capabilities_uses_names_and_numbers() {
        let caps = decode_capabilities(&build_test_payload()).unwrap();
        let v = serde_json::to_value(&caps).unwrap();

        let iface = &v["interfaces"][0];
        assert_eq!(iface["type"], "CAN");
        assert!(iface["index"].is_number());
        assert_eq!(iface["meta"][0]["name"], "CAN Max DLC");
        assert_eq!(iface["meta"][0]["value"], 8);

        assert_eq!(v["peripherals"][0]["kind"], "Actuator");

        let dm0 = &v["device_meta"][0];
        assert_eq!(dm0["name"], "Max Frame Defs");
        assert_eq!(dm0["value"], 16);
        // The raw metadata id is dropped — recoverable from the name.
        assert!(dm0.get("id").is_none());
    }

    #[test]
    fn serialise_meta_value_string_and_hex() {
        let utf8 = Meta {
            id: types::META_BOARD_NAME,
            quantity: types::QTY_STRING,
            value: MetaValue::Bytes(b"wiredflexlink".to_vec()),
        };
        assert_eq!(
            serde_json::to_value(&utf8).unwrap()["value"],
            "wiredflexlink"
        );

        // Invalid UTF-8 → lowercase hex.
        let invalid = Meta {
            id: types::META_BOARD_NAME,
            quantity: types::QTY_STRING,
            value: MetaValue::Bytes(vec![0xFF, 0xFE]),
        };
        assert_eq!(serde_json::to_value(&invalid).unwrap()["value"], "fffe");
    }

    #[test]
    fn serialise_supported_functions_as_name_array() {
        let meta = Meta {
            id: types::META_SUPPORTED_FUNCTIONS,
            quantity: types::QTY_RAW,
            value: MetaValue::Bytes(vec![
                xform::FUNC_PALETTE,
                xform::FUNC_CLAMP,
                xform::FUNC_THRESHOLD,
                xform::FUNC_GATE,
            ]),
        };
        let v = serde_json::to_value(&meta).unwrap();
        assert_eq!(v["name"], "Supported Functions");
        assert_eq!(
            v["value"],
            serde_json::json!(["Palette Lookup", "Clamp", "Threshold", "Gate"])
        );
    }

    #[test]
    fn serialise_non_printable_bytes_as_hex() {
        // Valid UTF-8 but control characters → treated as non-printable → hex.
        let meta = Meta {
            id: types::META_BOARD_NAME,
            quantity: types::QTY_STRING,
            value: MetaValue::Bytes(vec![0x00, 0x01, 0x1F]),
        };
        assert_eq!(serde_json::to_value(&meta).unwrap()["value"], "00011f");
        // Display and JSON stay consistent.
        assert_eq!(meta.value.to_string(), "00011f");
    }

    #[test]
    fn display_supported_functions_as_names() {
        let mut buf = Vec::new();
        buf.push(1); // 1 device meta entry
        push_meta_bytes(
            &mut buf,
            types::META_SUPPORTED_FUNCTIONS,
            types::QTY_RAW,
            &[
                xform::FUNC_PALETTE,
                xform::FUNC_CLAMP,
                xform::FUNC_THRESHOLD,
                xform::FUNC_GATE,
            ],
        );
        buf.push(0); // 0 interfaces
        buf.push(0); // 0 peripherals

        let caps = decode_capabilities(&buf).unwrap();
        let out = caps.to_string();
        assert!(out.contains("Supported Functions"));
        assert!(out.contains("Palette Lookup, Clamp, Threshold, Gate"));
        assert!(!out.contains("10111213"));
    }
}
