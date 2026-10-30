//! Device signals: their descriptors, reads and writes, and the write
//! interlock.
//!
//! A signal's identity is [`SignalKey`] plus the WRITABLE flag. `signal_id`
//! is a handle the device renumbers on reset, never identity.

use serde::{Serialize, Serializer};

use crate::{Error, frame_def, types};

const DSIG_LIST_ENTRY_SIZE: usize = 35;

/// A device signal's identity: at most one writable and one read-only signal
/// share a key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub struct SignalKey {
    pub target_type: u8,
    pub target_index: u8,
    pub role: u8,
    pub quantity: u8,
    pub aspect: u8,
    pub channel: u8,
}

/// A key's slug, as board TOML keys a signal:
/// `<target>.<index>.<role>.<quantity>[.<aspect>][.ch<N>]`, the quantity
/// suffixed `_per_s` for the per-second modifier, the aspect omitted when
/// default and the channel when none. For example
/// `peripheral.0.setpoint.colour_rgb.ch5`.
pub fn format_signal_key(key: &SignalKey) -> String {
    let mut slug = format!(
        "{}.{}.{}.{}",
        types::signal_target_slug(key.target_type),
        key.target_index,
        types::role_slug(key.role),
        types::quantity_slug(key.quantity),
    );
    if key.quantity & types::QTY_PER_SECOND != 0 {
        slug.push_str("_per_s");
    }
    if key.aspect != types::ASPECT_DEFAULT {
        slug.push('.');
        slug.push_str(types::aspect_slug(key.aspect));
    }
    if key.channel != types::SIGNAL_CHANNEL_NONE {
        slug.push_str(&format!(".ch{}", key.channel));
    }
    slug
}

/// The inverse of [`format_signal_key`].
pub fn parse_signal_key(s: &str) -> Result<SignalKey, Error> {
    let key = || s.to_string();
    let parts: Vec<&str> = s.split('.').collect();
    if !(4..=6).contains(&parts.len()) {
        return Err(Error::SignalKeySegments { key: key() });
    }
    let segment = |i: usize| parts[i].to_string();

    let target_type =
        types::signal_target_from_slug(parts[0]).ok_or_else(|| Error::SignalKeyTarget {
            key: key(),
            segment: segment(0),
        })?;
    let target_index = parts[1].parse().map_err(|_| Error::SignalKeyTargetIndex {
        key: key(),
        segment: segment(1),
    })?;
    let role = types::role_from_slug(parts[2]).ok_or_else(|| Error::SignalKeyRole {
        key: key(),
        segment: segment(2),
    })?;
    let quantity = types::quantity_from_slug(parts[3]).ok_or_else(|| Error::SignalKeyQuantity {
        key: key(),
        segment: segment(3),
    })?;

    let mut aspect = types::ASPECT_DEFAULT;
    let mut channel = types::SIGNAL_CHANNEL_NONE;
    for part in &parts[4..] {
        let segment = part.to_string();
        if let Some(ch) = part.strip_prefix("ch") {
            channel = ch.parse().map_err(|_| Error::SignalKeyChannel {
                key: key(),
                segment,
            })?;
        } else {
            aspect = types::aspect_from_slug(part).ok_or(Error::SignalKeyAspect {
                key: key(),
                segment,
            })?;
        }
    }

    Ok(SignalKey {
        target_type,
        target_index,
        role,
        quantity,
        aspect,
        channel,
    })
}

/// A device signal descriptor from DSIG_LIST_RESP.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(as = "SignalInfoWire"))]
pub struct SignalInfo {
    pub signal_id: u16,
    pub target_type: u8,
    pub target_index: u8,
    pub role: u8,
    /// The base quantity, or'd with `types::QTY_PER_SECOND` for a rate.
    pub quantity: u8,
    pub aspect: u8,
    /// `types::SIGNAL_CHANNEL_NONE` for the whole target.
    pub channel: u8,
    pub flags: u8,
    /// A `frame_def::VALUE_TYPE_*`.
    pub value_type: u8,
    pub value_len: u8,
    /// Physical value = raw × scale + offset, in the quantity's unit.
    pub scale: f32,
    pub offset: f32,
    /// Write bounds, unbounded when equal.
    pub min_raw: i64,
    pub max_raw: i64,
}

#[derive(Serialize)]
#[serde(rename = "SignalInfo")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
struct SignalInfoWire {
    signal_id: u16,
    target: &'static str,
    target_index: u8,
    role: &'static str,
    quantity: String,
    aspect: &'static str,
    channel: Option<u8>,
    writable: bool,
    persistable: bool,
    rule_destination: bool,
    frame_destination: bool,
    value_type: &'static str,
    value_len: u8,
    scale: f32,
    offset: f32,
    bounds: Option<(i64, i64)>,
}

impl Serialize for SignalInfo {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        SignalInfoWire {
            signal_id: self.signal_id,
            target: types::signal_target_name(self.target_type),
            target_index: self.target_index,
            role: types::role_name(self.role),
            quantity: types::quantity_display(self.quantity),
            aspect: types::aspect_name(self.aspect),
            channel: self.channel_index(),
            writable: self.is_writable(),
            persistable: self.is_persistable(),
            rule_destination: self.is_rule_destination(),
            frame_destination: self.is_frame_destination(),
            value_type: frame_def::value_type_name(self.value_type),
            value_len: self.value_len,
            scale: self.scale,
            offset: self.offset,
            bounds: self.bounds(),
        }
        .serialize(serializer)
    }
}

impl SignalInfo {
    pub fn key(&self) -> SignalKey {
        SignalKey {
            target_type: self.target_type,
            target_index: self.target_index,
            role: self.role,
            quantity: self.quantity,
            aspect: self.aspect,
            channel: self.channel,
        }
    }

    pub fn is_writable(&self) -> bool {
        self.flags & types::DSIG_FLAG_WRITABLE != 0
    }

    /// Whether a persist-save keeps it across a reboot.
    pub fn is_persistable(&self) -> bool {
        self.flags & types::DSIG_FLAG_PERSISTABLE != 0
    }

    pub fn is_rule_destination(&self) -> bool {
        self.flags & types::DSIG_FLAG_RULE_DEST != 0
    }

    pub fn is_frame_destination(&self) -> bool {
        self.flags & types::DSIG_FLAG_FRAME_DEST != 0
    }

    pub fn is_interface_signal(&self) -> bool {
        self.target_type == types::SIGNAL_TARGET_INTERFACE
    }

    /// The channel as an index, or `None` for a target-level signal.
    pub fn channel_index(&self) -> Option<u8> {
        (self.channel != types::SIGNAL_CHANNEL_NONE).then_some(self.channel)
    }

    /// Declared raw write bounds, or `None` when unbounded (min == max).
    pub fn bounds(&self) -> Option<(i64, i64)> {
        (self.min_raw != self.max_raw).then_some((self.min_raw, self.max_raw))
    }

    /// See [`semantic_signal_name`]; a board TOML's name overrides it.
    pub fn semantic_name(&self, iface_type: Option<u8>) -> String {
        semantic_signal_name(
            self.role,
            self.quantity,
            self.aspect,
            self.channel,
            iface_type,
        )
    }
}

/// A display name derived from the tuple: a conventional name where one
/// exists, else the aspect and quantity names, then a 1-based channel.
/// `iface_type` tells a serial port's STATUS BOOL ("Half Duplex") from any
/// other target's ("Running"); pass `None` off an interface.
pub fn semantic_signal_name(
    role: u8,
    quantity: u8,
    aspect: u8,
    channel: u8,
    iface_type: Option<u8>,
) -> String {
    let base = base_signal_name(role, quantity, aspect, iface_type);
    match channel {
        types::SIGNAL_CHANNEL_NONE => base,
        ch => format!("{base} {}", ch + 1),
    }
}

const TUPLE_NAMES: &[(u8, u8, u8, &str)] = &[
    (
        types::ROLE_CONFIG,
        types::QTY_DATARATE,
        types::ASPECT_DEFAULT,
        "Bitrate",
    ),
    (
        types::ROLE_CONFIG,
        types::QTY_BOOL,
        types::ASPECT_DEFAULT,
        "Enabled",
    ),
    (
        types::ROLE_CONFIG,
        types::QTY_BOOL,
        types::ASPECT_TERMINATION,
        "Termination",
    ),
    (
        types::ROLE_CONFIG,
        types::QTY_BOOL,
        types::ASPECT_STANDBY,
        "Standby",
    ),
    (
        types::ROLE_CONFIG,
        types::QTY_ENUM,
        types::ASPECT_PARITY,
        "Parity",
    ),
    (
        types::ROLE_CONFIG,
        types::QTY_ENUM,
        types::ASPECT_STOP_BITS,
        "Stop Bits",
    ),
    (
        types::ROLE_CONFIG,
        types::QTY_ENUM,
        types::ASPECT_DATA_BITS,
        "Data Bits",
    ),
    (
        types::ROLE_CONFIG,
        types::QTY_DURATION,
        types::ASPECT_DEFAULT,
        "Period",
    ),
    (
        types::ROLE_STATUS,
        types::QTY_ENUM,
        types::ASPECT_DEFAULT,
        "State",
    ),
    (
        types::ROLE_STATUS,
        types::QTY_BITMASK,
        types::ASPECT_DEFAULT,
        "Faults",
    ),
    (
        types::ROLE_SETPOINT,
        types::QTY_COLOUR_RGB,
        types::ASPECT_DEFAULT,
        "Colour",
    ),
    (
        types::ROLE_SETPOINT,
        types::QTY_BOOL,
        types::ASPECT_DEFAULT,
        "Enable",
    ),
    (
        types::ROLE_SETPOINT,
        types::QTY_ENUM,
        types::ASPECT_DEFAULT,
        "Mode",
    ),
    (
        types::ROLE_COMMAND,
        types::QTY_BOOL,
        types::ASPECT_DEFAULT,
        "Toggle",
    ),
    (
        types::ROLE_MEASUREMENT,
        types::QTY_TEMPERATURE,
        types::ASPECT_REFERENCE,
        "Cold Junction",
    ),
    (
        types::ROLE_DIAGNOSTIC,
        types::QTY_COUNT,
        types::ASPECT_CLIENT,
        "Client Drops",
    ),
    (
        types::ROLE_DIAGNOSTIC,
        types::QTY_COUNT,
        types::ASPECT_FORWARD,
        "Forward Drops",
    ),
    (
        types::ROLE_DIAGNOSTIC,
        types::QTY_COUNT,
        types::ASPECT_INGRESS,
        "Ingress Drops",
    ),
];

fn base_signal_name(role: u8, quantity: u8, aspect: u8, iface_type: Option<u8>) -> String {
    let base_qty = quantity & types::QTY_BASE_MASK;

    if let Some((_, _, _, name)) = TUPLE_NAMES
        .iter()
        .find(|(r, q, a, _)| *r == role && *q == base_qty && *a == aspect)
    {
        return per_second_qualified(name, quantity);
    }

    if (role, base_qty, aspect) == (types::ROLE_STATUS, types::QTY_BOOL, types::ASPECT_DEFAULT) {
        let name = match iface_type {
            Some(types::IFACE_RS485) | Some(types::IFACE_RS232) => "Half Duplex",
            _ => "Running",
        };
        return name.to_string();
    }

    if aspect != types::ASPECT_DEFAULT {
        return format!(
            "{} {}",
            types::aspect_name(aspect),
            per_second_qualified(types::quantity_name(quantity), quantity)
        );
    }

    per_second_qualified(types::quantity_name(quantity), quantity)
}

fn per_second_qualified(name: &str, quantity: u8) -> String {
    if quantity & types::QTY_PER_SECOND != 0 {
        format!("{name}/s")
    } else {
        name.to_string()
    }
}

/// The signals targeting interface `iface_index`.
pub fn interface_signals(signals: &[SignalInfo], iface_index: u8) -> Vec<&SignalInfo> {
    signals
        .iter()
        .filter(|s| s.is_interface_signal() && s.target_index == iface_index)
        .collect()
}

#[derive(Debug, Clone)]
pub struct SignalValue {
    pub signal_id: u16,
    pub value: u64,
    pub value_len: u8,
}

const DSIG_LIST_RESP_HDR_SIZE: usize = 6;

/// One DSIG_LIST_RESP: `signals` from `offset` of the device's `total`.
pub struct DsigListChunk {
    pub total: u16,
    pub offset: u16,
    pub signals: Vec<SignalInfo>,
}

pub fn build_list_request(offset: u16) -> Vec<u8> {
    offset.to_le_bytes().to_vec()
}

pub fn parse_list_response(payload: &[u8]) -> Result<DsigListChunk, Error> {
    if payload.len() < DSIG_LIST_RESP_HDR_SIZE {
        return Err(Error::InvalidPayload("truncated: missing header"));
    }

    let total = u16::from_le_bytes([payload[0], payload[1]]);
    let offset = u16::from_le_bytes([payload[2], payload[3]]);
    let count = u16::from_le_bytes([payload[4], payload[5]]) as usize;

    let mut pos = DSIG_LIST_RESP_HDR_SIZE;
    let mut signals = Vec::with_capacity(count);

    for _ in 0..count {
        if pos + DSIG_LIST_ENTRY_SIZE > payload.len() {
            break;
        }
        let e = &payload[pos..pos + DSIG_LIST_ENTRY_SIZE];
        pos += DSIG_LIST_ENTRY_SIZE;

        signals.push(SignalInfo {
            signal_id: u16::from_le_bytes([e[0], e[1]]),
            target_type: e[2],
            target_index: e[3],
            role: e[4],
            quantity: e[5],
            aspect: e[6],
            channel: e[7],
            flags: e[8],
            value_type: e[9],
            value_len: e[10],
            scale: f32::from_le_bytes([e[11], e[12], e[13], e[14]]),
            offset: f32::from_le_bytes([e[15], e[16], e[17], e[18]]),
            min_raw: i64::from_le_bytes(e[19..27].try_into().unwrap()),
            max_raw: i64::from_le_bytes(e[27..35].try_into().unwrap()),
        });
    }

    Ok(DsigListChunk {
        total,
        offset,
        signals,
    })
}

impl DsigListChunk {
    pub fn is_complete(&self) -> bool {
        self.offset + self.signals.len() as u16 >= self.total
    }

    pub fn next_offset(&self) -> u16 {
        self.offset + self.signals.len() as u16
    }
}

pub fn build_read_request(signal_id: u16) -> Vec<u8> {
    signal_id.to_le_bytes().to_vec()
}

pub fn parse_read_response(payload: &[u8]) -> Result<SignalValue, Error> {
    if payload.len() < 3 {
        return Err(Error::InvalidPayload(
            "truncated: missing signal ID or value length",
        ));
    }

    let signal_id = u16::from_le_bytes([payload[0], payload[1]]);
    let value_len = payload[2];

    if value_len == 0 || value_len > 8 {
        return Err(Error::InvalidPayload("invalid value length"));
    }

    if payload.len() < 3 + value_len as usize {
        return Err(Error::InvalidPayload("truncated: value data"));
    }

    let vdata = &payload[3..3 + value_len as usize];
    let value = decode_le_value(vdata);

    Ok(SignalValue {
        signal_id,
        value,
        value_len,
    })
}

pub fn build_write_request(signal_id: u16, value: u64) -> Vec<u8> {
    let vlen = value_encoded_len(value);
    let mut buf = Vec::with_capacity(3 + vlen as usize);

    buf.extend_from_slice(&signal_id.to_le_bytes());
    buf.push(vlen);

    match vlen {
        1 => buf.push(value as u8),
        2 => buf.extend_from_slice(&(value as u16).to_le_bytes()),
        4 => buf.extend_from_slice(&(value as u32).to_le_bytes()),
        8 => buf.extend_from_slice(&value.to_le_bytes()),
        _ => unreachable!(),
    }

    buf
}

pub fn build_user_signal_add(signal_id: u16) -> Vec<u8> {
    signal_id.to_le_bytes().to_vec()
}

pub fn build_user_signal_remove(signal_id: u16) -> Vec<u8> {
    signal_id.to_le_bytes().to_vec()
}

/// WRITE_UNLOCK echoes the challenge's nonce.
pub fn build_unlock_request(nonce: u32) -> Vec<u8> {
    nonce.to_le_bytes().to_vec()
}

pub fn build_set_interval_request(signal_id: u16, interval: u16) -> Vec<u8> {
    let mut buf = Vec::with_capacity(4);
    buf.extend_from_slice(&signal_id.to_le_bytes());
    buf.extend_from_slice(&interval.to_le_bytes());
    buf
}

pub fn parse_challenge_response(payload: &[u8]) -> Result<u32, Error> {
    if payload.len() < 4 {
        return Err(Error::InvalidPayload("truncated: challenge nonce"));
    }
    Ok(u32::from_le_bytes([
        payload[0], payload[1], payload[2], payload[3],
    ]))
}

fn value_encoded_len(val: u64) -> u8 {
    if val <= u8::MAX as u64 {
        1
    } else if val <= u16::MAX as u64 {
        2
    } else if val <= u32::MAX as u64 {
        4
    } else {
        8
    }
}

fn decode_le_value(data: &[u8]) -> u64 {
    let mut value: u64 = 0;
    for (i, &byte) in data.iter().enumerate() {
        value |= (byte as u64) << (i * 8);
    }
    value
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encode_entry(sig: &SignalInfo) -> Vec<u8> {
        let mut e = Vec::with_capacity(DSIG_LIST_ENTRY_SIZE);
        e.extend_from_slice(&sig.signal_id.to_le_bytes());
        e.extend_from_slice(&[
            sig.target_type,
            sig.target_index,
            sig.role,
            sig.quantity,
            sig.aspect,
            sig.channel,
            sig.flags,
            sig.value_type,
            sig.value_len,
        ]);
        e.extend_from_slice(&sig.scale.to_le_bytes());
        e.extend_from_slice(&sig.offset.to_le_bytes());
        e.extend_from_slice(&sig.min_raw.to_le_bytes());
        e.extend_from_slice(&sig.max_raw.to_le_bytes());
        assert_eq!(e.len(), DSIG_LIST_ENTRY_SIZE);
        e
    }

    fn bitrate_signal() -> SignalInfo {
        SignalInfo {
            signal_id: 0xFF00,
            target_type: types::SIGNAL_TARGET_INTERFACE,
            target_index: 0,
            role: types::ROLE_CONFIG,
            quantity: types::QTY_DATARATE,
            aspect: types::ASPECT_DEFAULT,
            channel: types::SIGNAL_CHANNEL_NONE,
            flags: types::DSIG_FLAG_WRITABLE | types::DSIG_FLAG_PERSISTABLE,
            value_type: frame_def::VALUE_TYPE_UNSIGNED,
            value_len: 4,
            scale: 1.0,
            offset: 0.0,
            min_raw: 0,
            max_raw: 1_000_000,
        }
    }

    fn temp_signal() -> SignalInfo {
        SignalInfo {
            signal_id: 0xFFC0,
            target_type: types::SIGNAL_TARGET_PERIPHERAL,
            target_index: 2,
            role: types::ROLE_MEASUREMENT,
            quantity: types::QTY_TEMPERATURE,
            aspect: types::ASPECT_DEFAULT,
            channel: types::SIGNAL_CHANNEL_NONE,
            flags: 0,
            value_type: frame_def::VALUE_TYPE_SIGNED,
            value_len: 2,
            scale: 0.1,
            offset: 0.0,
            min_raw: 0,
            max_raw: 0,
        }
    }

    #[test]
    fn roundtrip_write_request() {
        let buf = build_write_request(0xFF00, 125000);
        assert_eq!(buf[0..2], 0xFF00u16.to_le_bytes());
        assert_eq!(buf[2], 4); // 125000 fits in u32
        let val = u32::from_le_bytes([buf[3], buf[4], buf[5], buf[6]]);
        assert_eq!(val, 125000);
    }

    #[test]
    fn roundtrip_read_response() {
        // Build a fake response: signal_id=0xFF00, value_len=4, value=125000
        let mut payload = Vec::new();
        payload.extend_from_slice(&0xFF00u16.to_le_bytes());
        payload.push(4);
        payload.extend_from_slice(&125000u32.to_le_bytes());

        let sv = parse_read_response(&payload).unwrap();
        assert_eq!(sv.signal_id, 0xFF00);
        assert_eq!(sv.value, 125000);
        assert_eq!(sv.value_len, 4);
    }

    #[test]
    fn parse_list_response_chunked() {
        let bitrate = bitrate_signal();
        let temp = temp_signal();

        let mut payload = Vec::new();
        payload.extend_from_slice(&2u16.to_le_bytes()); // total
        payload.extend_from_slice(&0u16.to_le_bytes()); // offset
        payload.extend_from_slice(&2u16.to_le_bytes()); // count
        payload.extend_from_slice(&encode_entry(&bitrate));
        payload.extend_from_slice(&encode_entry(&temp));

        let chunk = parse_list_response(&payload).unwrap();
        assert_eq!(chunk.total, 2);
        assert_eq!(chunk.offset, 0);
        assert_eq!(chunk.signals.len(), 2);

        let s0 = &chunk.signals[0];
        assert_eq!(s0.signal_id, 0xFF00);
        assert_eq!(s0.target_type, types::SIGNAL_TARGET_INTERFACE);
        assert_eq!(s0.role, types::ROLE_CONFIG);
        assert_eq!(s0.quantity, types::QTY_DATARATE);
        assert_eq!(s0.aspect, types::ASPECT_DEFAULT);
        assert_eq!(s0.channel, types::SIGNAL_CHANNEL_NONE);
        assert!(s0.is_writable());
        assert!(s0.is_persistable());
        assert_eq!(s0.value_type, frame_def::VALUE_TYPE_UNSIGNED);
        assert_eq!(s0.value_len, 4);
        assert_eq!(s0.scale, 1.0);
        assert_eq!(s0.bounds(), Some((0, 1_000_000)));

        let s1 = &chunk.signals[1];
        assert_eq!(s1.signal_id, 0xFFC0);
        assert_eq!(s1.role, types::ROLE_MEASUREMENT);
        assert_eq!(s1.scale, 0.1);
        assert_eq!(s1.bounds(), None); // min == max = unbounded
        assert!(!s1.is_writable());
        assert!(chunk.is_complete());
    }

    #[test]
    fn list_entry_field_offsets_match_wire_layout() {
        // Pin every field to its byte offset — distinct sentinel values so a
        // transposed field cannot cancel out.
        let sig = SignalInfo {
            signal_id: 0xA1B2,
            target_type: 0x01,
            target_index: 0x02,
            role: 0x03,
            quantity: 0x84, // COUNT | PER_SECOND
            aspect: 0x05,
            channel: 0x06,
            flags: 0x03,
            value_type: 0x04,
            value_len: 0x08,
            scale: 0.5,
            offset: -1.0,
            min_raw: -2,
            max_raw: 0x0102_0304_0506_0708,
        };
        let e = encode_entry(&sig);

        assert_eq!(&e[0..2], &0xA1B2u16.to_le_bytes());
        assert_eq!(e[2], 0x01); // target_type
        assert_eq!(e[3], 0x02); // target_index
        assert_eq!(e[4], 0x03); // role
        assert_eq!(e[5], 0x84); // quantity
        assert_eq!(e[6], 0x05); // aspect
        assert_eq!(e[7], 0x06); // channel
        assert_eq!(e[8], 0x03); // flags
        assert_eq!(e[9], 0x04); // value_type
        assert_eq!(e[10], 0x08); // value_len
        assert_eq!(&e[11..15], &0.5f32.to_le_bytes());
        assert_eq!(&e[15..19], &(-1.0f32).to_le_bytes());
        assert_eq!(&e[19..27], &(-2i64).to_le_bytes());
        assert_eq!(&e[27..35], &0x0102_0304_0506_0708i64.to_le_bytes());

        let mut payload = Vec::new();
        payload.extend_from_slice(&1u16.to_le_bytes());
        payload.extend_from_slice(&0u16.to_le_bytes());
        payload.extend_from_slice(&1u16.to_le_bytes());
        payload.extend_from_slice(&e);

        let parsed = &parse_list_response(&payload).unwrap().signals[0];
        assert_eq!(parsed.signal_id, sig.signal_id);
        assert_eq!(parsed.quantity, sig.quantity);
        assert_eq!(parsed.scale, sig.scale);
        assert_eq!(parsed.offset, sig.offset);
        assert_eq!(parsed.min_raw, sig.min_raw);
        assert_eq!(parsed.max_raw, sig.max_raw);
        assert_eq!(parsed.key(), sig.key());
    }

    #[test]
    fn semantic_names_for_conventional_tuples() {
        use types::*;
        let name = |r, q, a, ch, ift| semantic_signal_name(r, q, a, ch, ift);

        assert_eq!(
            name(
                ROLE_CONFIG,
                QTY_DATARATE,
                ASPECT_DEFAULT,
                SIGNAL_CHANNEL_NONE,
                None
            ),
            "Bitrate"
        );
        assert_eq!(
            name(
                ROLE_CONFIG,
                QTY_BOOL,
                ASPECT_TERMINATION,
                SIGNAL_CHANNEL_NONE,
                None
            ),
            "Termination"
        );
        assert_eq!(
            name(
                ROLE_CONFIG,
                QTY_BOOL,
                ASPECT_STANDBY,
                SIGNAL_CHANNEL_NONE,
                None
            ),
            "Standby"
        );
        assert_eq!(
            name(
                ROLE_CONFIG,
                QTY_BOOL,
                ASPECT_DEFAULT,
                SIGNAL_CHANNEL_NONE,
                None
            ),
            "Enabled"
        );
        assert_eq!(
            name(ROLE_MEASUREMENT, QTY_TEMPERATURE, ASPECT_DEFAULT, 0, None),
            "Temperature 1"
        );
        assert_eq!(
            name(
                ROLE_MEASUREMENT,
                QTY_TEMPERATURE,
                ASPECT_DEFAULT,
                SIGNAL_CHANNEL_NONE,
                None
            ),
            "Temperature"
        );
        assert_eq!(
            name(ROLE_MEASUREMENT, QTY_TEMPERATURE, ASPECT_REFERENCE, 1, None),
            "Cold Junction 2"
        );
        assert_eq!(
            name(ROLE_SETPOINT, QTY_COLOUR_RGB, ASPECT_DEFAULT, 5, None),
            "Colour 6"
        );
        assert_eq!(
            name(
                ROLE_DIAGNOSTIC,
                QTY_COUNT,
                ASPECT_CLIENT,
                SIGNAL_CHANNEL_NONE,
                None
            ),
            "Client Drops"
        );
        assert_eq!(
            name(
                ROLE_DIAGNOSTIC,
                QTY_COUNT,
                ASPECT_FORWARD,
                SIGNAL_CHANNEL_NONE,
                None
            ),
            "Forward Drops"
        );
        assert_eq!(
            name(
                ROLE_DIAGNOSTIC,
                QTY_COUNT,
                ASPECT_INGRESS,
                SIGNAL_CHANNEL_NONE,
                None
            ),
            "Ingress Drops"
        );
    }

    #[test]
    fn status_bool_default_depends_on_interface_type() {
        use types::*;
        let running = semantic_signal_name(
            ROLE_STATUS,
            QTY_BOOL,
            ASPECT_DEFAULT,
            SIGNAL_CHANNEL_NONE,
            Some(IFACE_CAN),
        );
        assert_eq!(running, "Running");
        let duplex = semantic_signal_name(
            ROLE_STATUS,
            QTY_BOOL,
            ASPECT_DEFAULT,
            SIGNAL_CHANNEL_NONE,
            Some(IFACE_RS485),
        );
        assert_eq!(duplex, "Half Duplex");
        // No target context — a run-state is the safer universal reading.
        let bare = semantic_signal_name(
            ROLE_STATUS,
            QTY_BOOL,
            ASPECT_DEFAULT,
            SIGNAL_CHANNEL_NONE,
            None,
        );
        assert_eq!(bare, "Running");
    }

    #[test]
    fn semantic_name_fallbacks_stay_data_driven() {
        use types::*;
        // Unlisted tuple with a non-default aspect: aspect + quantity.
        assert_eq!(
            semantic_signal_name(
                ROLE_MEASUREMENT,
                QTY_DURATION,
                ASPECT_ELAPSED,
                SIGNAL_CHANNEL_NONE,
                None
            ),
            "Elapsed Duration"
        );
        // Per-second modifier flows through the fallback name.
        assert_eq!(
            semantic_signal_name(
                ROLE_SETPOINT,
                QTY_TEMPERATURE | QTY_PER_SECOND,
                ASPECT_RAMPED,
                SIGNAL_CHANNEL_NONE,
                None,
            ),
            "Ramped Temperature/s"
        );
        // Plain quantity fallback.
        assert_eq!(
            semantic_signal_name(ROLE_MEASUREMENT, QTY_CURRENT, ASPECT_DEFAULT, 2, None),
            "Current 3"
        );
    }

    #[test]
    fn value_encoding_lengths() {
        assert_eq!(value_encoded_len(0), 1);
        assert_eq!(value_encoded_len(255), 1);
        assert_eq!(value_encoded_len(256), 2);
        assert_eq!(value_encoded_len(65535), 2);
        assert_eq!(value_encoded_len(65536), 4);
        assert_eq!(value_encoded_len(u32::MAX as u64), 4);
        assert_eq!(value_encoded_len(u32::MAX as u64 + 1), 8);
    }

    #[test]
    fn challenge_response_roundtrip() {
        let nonce: u32 = 0xA3B7C1D2;
        let payload = nonce.to_le_bytes().to_vec();
        assert_eq!(parse_challenge_response(&payload).unwrap(), nonce);

        let unlock = build_unlock_request(nonce);
        assert_eq!(unlock, payload);
    }

    #[test]
    fn serialise_signal_info_expands_flags_and_names() {
        let si = temp_signal();
        let v = serde_json::to_value(&si).unwrap();
        assert_eq!(v["target"], "Peripheral");
        assert_eq!(v["role"], "Measurement");
        assert_eq!(v["quantity"], "Temperature");
        assert_eq!(v["aspect"], "Default");
        assert_eq!(v["channel"], serde_json::Value::Null);
        assert_eq!(v["writable"], false);
        assert_eq!(v["persistable"], false);
        assert_eq!(v["value_type"], "signed");
        assert!(v["signal_id"].is_number());
        assert!(v["value_len"].is_number());
        // The raw flags bitfield is expanded, not exposed.
        assert!(v.get("flags").is_none());
    }

    fn slug_key(
        target_type: u8,
        target_index: u8,
        role: u8,
        quantity: u8,
        aspect: u8,
        channel: u8,
    ) -> SignalKey {
        SignalKey {
            target_type,
            target_index,
            role,
            quantity,
            aspect,
            channel,
        }
    }

    #[test]
    fn signal_key_slugs_are_pinned_and_round_trip() {
        use types::*;
        let pinned = [
            (
                slug_key(
                    SIGNAL_TARGET_INTERFACE,
                    0,
                    ROLE_CONFIG,
                    QTY_DATARATE,
                    ASPECT_DEFAULT,
                    SIGNAL_CHANNEL_NONE,
                ),
                "interface.0.config.datarate",
            ),
            (
                slug_key(
                    SIGNAL_TARGET_INTERFACE,
                    2,
                    ROLE_CONFIG,
                    QTY_BOOL,
                    ASPECT_TERMINATION,
                    SIGNAL_CHANNEL_NONE,
                ),
                "interface.2.config.bool.termination",
            ),
            (
                slug_key(
                    SIGNAL_TARGET_PERIPHERAL,
                    0,
                    ROLE_SETPOINT,
                    QTY_COLOUR_RGB,
                    ASPECT_DEFAULT,
                    5,
                ),
                "peripheral.0.setpoint.colour_rgb.ch5",
            ),
            (
                slug_key(
                    SIGNAL_TARGET_PERIPHERAL,
                    1,
                    ROLE_MEASUREMENT,
                    QTY_TEMPERATURE | QTY_PER_SECOND,
                    ASPECT_RAMPED,
                    3,
                ),
                "peripheral.1.measurement.temperature_per_s.ramped.ch3",
            ),
            (
                slug_key(
                    SIGNAL_TARGET_DEVICE,
                    0,
                    ROLE_DIAGNOSTIC,
                    QTY_COUNT,
                    ASPECT_CLIENT,
                    SIGNAL_CHANNEL_NONE,
                ),
                "device.0.diagnostic.count.client",
            ),
        ];
        for (key, slug) in pinned {
            assert_eq!(format_signal_key(&key), slug);
            assert_eq!(parse_signal_key(slug), Ok(key), "{slug}");
        }
    }

    #[test]
    fn a_bad_signal_key_names_its_fault_as_before() {
        let pinned = [
            (
                "interface.0.config",
                "signal key 'interface.0.config': expected 4-6 dot-separated segments",
            ),
            (
                "a.b.c.d.e.f.g",
                "signal key 'a.b.c.d.e.f.g': expected 4-6 dot-separated segments",
            ),
            (
                "widget.0.config.datarate",
                "signal key 'widget.0.config.datarate': unknown target 'widget'",
            ),
            (
                "interface.x.config.datarate",
                "signal key 'interface.x.config.datarate': bad target index 'x'",
            ),
            (
                "interface.0.boss.datarate",
                "signal key 'interface.0.boss.datarate': unknown role 'boss'",
            ),
            (
                "interface.0.config.warp",
                "signal key 'interface.0.config.warp': unknown quantity 'warp'",
            ),
            (
                "interface.0.config.datarate.chx",
                "signal key 'interface.0.config.datarate.chx': bad channel 'chx'",
            ),
            (
                "interface.0.config.datarate.bogus",
                "signal key 'interface.0.config.datarate.bogus': unknown aspect 'bogus'",
            ),
        ];
        for (slug, message) in pinned {
            assert_eq!(parse_signal_key(slug).unwrap_err().to_string(), message);
        }
    }
}
