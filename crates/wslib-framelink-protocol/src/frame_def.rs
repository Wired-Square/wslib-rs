//! Frame definitions: where each signal sits in a frame.
//!
//! FRAME_DEF_ADD / FRAME_DEF_RESP (0x30 / 0x33):
//!   `frame_def_id(u16 LE) interface_type(u8)`
//!   CAN header: `can_id(u32 LE) dlc(u8) flags(u8)`
//!   RS485 header: `framing_mode(u8)`
//!   `num_signals(u8)`
//!   `[signals: signal_id(u16 LE) start_bit(u16 LE) bit_length(u16 LE)
//!             byte_order(u8) value_type(u8) quantity(u8) scale(f32 LE)
//!             offset(f32 LE)]...`
//!
//! Each signal is 17 bytes.
//!
//! FRAME_DEF_REMOVE (0x31): `frame_def_id(u16 LE)`
//! FRAME_DEF_LIST (0x32): empty payload

use crate::{Error, types};
use serde::{Serialize, Serializer};

pub const BYTE_ORDER_LE: u8 = 0;
pub const BYTE_ORDER_BE: u8 = 1;

pub const VALUE_TYPE_UNSIGNED: u8 = 0;
pub const VALUE_TYPE_SIGNED: u8 = 1;
pub const VALUE_TYPE_FLOAT: u8 = 2;
pub const VALUE_TYPE_BOOL: u8 = 3;
pub const VALUE_TYPE_ARRAY: u8 = 4;

pub fn byte_order_name(byte_order: u8) -> &'static str {
    match byte_order {
        BYTE_ORDER_LE => "le",
        BYTE_ORDER_BE => "be",
        _ => "unknown",
    }
}

/// Every value type with its name, for a consumer to enumerate.
pub const VALUE_TYPE_NAMES: &[(u8, &str)] = &[
    (VALUE_TYPE_UNSIGNED, "unsigned"),
    (VALUE_TYPE_SIGNED, "signed"),
    (VALUE_TYPE_FLOAT, "float"),
    (VALUE_TYPE_BOOL, "bool"),
    (VALUE_TYPE_ARRAY, "array"),
];

/// `"unknown"` for a type not in [`VALUE_TYPE_NAMES`].
pub fn value_type_name(value_type: u8) -> &'static str {
    types::table_name(VALUE_TYPE_NAMES, value_type, "unknown")
}

fn ser_byte_order_name<S: Serializer>(byte_order: &u8, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(byte_order_name(*byte_order))
}

fn ser_value_type_name<S: Serializer>(value_type: &u8, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(value_type_name(*value_type))
}

fn ser_quantity_display<S: Serializer>(quantity: &u8, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&types::quantity_display(*quantity))
}

// The firmware's `frame_def.h` (`FL_CAN_FLAG_*`).
pub const CAN_FLAG_EXTENDED: u8 = 0x01;
pub const CAN_FLAG_FD: u8 = 0x02;
pub const CAN_FLAG_BRS: u8 = 0x04;
pub const CAN_FLAG_RTR: u8 = 0x08;
pub const CAN_FLAG_MATCH_ANY: u8 = 0x80;

pub const IFACE_TYPE_CAN: u8 = types::IFACE_CAN;
pub const IFACE_TYPE_CANFD: u8 = types::IFACE_CANFD;
pub const IFACE_TYPE_RS485: u8 = types::IFACE_RS485;
pub const IFACE_TYPE_RS232: u8 = types::IFACE_RS232;
pub const IFACE_TYPE_LIN: u8 = types::IFACE_LIN;

const SIGNAL_SIZE: usize = 17;

pub const SIGNAL_MAX_BITS: u16 = 64;
pub const MAX_SIGNALS: usize = u8::MAX as usize;
pub const RESERVED_IDS: [u16; 2] = [types::FRAME_DEF_ID_USER, types::FRAME_DEF_ID_DEVICE];

#[derive(Debug, Clone, Serialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub struct FrameSignalDef {
    pub signal_id: u16,
    pub start_bit: u16,
    pub bit_length: u16,
    #[serde(serialize_with = "ser_byte_order_name")]
    #[cfg_attr(feature = "ts", ts(type = "string"))]
    pub byte_order: u8,
    #[serde(serialize_with = "ser_value_type_name")]
    #[cfg_attr(feature = "ts", ts(type = "string"))]
    pub value_type: u8,
    #[serde(serialize_with = "ser_quantity_display")]
    #[cfg_attr(feature = "ts", ts(type = "string"))]
    pub quantity: u8,
    pub scale: f32,
    pub offset: f32,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
#[non_exhaustive]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub enum FrameHeader {
    Can { can_id: u32, dlc: u8, flags: u8 },
    Rs485 { framing_mode: u8 },
}

#[derive(Debug, Clone, Serialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub struct FrameDefInfo {
    pub frame_def_id: u16,
    #[serde(serialize_with = "types::ser_interface_name")]
    #[cfg_attr(feature = "ts", ts(type = "string"))]
    pub interface_type: u8,
    pub header: FrameHeader,
    pub signals: Vec<FrameSignalDef>,
}

pub fn build_frame_def_add(info: &FrameDefInfo) -> Result<Vec<u8>, Error> {
    if RESERVED_IDS.contains(&info.frame_def_id) {
        return Err(Error::ReservedFrameDefId(info.frame_def_id));
    }
    let count =
        u8::try_from(info.signals.len()).map_err(|_| Error::TooManySignals(info.signals.len()))?;
    if let Some(sig) = info
        .signals
        .iter()
        .find(|sig| !(1..=SIGNAL_MAX_BITS).contains(&sig.bit_length))
    {
        return Err(Error::SignalBits {
            signal_id: sig.signal_id,
            bit_length: sig.bit_length,
        });
    }
    Ok(encode(info, count))
}

fn encode(info: &FrameDefInfo, count: u8) -> Vec<u8> {
    let header_size = match &info.header {
        FrameHeader::Can { .. } => 6,
        FrameHeader::Rs485 { .. } => 1,
    };
    let mut buf = Vec::with_capacity(3 + header_size + 1 + info.signals.len() * SIGNAL_SIZE);

    buf.extend_from_slice(&info.frame_def_id.to_le_bytes());
    buf.push(info.interface_type);

    match &info.header {
        FrameHeader::Can { can_id, dlc, flags } => {
            buf.extend_from_slice(&can_id.to_le_bytes());
            buf.push(*dlc);
            buf.push(*flags);
        }
        FrameHeader::Rs485 { framing_mode } => {
            buf.push(*framing_mode);
        }
    }

    buf.push(count);

    for sig in &info.signals {
        buf.extend_from_slice(&sig.signal_id.to_le_bytes());
        buf.extend_from_slice(&sig.start_bit.to_le_bytes());
        buf.extend_from_slice(&sig.bit_length.to_le_bytes());
        buf.push(sig.byte_order);
        buf.push(sig.value_type);
        buf.push(sig.quantity);
        buf.extend_from_slice(&sig.scale.to_le_bytes());
        buf.extend_from_slice(&sig.offset.to_le_bytes());
    }

    buf
}

pub fn build_frame_def_remove(frame_def_id: u16) -> Vec<u8> {
    frame_def_id.to_le_bytes().to_vec()
}

pub fn build_frame_def_list() -> Vec<u8> {
    Vec::new()
}

pub fn parse_frame_def_resp(payload: &[u8]) -> Result<FrameDefInfo, Error> {
    if payload.len() < 3 {
        return Err(Error::InvalidPayload("frame def resp too short"));
    }

    let frame_def_id = u16::from_le_bytes([payload[0], payload[1]]);
    let interface_type = payload[2];

    let (header, pos) = match interface_type {
        IFACE_TYPE_CAN | IFACE_TYPE_CANFD => {
            if payload.len() < 3 + 6 {
                return Err(Error::InvalidPayload("frame def CAN header truncated"));
            }
            let can_id = u32::from_le_bytes([payload[3], payload[4], payload[5], payload[6]]);
            let dlc = payload[7];
            let flags = payload[8];
            (FrameHeader::Can { can_id, dlc, flags }, 9)
        }
        IFACE_TYPE_RS485 | IFACE_TYPE_RS232 | IFACE_TYPE_LIN => {
            if payload.len() < 3 + 1 {
                return Err(Error::InvalidPayload("frame def RS485 header truncated"));
            }
            let framing_mode = payload[3];
            (FrameHeader::Rs485 { framing_mode }, 4)
        }
        _ => {
            return Err(Error::InvalidPayload("unknown interface type"));
        }
    };

    if payload.len() < pos + 1 {
        return Err(Error::InvalidPayload("frame def missing signal count"));
    }

    let num_signals = payload[pos] as usize;
    let signals_start = pos + 1;

    if payload.len() < signals_start + num_signals * SIGNAL_SIZE {
        return Err(Error::InvalidPayload("frame def signals truncated"));
    }

    let mut signals = Vec::with_capacity(num_signals);
    let mut p = signals_start;

    for _ in 0..num_signals {
        let signal_id = u16::from_le_bytes([payload[p], payload[p + 1]]);
        let start_bit = u16::from_le_bytes([payload[p + 2], payload[p + 3]]);
        let bit_length = u16::from_le_bytes([payload[p + 4], payload[p + 5]]);
        let byte_order = payload[p + 6];
        let value_type = payload[p + 7];
        let quantity = payload[p + 8];
        let scale = f32::from_le_bytes([
            payload[p + 9],
            payload[p + 10],
            payload[p + 11],
            payload[p + 12],
        ]);
        let offset = f32::from_le_bytes([
            payload[p + 13],
            payload[p + 14],
            payload[p + 15],
            payload[p + 16],
        ]);

        signals.push(FrameSignalDef {
            signal_id,
            start_bit,
            bit_length,
            byte_order,
            value_type,
            quantity,
            scale,
            offset,
        });

        p += SIGNAL_SIZE;
    }

    Ok(FrameDefInfo {
        frame_def_id,
        interface_type,
        header,
        signals,
    })
}

/// The bits a signal occupies: contiguous from `start_bit` little-endian, or
/// Motorola order big-endian.
pub fn signal_bit_positions(start_bit: u16, bit_length: u16, byte_order: u8) -> Vec<u16> {
    if byte_order == BYTE_ORDER_BE {
        motorola_bit_positions(start_bit, bit_length)
    } else {
        (start_bit..start_bit + bit_length).collect()
    }
}

/// Motorola order: from the MSB at `start_bit`, down each byte's bits 7 to 0,
/// then on to bit 7 of the next byte.
pub fn motorola_bit_positions(start_bit: u16, bit_length: u16) -> Vec<u16> {
    let mut positions = Vec::with_capacity(bit_length as usize);
    let mut bit = start_bit;
    for _ in 0..bit_length {
        positions.push(bit);
        let bit_in_byte = bit % 8;
        if bit_in_byte == 0 {
            bit += 15;
        } else {
            bit -= 1;
        }
    }
    positions
}

pub fn next_available_id(existing: &[FrameDefInfo]) -> u16 {
    crate::next_free_id(existing.iter().map(|f| f.frame_def_id).chain(RESERVED_IDS))
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEVICE_SIGNAL_BYTES: usize = 17;

    #[test]
    fn motorola_8bit_signal() {
        // 8-bit signal starting at bit 7 (byte 0 MSB) should cover byte 0
        let pos = motorola_bit_positions(7, 8);
        assert_eq!(pos, vec![7, 6, 5, 4, 3, 2, 1, 0]);
    }

    #[test]
    fn motorola_crosses_byte() {
        // 12-bit signal starting at bit 7 should cover byte 0 + 4 bits of byte 1
        let pos = motorola_bit_positions(7, 12);
        assert_eq!(pos, vec![7, 6, 5, 4, 3, 2, 1, 0, 15, 14, 13, 12]);
    }

    #[test]
    fn intel_8bit_signal() {
        let pos = signal_bit_positions(0, 8, BYTE_ORDER_LE);
        assert_eq!(pos, vec![0, 1, 2, 3, 4, 5, 6, 7]);
    }

    #[test]
    fn signal_bit_positions_be_dispatches() {
        let pos = signal_bit_positions(7, 8, BYTE_ORDER_BE);
        assert_eq!(pos, motorola_bit_positions(7, 8));
    }

    #[test]
    fn next_available_id_empty() {
        assert_eq!(next_available_id(&[]), 0);
    }

    #[test]
    fn next_available_id_skips_used() {
        let existing = vec![
            FrameDefInfo {
                frame_def_id: 0,
                interface_type: IFACE_TYPE_CAN,
                header: FrameHeader::Can {
                    can_id: 0x100,
                    dlc: 8,
                    flags: 0,
                },
                signals: vec![],
            },
            FrameDefInfo {
                frame_def_id: 1,
                interface_type: IFACE_TYPE_CAN,
                header: FrameHeader::Can {
                    can_id: 0x101,
                    dlc: 8,
                    flags: 0,
                },
                signals: vec![],
            },
        ];
        assert_eq!(next_available_id(&existing), 2);
    }

    #[test]
    fn build_frame_def_add_can_with_signals() {
        let info = FrameDefInfo {
            frame_def_id: 1,
            interface_type: IFACE_TYPE_CAN,
            header: FrameHeader::Can {
                can_id: 0x18FF00FE,
                dlc: 8,
                flags: 0,
            },
            signals: vec![
                FrameSignalDef {
                    signal_id: 0x0001,
                    start_bit: 0,
                    bit_length: 16,
                    byte_order: BYTE_ORDER_LE,
                    value_type: VALUE_TYPE_UNSIGNED,
                    quantity: types::QTY_RAW,
                    scale: 1.0,
                    offset: 0.0,
                },
                FrameSignalDef {
                    signal_id: 0x0002,
                    start_bit: 16,
                    bit_length: 8,
                    byte_order: BYTE_ORDER_BE,
                    value_type: VALUE_TYPE_SIGNED,
                    quantity: types::QTY_RAW,
                    scale: 0.1,
                    offset: -40.0,
                },
            ],
        };
        let payload = build_frame_def_add(&info).unwrap();

        assert_eq!(payload.len(), 3 + 6 + 1 + 2 * DEVICE_SIGNAL_BYTES);

        assert_eq!(u16::from_le_bytes([payload[0], payload[1]]), 1);
        assert_eq!(payload[2], IFACE_TYPE_CAN);
        let can_id = u32::from_le_bytes([payload[3], payload[4], payload[5], payload[6]]);
        assert_eq!(can_id, 0x18FF00FE);
        assert_eq!(payload[7], 8); // dlc
        assert_eq!(payload[8], 0); // flags
        assert_eq!(payload[9], 2); // num_signals

        // First signal at offset 10
        assert_eq!(u16::from_le_bytes([payload[10], payload[11]]), 0x0001);
        assert_eq!(u16::from_le_bytes([payload[12], payload[13]]), 0); // start_bit
        assert_eq!(u16::from_le_bytes([payload[14], payload[15]]), 16); // bit_length
        assert_eq!(payload[16], BYTE_ORDER_LE);
        assert_eq!(payload[17], VALUE_TYPE_UNSIGNED);
        assert_eq!(payload[18], types::QTY_RAW);
        assert_eq!(
            f32::from_le_bytes([payload[19], payload[20], payload[21], payload[22]]),
            1.0
        );
        assert_eq!(
            f32::from_le_bytes([payload[23], payload[24], payload[25], payload[26]]),
            0.0
        );

        assert_eq!(u16::from_le_bytes([payload[27], payload[28]]), 0x0002);
        assert_eq!(payload[33], BYTE_ORDER_BE);
        assert_eq!(payload[34], VALUE_TYPE_SIGNED);
        assert_eq!(payload[35], types::QTY_RAW);
    }

    #[test]
    fn build_frame_def_add_rs485_no_signals() {
        let info = FrameDefInfo {
            frame_def_id: 0x00FF,
            interface_type: IFACE_TYPE_RS485,
            header: FrameHeader::Rs485 { framing_mode: 2 },
            signals: vec![],
        };
        let payload = build_frame_def_add(&info).unwrap();

        // 3 (id + iface) + 1 (RS485 header) + 1 (num_signals) = 5
        assert_eq!(payload.len(), 5);
        assert_eq!(u16::from_le_bytes([payload[0], payload[1]]), 0x00FF);
        assert_eq!(payload[2], IFACE_TYPE_RS485);
        assert_eq!(payload[3], 2); // framing_mode
        assert_eq!(payload[4], 0); // num_signals
    }

    #[test]
    fn frame_def_remove_payload() {
        let payload = build_frame_def_remove(42);
        assert_eq!(payload, 42u16.to_le_bytes().to_vec());
    }

    #[test]
    fn frame_def_list_payload() {
        let payload = build_frame_def_list();
        assert!(payload.is_empty());
    }

    #[test]
    fn parse_frame_def_resp_can_roundtrip() {
        let info = FrameDefInfo {
            frame_def_id: 5,
            interface_type: IFACE_TYPE_CAN,
            header: FrameHeader::Can {
                can_id: 0x18FF00FE,
                dlc: 8,
                flags: CAN_FLAG_BRS,
            },
            signals: vec![
                FrameSignalDef {
                    signal_id: 0x1234,
                    start_bit: 0,
                    bit_length: 16,
                    byte_order: BYTE_ORDER_LE,
                    value_type: VALUE_TYPE_UNSIGNED,
                    quantity: types::QTY_RAW,
                    scale: 1.0,
                    offset: 0.0,
                },
                FrameSignalDef {
                    signal_id: 0x5678,
                    start_bit: 32,
                    bit_length: 32,
                    byte_order: BYTE_ORDER_BE,
                    value_type: VALUE_TYPE_FLOAT,
                    quantity: types::QTY_TEMPERATURE | types::QTY_PER_SECOND,
                    scale: 0.01,
                    offset: -273.15,
                },
            ],
        };
        let payload = build_frame_def_add(&info).unwrap();
        let parsed = parse_frame_def_resp(&payload).unwrap();

        assert_eq!(parsed.frame_def_id, 5);
        assert_eq!(parsed.interface_type, IFACE_TYPE_CAN);

        match &parsed.header {
            FrameHeader::Can { can_id, dlc, flags } => {
                assert_eq!(*can_id, 0x18FF00FE);
                assert_eq!(*dlc, 8);
                assert_eq!(*flags, CAN_FLAG_BRS);
            }
            _ => panic!("expected CAN header"),
        }

        assert_eq!(parsed.signals.len(), 2);

        assert_eq!(parsed.signals[0].signal_id, 0x1234);
        assert_eq!(parsed.signals[0].start_bit, 0);
        assert_eq!(parsed.signals[0].bit_length, 16);
        assert_eq!(parsed.signals[0].byte_order, BYTE_ORDER_LE);
        assert_eq!(parsed.signals[0].value_type, VALUE_TYPE_UNSIGNED);
        assert_eq!(parsed.signals[0].quantity, types::QTY_RAW);
        assert_eq!(parsed.signals[0].scale, 1.0);
        assert_eq!(parsed.signals[0].offset, 0.0);

        assert_eq!(parsed.signals[1].signal_id, 0x5678);
        assert_eq!(parsed.signals[1].start_bit, 32);
        assert_eq!(parsed.signals[1].bit_length, 32);
        assert_eq!(parsed.signals[1].byte_order, BYTE_ORDER_BE);
        assert_eq!(parsed.signals[1].value_type, VALUE_TYPE_FLOAT);
        assert_eq!(
            parsed.signals[1].quantity,
            types::QTY_TEMPERATURE | types::QTY_PER_SECOND
        );
        assert_eq!(parsed.signals[1].scale, 0.01);
        assert_eq!(parsed.signals[1].offset, -273.15);
    }

    #[test]
    fn parse_frame_def_resp_rs485_roundtrip() {
        let info = FrameDefInfo {
            frame_def_id: 10,
            interface_type: IFACE_TYPE_RS485,
            header: FrameHeader::Rs485 { framing_mode: 1 },
            signals: vec![],
        };
        let payload = build_frame_def_add(&info).unwrap();
        let parsed = parse_frame_def_resp(&payload).unwrap();

        assert_eq!(parsed.frame_def_id, 10);
        assert_eq!(parsed.interface_type, IFACE_TYPE_RS485);

        match &parsed.header {
            FrameHeader::Rs485 { framing_mode } => {
                assert_eq!(*framing_mode, 1);
            }
            _ => panic!("expected RS485 header"),
        }

        assert!(parsed.signals.is_empty());
    }

    #[test]
    fn parse_frame_def_resp_canfd_roundtrip() {
        let info = FrameDefInfo {
            frame_def_id: 3,
            interface_type: IFACE_TYPE_CANFD,
            header: FrameHeader::Can {
                can_id: 0x100,
                dlc: 64,
                flags: CAN_FLAG_EXTENDED,
            },
            signals: vec![FrameSignalDef {
                signal_id: 0xABCD,
                start_bit: 8,
                bit_length: 24,
                byte_order: BYTE_ORDER_LE,
                value_type: VALUE_TYPE_BOOL,
                quantity: types::QTY_RAW,
                scale: 1.0,
                offset: 0.0,
            }],
        };
        let payload = build_frame_def_add(&info).unwrap();
        let parsed = parse_frame_def_resp(&payload).unwrap();

        assert_eq!(parsed.frame_def_id, 3);
        assert_eq!(parsed.interface_type, IFACE_TYPE_CANFD);

        match &parsed.header {
            FrameHeader::Can { can_id, dlc, flags } => {
                assert_eq!(*can_id, 0x100);
                assert_eq!(*dlc, 64);
                assert_eq!(*flags, CAN_FLAG_EXTENDED);
            }
            _ => panic!("expected CAN header"),
        }

        assert_eq!(parsed.signals.len(), 1);
        assert_eq!(parsed.signals[0].signal_id, 0xABCD);
        assert_eq!(parsed.signals[0].value_type, VALUE_TYPE_BOOL);
    }

    #[test]
    fn parse_frame_def_resp_too_short() {
        assert!(parse_frame_def_resp(&[0; 2]).is_err());
    }

    #[test]
    fn parse_frame_def_resp_can_header_truncated() {
        // 3 bytes (id + iface) but CAN needs 6 more for header
        let payload = [0x01, 0x00, IFACE_TYPE_CAN, 0x00, 0x00];
        assert!(parse_frame_def_resp(&payload).is_err());
    }

    #[test]
    fn parse_frame_def_resp_signals_truncated() {
        // Valid CAN header but claims 1 signal with insufficient data
        let mut payload = vec![0x01, 0x00, IFACE_TYPE_CAN];
        payload.extend_from_slice(&0x100u32.to_le_bytes()); // can_id
        payload.push(8); // dlc
        payload.push(0); // flags
        payload.push(1); // num_signals = 1, but no signal data follows
        assert!(parse_frame_def_resp(&payload).is_err());
    }

    #[test]
    fn parse_frame_def_resp_unknown_interface() {
        let payload = [0x01, 0x00, 0xFF];
        assert!(parse_frame_def_resp(&payload).is_err());
    }

    #[test]
    fn serialise_frame_def_uses_names_and_numbers() {
        let info = FrameDefInfo {
            frame_def_id: 5,
            interface_type: IFACE_TYPE_CAN,
            header: FrameHeader::Can {
                can_id: 0x100,
                dlc: 8,
                flags: 0,
            },
            signals: vec![FrameSignalDef {
                signal_id: 0x0001,
                start_bit: 0,
                bit_length: 16,
                byte_order: BYTE_ORDER_BE,
                value_type: VALUE_TYPE_SIGNED,
                quantity: types::QTY_RAW,
                scale: 0.1,
                offset: -40.0,
            }],
        };
        let v = serde_json::to_value(&info).unwrap();
        assert_eq!(v["interface_type"], "CAN");
        assert_eq!(v["header"]["kind"], "can");
        assert_eq!(v["header"]["can_id"], 0x100);
        assert!(v["frame_def_id"].is_number());

        let sig = &v["signals"][0];
        assert_eq!(sig["byte_order"], "be");
        assert_eq!(sig["value_type"], "signed");
        assert!(sig["start_bit"].is_number());
        assert!(sig["bit_length"].is_number());
    }

    #[test]
    fn serialise_frame_header_rs485() {
        let v = serde_json::to_value(FrameHeader::Rs485 { framing_mode: 2 }).unwrap();
        assert_eq!(v["kind"], "rs485");
        assert_eq!(v["framing_mode"], 2);
    }

    fn signal_of(signal_id: u16, bit_length: u16) -> FrameSignalDef {
        FrameSignalDef {
            signal_id,
            start_bit: 0,
            bit_length,
            byte_order: BYTE_ORDER_LE,
            value_type: VALUE_TYPE_UNSIGNED,
            quantity: types::QTY_RAW,
            scale: 1.0,
            offset: 0.0,
        }
    }

    fn can_def_with(signals: Vec<FrameSignalDef>) -> FrameDefInfo {
        FrameDefInfo {
            frame_def_id: 1,
            interface_type: IFACE_TYPE_CAN,
            header: FrameHeader::Can {
                can_id: 0x100,
                dlc: 8,
                flags: 0,
            },
            signals,
        }
    }

    #[test]
    fn a_signal_of_one_to_sixty_four_bits_encodes() {
        for bits in [1, SIGNAL_MAX_BITS] {
            assert!(build_frame_def_add(&can_def_with(vec![signal_of(7, bits)])).is_ok());
        }
    }

    #[test]
    fn a_signal_of_no_bits_or_more_than_sixty_four_is_refused_naming_it() {
        for bits in [0, SIGNAL_MAX_BITS + 1] {
            assert_eq!(
                build_frame_def_add(&can_def_with(vec![signal_of(1, 8), signal_of(7, bits)])),
                Err(Error::SignalBits {
                    signal_id: 7,
                    bit_length: bits
                })
            );
        }
    }

    #[test]
    fn more_signals_than_the_count_byte_holds_are_refused_not_truncated() {
        let fits: Vec<_> = (0..MAX_SIGNALS as u16).map(|id| signal_of(id, 1)).collect();
        let payload = build_frame_def_add(&can_def_with(fits.clone())).unwrap();
        assert_eq!(
            parse_frame_def_resp(&payload).unwrap().signals.len(),
            MAX_SIGNALS
        );
        let mut over = fits;
        over.push(signal_of(MAX_SIGNALS as u16, 1));
        assert_eq!(
            build_frame_def_add(&can_def_with(over)),
            Err(Error::TooManySignals(MAX_SIGNALS + 1))
        );
    }

    #[test]
    fn a_reserved_frame_def_id_is_refused() {
        for id in RESERVED_IDS {
            let mut info = can_def_with(vec![signal_of(1, 8)]);
            info.frame_def_id = id;
            assert_eq!(
                build_frame_def_add(&info),
                Err(Error::ReservedFrameDefId(id))
            );
        }
    }

    #[test]
    fn the_next_available_id_skips_the_user_tag_and_running_out_is_refused() {
        let taken: Vec<_> = (0..types::FRAME_DEF_ID_USER)
            .map(|frame_def_id| FrameDefInfo {
                frame_def_id,
                ..can_def_with(vec![])
            })
            .collect();
        let next = next_available_id(&taken);
        assert_eq!(next, types::FRAME_DEF_ID_DEVICE);
        assert_eq!(
            build_frame_def_add(&FrameDefInfo {
                frame_def_id: next,
                ..can_def_with(vec![])
            }),
            Err(Error::ReservedFrameDefId(next))
        );
    }
}
