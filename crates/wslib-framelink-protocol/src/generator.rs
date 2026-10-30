//! Generators: frames a device sends on its own, filled from signals.
//!
//! GEN_ADD (0x48):
//!   `generator_id(u16 LE) frame_def_id(u16 LE) interface_index(u8)
//!    period_ms(u32 LE) trigger_type(u8) enabled(u8)
//!    num_mappings(u8) mappings...`
//!
//! A mapping is a transformer's: `src_signal_id(u16 LE) dest_signal_id(u16 LE)
//! transform_type(u8) [params]`.
//!
//! GEN_REMOVE (0x49): `generator_id(u16 LE)`
//! GEN_LIST (0x4A): empty payload
//! GEN_ENABLE (0x4C): `generator_id(u16 LE) enabled(u8)`

use crate::Error;
use crate::xform::{self, Reader, SignalMapping};
use serde::{Serialize, Serializer};

pub const TRIGGER_PERIODIC: u8 = 0x00;
pub const TRIGGER_ON_CHANGE: u8 = 0x01;
pub const TRIGGER_ONE_SHOT: u8 = 0x02;

#[derive(Debug, Clone, Serialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub struct GeneratorInfo {
    pub generator_id: u16,
    pub frame_def_id: u16,
    pub interface_index: u8,
    pub period_ms: u32,
    #[serde(rename = "trigger", serialize_with = "ser_trigger_type_name")]
    #[cfg_attr(feature = "ts", ts(type = "string"))]
    pub trigger_type: u8,
    pub enabled: bool,
    pub mappings: Vec<SignalMapping>,
}

fn ser_trigger_type_name<S: Serializer>(trigger_type: &u8, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(trigger_type_name(*trigger_type))
}

pub fn build_gen_add(info: &GeneratorInfo) -> Vec<u8> {
    let mut buf = Vec::with_capacity(12 + info.mappings.len() * 13);
    buf.extend_from_slice(&info.generator_id.to_le_bytes());
    buf.extend_from_slice(&info.frame_def_id.to_le_bytes());
    buf.push(info.interface_index);
    buf.extend_from_slice(&info.period_ms.to_le_bytes());
    buf.push(info.trigger_type);
    buf.push(u8::from(info.enabled));
    xform::encode_mappings(&mut buf, &info.mappings);
    buf
}

pub fn build_gen_remove(generator_id: u16) -> Vec<u8> {
    generator_id.to_le_bytes().to_vec()
}

pub fn build_gen_list() -> Vec<u8> {
    Vec::new()
}

pub fn build_gen_enable(generator_id: u16, enabled: bool) -> Vec<u8> {
    crate::build_enable(generator_id, enabled)
}

pub fn parse_gen_resp(payload: &[u8]) -> Result<GeneratorInfo, Error> {
    const SHORT: &str = "gen resp too short";
    if payload.len() < 12 {
        return Err(Error::InvalidPayload(SHORT));
    }
    let mut r = Reader::new(payload, 0);
    Ok(GeneratorInfo {
        generator_id: r.u16(SHORT)?,
        frame_def_id: r.u16(SHORT)?,
        interface_index: r.u8(SHORT)?,
        period_ms: r.u32(SHORT)?,
        trigger_type: r.u8(SHORT)?,
        enabled: r.u8(SHORT)? != 0,
        mappings: xform::parse_mappings(&mut r, "gen mapping truncated")?,
    })
}

pub fn trigger_type_name(t: u8) -> &'static str {
    match t {
        TRIGGER_PERIODIC => "Periodic",
        TRIGGER_ON_CHANGE => "On Change",
        TRIGGER_ONE_SHOT => "One Shot",
        _ => "Unknown",
    }
}

pub fn next_available_id(existing: &[GeneratorInfo]) -> u16 {
    crate::next_free_id(existing.iter().map(|g| g.generator_id))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xform::TransformParams;

    #[test]
    fn next_available_id_empty() {
        assert_eq!(next_available_id(&[]), 0);
    }

    #[test]
    fn build_gen_add_no_mappings() {
        let info = GeneratorInfo {
            generator_id: 1,
            frame_def_id: 0x100,
            interface_index: 0,
            period_ms: 100,
            trigger_type: TRIGGER_PERIODIC,
            enabled: true,
            mappings: vec![],
        };
        let payload = build_gen_add(&info);
        assert_eq!(payload.len(), 12);
        assert_eq!(u16::from_le_bytes([payload[0], payload[1]]), 1);
        assert_eq!(u16::from_le_bytes([payload[2], payload[3]]), 0x100);
        assert_eq!(payload[4], 0);
        assert_eq!(
            u32::from_le_bytes([payload[5], payload[6], payload[7], payload[8]]),
            100
        );
        assert_eq!(payload[9], TRIGGER_PERIODIC);
        assert_eq!(payload[10], 1);
        assert_eq!(payload[11], 0); // num_mappings
    }

    #[test]
    fn build_gen_add_with_mappings() {
        let info = GeneratorInfo {
            generator_id: 5,
            frame_def_id: 0x200,
            interface_index: 1,
            period_ms: 500,
            trigger_type: TRIGGER_PERIODIC,
            enabled: true,
            mappings: vec![
                SignalMapping {
                    source_signal_id: 0xFF01,
                    dest_signal_id: 0x0001,
                    transform: TransformParams::Direct,
                },
                SignalMapping {
                    source_signal_id: 0xFF02,
                    dest_signal_id: 0x0002,
                    transform: TransformParams::Scale {
                        scale: 2.0,
                        offset: 1.0,
                    },
                },
            ],
        };
        let payload = build_gen_add(&info);
        assert_eq!(payload[11], 2); // num_mappings
        let parsed = parse_gen_resp(&payload).unwrap();
        assert_eq!(parsed.mappings.len(), 2);
        assert_eq!(parsed.mappings[0].source_signal_id, 0xFF01);
        assert_eq!(parsed.mappings[0].dest_signal_id, 0x0001);
        assert!(matches!(
            parsed.mappings[0].transform,
            TransformParams::Direct
        ));
        assert_eq!(parsed.mappings[1].source_signal_id, 0xFF02);
        assert!(matches!(
            parsed.mappings[1].transform,
            TransformParams::Scale { .. }
        ));
    }

    #[test]
    fn gen_remove_payload() {
        let payload = build_gen_remove(42);
        assert_eq!(payload, 42u16.to_le_bytes().to_vec());
    }

    #[test]
    fn gen_enable_payload() {
        let payload = build_gen_enable(7, true);
        assert_eq!(payload.len(), 3);
        assert_eq!(u16::from_le_bytes([payload[0], payload[1]]), 7);
        assert_eq!(payload[2], 1);
    }

    #[test]
    fn parse_gen_resp_roundtrip() {
        let info = GeneratorInfo {
            generator_id: 10,
            frame_def_id: 0x300,
            interface_index: 2,
            period_ms: 50000,
            trigger_type: TRIGGER_PERIODIC,
            enabled: true,
            mappings: vec![],
        };
        let payload = build_gen_add(&info);
        let parsed = parse_gen_resp(&payload).unwrap();
        assert_eq!(parsed.generator_id, 10);
        assert_eq!(parsed.frame_def_id, 0x300);
        assert_eq!(parsed.interface_index, 2);
        assert_eq!(parsed.period_ms, 50000);
        assert_eq!(parsed.trigger_type, TRIGGER_PERIODIC);
        assert!(parsed.enabled);
        assert!(parsed.mappings.is_empty());
    }

    #[test]
    fn parse_gen_resp_too_short() {
        assert!(parse_gen_resp(&[0; 11]).is_err());
    }

    #[test]
    fn trigger_type_names() {
        assert_eq!(trigger_type_name(TRIGGER_PERIODIC), "Periodic");
        assert_eq!(trigger_type_name(TRIGGER_ON_CHANGE), "On Change");
        assert_eq!(trigger_type_name(TRIGGER_ONE_SHOT), "One Shot");
        assert_eq!(trigger_type_name(0xFF), "Unknown");
    }

    #[test]
    fn serialise_generator_info_uses_names_and_numbers() {
        let info = GeneratorInfo {
            generator_id: 1,
            frame_def_id: 0x100,
            interface_index: 0,
            period_ms: 100,
            trigger_type: TRIGGER_PERIODIC,
            enabled: true,
            mappings: vec![SignalMapping {
                source_signal_id: 0xFF01,
                dest_signal_id: 0x0001,
                transform: TransformParams::Direct,
            }],
        };
        let v = serde_json::to_value(&info).unwrap();
        assert_eq!(v["trigger"], "Periodic");
        assert!(v["period_ms"].is_number());
        assert!(v["generator_id"].is_number());
        assert_eq!(v["mappings"][0]["transform"]["kind"], "direct");
    }
}
