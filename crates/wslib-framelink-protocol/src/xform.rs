//! Transformers: signals mapped from one frame definition into another, then
//! functions run over them.
//!
//! XFORM_ADD (0x40):
//!   `transformer_id(u16 LE) source_frame_def_id(u16 LE) source_iface(u8)
//!    dest_frame_def_id(u16 LE) dest_iface(u8) enabled(u8)
//!    num_mappings(u8) [mappings...] num_functions(u8) [functions...]`
//!
//!   Mapping: `src_signal_id(u16 LE) dest_signal_id(u16 LE) transform_type(u8) [params]`
//!     DIRECT  (0x00): no params
//!     SCALE   (0x01): scale(f32 LE) + offset(f32 LE) = 8 bytes
//!     INVERT  (0x02): no params
//!     MASK    (0x03): mask(u32 LE) = 4 bytes
//!
//! XFORM_REMOVE (0x41): `transformer_id(u16 LE)`
//! XFORM_LIST (0x42): empty payload
//! XFORM_ENABLE (0x44): `transformer_id(u16 LE) enabled(u8)`

use crate::Error;
use serde::{Serialize, Serializer};

pub const XFORM_DIRECT: u8 = 0x00;
pub const XFORM_SCALE: u8 = 0x01;
pub const XFORM_INVERT: u8 = 0x02;
pub const XFORM_MASK: u8 = 0x03;

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
#[non_exhaustive]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub enum TransformParams {
    Direct,
    Scale { scale: f32, offset: f32 },
    Invert,
    Mask { mask: u32 },
}

#[derive(Debug, Clone, Serialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub struct SignalMapping {
    pub source_signal_id: u16,
    pub dest_signal_id: u16,
    pub transform: TransformParams,
}

/// The firmware's `fl_gate_op`, serialised as its operator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(
    feature = "ts",
    derive(ts_rs::TS),
    ts(type = r#""!=" | "==" | ">" | "<" | ">=" | "<=""#)
)]
#[repr(u8)]
pub enum GateOp {
    NotEqual = 0x00,
    Equal = 0x01,
    GreaterThan = 0x02,
    LessThan = 0x03,
    GreaterEqual = 0x04,
    LessEqual = 0x05,
}

impl GateOp {
    pub fn from_u8(val: u8) -> Option<Self> {
        match val {
            0x00 => Some(Self::NotEqual),
            0x01 => Some(Self::Equal),
            0x02 => Some(Self::GreaterThan),
            0x03 => Some(Self::LessThan),
            0x04 => Some(Self::GreaterEqual),
            0x05 => Some(Self::LessEqual),
            _ => None,
        }
    }
}

impl std::fmt::Display for GateOp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::NotEqual => "!=",
            Self::Equal => "==",
            Self::GreaterThan => ">",
            Self::LessThan => "<",
            Self::GreaterEqual => ">=",
            Self::LessEqual => "<=",
        })
    }
}

impl Serialize for GateOp {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

fn ser_function_name<S: Serializer>(function_id: &u8, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(function_name(*function_id))
}

pub const FUNC_PALETTE: u8 = 0x10;
pub const FUNC_CLAMP: u8 = 0x11;
pub const FUNC_THRESHOLD: u8 = 0x12;
pub const FUNC_GATE: u8 = 0x13;

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
#[non_exhaustive]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub enum FunctionParams {
    Palette {
        palette_signal_start: u16,
        signal_max: u16,
    },
    Clamp {
        min: u32,
        max: u32,
    },
    Threshold {
        threshold: u32,
        value_above: u32,
        value_below: u32,
    },
    Gate {
        guard_signal_id: u16,
        compare_op: GateOp,
        compare_value: u32,
        fail_value: u32,
    },
}

/// A function a transformer runs after its mappings.
#[derive(Debug, Clone, Serialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub struct XformFunction {
    #[serde(rename = "function", serialize_with = "ser_function_name")]
    #[cfg_attr(feature = "ts", ts(type = "string"))]
    pub function_id: u8,
    pub source_signal_id: u16,
    pub dest_signal_id: u16,
    pub params: FunctionParams,
}

#[derive(Debug, Clone, Serialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub struct TransformerInfo {
    pub transformer_id: u16,
    pub source_frame_def_id: u16,
    pub source_interface: u8,
    pub dest_frame_def_id: u16,
    pub dest_interface: u8,
    pub enabled: bool,
    pub mappings: Vec<SignalMapping>,
    pub functions: Vec<XformFunction>,
}

/// Reads little-endian fields, each refused with `truncated` when short.
pub(crate) struct Reader<'a> {
    buf: &'a [u8],
    pub(crate) pos: usize,
}

impl<'a> Reader<'a> {
    pub(crate) fn new(buf: &'a [u8], pos: usize) -> Self {
        Self { buf, pos }
    }

    pub(crate) fn has_more(&self) -> bool {
        self.pos < self.buf.len()
    }

    fn take<const N: usize>(&mut self, truncated: &'static str) -> Result<[u8; N], Error> {
        let bytes = self
            .buf
            .get(self.pos..self.pos + N)
            .ok_or(Error::InvalidPayload(truncated))?;
        self.pos += N;
        Ok(bytes.try_into().expect("N bytes"))
    }

    pub(crate) fn u8(&mut self, truncated: &'static str) -> Result<u8, Error> {
        Ok(self.take::<1>(truncated)?[0])
    }

    pub(crate) fn u16(&mut self, truncated: &'static str) -> Result<u16, Error> {
        self.take(truncated).map(u16::from_le_bytes)
    }

    pub(crate) fn u32(&mut self, truncated: &'static str) -> Result<u32, Error> {
        self.take(truncated).map(u32::from_le_bytes)
    }

    pub(crate) fn f32(&mut self, truncated: &'static str) -> Result<f32, Error> {
        self.take(truncated).map(f32::from_le_bytes)
    }
}

pub(crate) fn encode_mappings(buf: &mut Vec<u8>, mappings: &[SignalMapping]) {
    buf.push(mappings.len() as u8);
    for m in mappings {
        buf.extend_from_slice(&m.source_signal_id.to_le_bytes());
        buf.extend_from_slice(&m.dest_signal_id.to_le_bytes());
        match &m.transform {
            TransformParams::Direct => buf.push(XFORM_DIRECT),
            TransformParams::Scale { scale, offset } => {
                buf.push(XFORM_SCALE);
                buf.extend_from_slice(&scale.to_le_bytes());
                buf.extend_from_slice(&offset.to_le_bytes());
            }
            TransformParams::Invert => buf.push(XFORM_INVERT),
            TransformParams::Mask { mask } => {
                buf.push(XFORM_MASK);
                buf.extend_from_slice(&mask.to_le_bytes());
            }
        }
    }
}

/// The count byte and the mappings after it.
pub(crate) fn parse_mappings(
    r: &mut Reader,
    truncated: &'static str,
) -> Result<Vec<SignalMapping>, Error> {
    let count = r.u8(truncated)?;
    (0..count)
        .map(|_| {
            let source_signal_id = r.u16(truncated)?;
            let dest_signal_id = r.u16(truncated)?;
            let transform = match r.u8(truncated)? {
                XFORM_DIRECT => TransformParams::Direct,
                XFORM_SCALE => TransformParams::Scale {
                    scale: r.f32("scale params truncated")?,
                    offset: r.f32("scale params truncated")?,
                },
                XFORM_INVERT => TransformParams::Invert,
                XFORM_MASK => TransformParams::Mask {
                    mask: r.u32("mask param truncated")?,
                },
                _ => return Err(Error::InvalidPayload("unknown transform type")),
            };
            Ok(SignalMapping {
                source_signal_id,
                dest_signal_id,
                transform,
            })
        })
        .collect()
}

pub fn build_xform_add(info: &TransformerInfo) -> Vec<u8> {
    let mut buf = Vec::with_capacity(10 + info.mappings.len() * 13);
    buf.extend_from_slice(&info.transformer_id.to_le_bytes());
    buf.extend_from_slice(&info.source_frame_def_id.to_le_bytes());
    buf.push(info.source_interface);
    buf.extend_from_slice(&info.dest_frame_def_id.to_le_bytes());
    buf.push(info.dest_interface);
    buf.push(u8::from(info.enabled));
    encode_mappings(&mut buf, &info.mappings);

    buf.push(info.functions.len() as u8);
    for f in &info.functions {
        buf.push(f.function_id);
        buf.extend_from_slice(&f.source_signal_id.to_le_bytes());
        buf.extend_from_slice(&f.dest_signal_id.to_le_bytes());
        match &f.params {
            FunctionParams::Palette {
                palette_signal_start,
                signal_max,
            } => {
                buf.extend_from_slice(&palette_signal_start.to_le_bytes());
                buf.extend_from_slice(&signal_max.to_le_bytes());
            }
            FunctionParams::Clamp { min, max } => {
                buf.extend_from_slice(&min.to_le_bytes());
                buf.extend_from_slice(&max.to_le_bytes());
            }
            FunctionParams::Threshold {
                threshold,
                value_above,
                value_below,
            } => {
                buf.extend_from_slice(&threshold.to_le_bytes());
                buf.extend_from_slice(&value_above.to_le_bytes());
                buf.extend_from_slice(&value_below.to_le_bytes());
            }
            FunctionParams::Gate {
                guard_signal_id,
                compare_op,
                compare_value,
                fail_value,
            } => {
                buf.extend_from_slice(&guard_signal_id.to_le_bytes());
                buf.push(*compare_op as u8);
                buf.push(0);
                buf.extend_from_slice(&compare_value.to_le_bytes());
                buf.extend_from_slice(&fail_value.to_le_bytes());
            }
        }
    }

    buf
}

pub fn build_xform_remove(transformer_id: u16) -> Vec<u8> {
    transformer_id.to_le_bytes().to_vec()
}

pub fn build_xform_list() -> Vec<u8> {
    Vec::new()
}

pub fn build_xform_enable(transformer_id: u16, enabled: bool) -> Vec<u8> {
    crate::build_enable(transformer_id, enabled)
}

pub fn parse_xform_resp(payload: &[u8]) -> Result<TransformerInfo, Error> {
    const SHORT: &str = "xform resp too short";
    if payload.len() < 10 {
        return Err(Error::InvalidPayload(SHORT));
    }
    let mut r = Reader::new(payload, 0);
    let transformer_id = r.u16(SHORT)?;
    let source_frame_def_id = r.u16(SHORT)?;
    let source_interface = r.u8(SHORT)?;
    let dest_frame_def_id = r.u16(SHORT)?;
    let dest_interface = r.u8(SHORT)?;
    let enabled = r.u8(SHORT)? != 0;
    let mappings = parse_mappings(&mut r, "xform mapping truncated")?;

    let mut functions = Vec::new();
    if r.has_more() {
        for _ in 0..r.u8(SHORT)? {
            functions.push(parse_function(&mut r)?);
        }
    }

    Ok(TransformerInfo {
        transformer_id,
        source_frame_def_id,
        source_interface,
        dest_frame_def_id,
        dest_interface,
        enabled,
        mappings,
        functions,
    })
}

fn parse_function(r: &mut Reader) -> Result<XformFunction, Error> {
    const TRUNCATED: &str = "xform function truncated";
    let function_id = r.u8(TRUNCATED)?;
    let source_signal_id = r.u16(TRUNCATED)?;
    let dest_signal_id = r.u16(TRUNCATED)?;
    let params = match function_id {
        FUNC_PALETTE => {
            const P: &str = "palette params truncated";
            FunctionParams::Palette {
                palette_signal_start: r.u16(P)?,
                signal_max: r.u16(P)?,
            }
        }
        FUNC_CLAMP => {
            const P: &str = "clamp params truncated";
            FunctionParams::Clamp {
                min: r.u32(P)?,
                max: r.u32(P)?,
            }
        }
        FUNC_THRESHOLD => {
            const P: &str = "threshold params truncated";
            FunctionParams::Threshold {
                threshold: r.u32(P)?,
                value_above: r.u32(P)?,
                value_below: r.u32(P)?,
            }
        }
        FUNC_GATE => {
            const P: &str = "gate params truncated";
            if r.pos + 12 > r.buf.len() {
                return Err(Error::InvalidPayload(P));
            }
            let guard_signal_id = r.u16(P)?;
            let compare_op =
                GateOp::from_u8(r.u8(P)?).ok_or(Error::InvalidPayload("unknown gate operator"))?;
            r.u8(P)?;
            FunctionParams::Gate {
                guard_signal_id,
                compare_op,
                compare_value: r.u32(P)?,
                fail_value: r.u32(P)?,
            }
        }
        _ => return Err(Error::InvalidPayload("unknown function type")),
    };
    Ok(XformFunction {
        function_id,
        source_signal_id,
        dest_signal_id,
        params,
    })
}

pub fn transform_type_name(t: u8) -> &'static str {
    match t {
        XFORM_DIRECT => "Direct",
        XFORM_SCALE => "Scale",
        XFORM_INVERT => "Invert",
        XFORM_MASK => "Mask",
        _ => "Unknown",
    }
}

pub fn function_name(id: u8) -> &'static str {
    match id {
        FUNC_PALETTE => "Palette Lookup",
        FUNC_CLAMP => "Clamp",
        FUNC_THRESHOLD => "Threshold",
        FUNC_GATE => "Gate",
        _ => "Unknown",
    }
}

pub fn next_available_id(existing: &[TransformerInfo]) -> u16 {
    crate::next_free_id(existing.iter().map(|x| x.transformer_id))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn next_available_id_empty() {
        assert_eq!(next_available_id(&[]), 0);
    }

    #[test]
    fn build_xform_add_direct() {
        let info = TransformerInfo {
            transformer_id: 1,
            source_frame_def_id: 0x100,
            source_interface: 0,
            dest_frame_def_id: 0x200,
            dest_interface: 1,
            enabled: true,
            mappings: vec![SignalMapping {
                source_signal_id: 0x0010,
                dest_signal_id: 0x0020,
                transform: TransformParams::Direct,
            }],
            functions: vec![],
        };
        let payload = build_xform_add(&info);
        // 10 header + 5 mapping + 1 num_functions
        assert_eq!(payload.len(), 16);
        assert_eq!(payload[9], 1); // num_mappings
    }

    #[test]
    fn build_xform_add_scale() {
        let info = TransformerInfo {
            transformer_id: 2,
            source_frame_def_id: 0x100,
            source_interface: 0,
            dest_frame_def_id: 0x200,
            dest_interface: 1,
            enabled: false,
            mappings: vec![SignalMapping {
                source_signal_id: 0x0010,
                dest_signal_id: 0x0020,
                transform: TransformParams::Scale {
                    scale: 2.5,
                    offset: -1.0,
                },
            }],
            functions: vec![],
        };
        let payload = build_xform_add(&info);
        // 10 header + 5 mapping base + 8 scale params + 1 num_functions
        assert_eq!(payload.len(), 24);
    }

    #[test]
    fn build_xform_add_mask() {
        let info = TransformerInfo {
            transformer_id: 3,
            source_frame_def_id: 0x100,
            source_interface: 0,
            dest_frame_def_id: 0x200,
            dest_interface: 1,
            enabled: true,
            mappings: vec![SignalMapping {
                source_signal_id: 0x0010,
                dest_signal_id: 0x0020,
                transform: TransformParams::Mask { mask: 0xFF00FF00 },
            }],
            functions: vec![],
        };
        let payload = build_xform_add(&info);
        // 10 header + 5 mapping base + 4 mask param + 1 num_functions
        assert_eq!(payload.len(), 20);
    }

    #[test]
    fn xform_remove_payload() {
        let payload = build_xform_remove(42);
        assert_eq!(payload, 42u16.to_le_bytes().to_vec());
    }

    #[test]
    fn xform_enable_payload() {
        let payload = build_xform_enable(7, true);
        assert_eq!(payload.len(), 3);
        assert_eq!(u16::from_le_bytes([payload[0], payload[1]]), 7);
        assert_eq!(payload[2], 1);
    }

    #[test]
    fn parse_xform_resp_roundtrip_direct() {
        let info = TransformerInfo {
            transformer_id: 10,
            source_frame_def_id: 0x100,
            source_interface: 0,
            dest_frame_def_id: 0x200,
            dest_interface: 1,
            enabled: true,
            mappings: vec![
                SignalMapping {
                    source_signal_id: 0x0010,
                    dest_signal_id: 0x0020,
                    transform: TransformParams::Direct,
                },
                SignalMapping {
                    source_signal_id: 0x0011,
                    dest_signal_id: 0x0021,
                    transform: TransformParams::Invert,
                },
            ],
            functions: vec![],
        };
        let payload = build_xform_add(&info);
        let parsed = parse_xform_resp(&payload).unwrap();
        assert_eq!(parsed.transformer_id, 10);
        assert_eq!(parsed.source_frame_def_id, 0x100);
        assert_eq!(parsed.source_interface, 0);
        assert_eq!(parsed.dest_frame_def_id, 0x200);
        assert_eq!(parsed.dest_interface, 1);
        assert!(parsed.enabled);
        assert_eq!(parsed.mappings.len(), 2);
        assert!(matches!(
            parsed.mappings[0].transform,
            TransformParams::Direct
        ));
        assert!(matches!(
            parsed.mappings[1].transform,
            TransformParams::Invert
        ));
    }

    #[test]
    fn parse_xform_resp_roundtrip_scale() {
        let info = TransformerInfo {
            transformer_id: 20,
            source_frame_def_id: 0x300,
            source_interface: 2,
            dest_frame_def_id: 0x400,
            dest_interface: 3,
            enabled: false,
            mappings: vec![SignalMapping {
                source_signal_id: 0x0030,
                dest_signal_id: 0x0040,
                transform: TransformParams::Scale {
                    scale: 0.1,
                    offset: 100.0,
                },
            }],
            functions: vec![],
        };
        let payload = build_xform_add(&info);
        let parsed = parse_xform_resp(&payload).unwrap();
        if let TransformParams::Scale { scale, offset } = &parsed.mappings[0].transform {
            assert!((scale - 0.1).abs() < 1e-6);
            assert!((offset - 100.0).abs() < 1e-6);
        } else {
            panic!("expected Scale transform");
        }
    }

    #[test]
    fn parse_xform_resp_roundtrip_mask() {
        let info = TransformerInfo {
            transformer_id: 30,
            source_frame_def_id: 0x100,
            source_interface: 0,
            dest_frame_def_id: 0x200,
            dest_interface: 1,
            enabled: true,
            mappings: vec![SignalMapping {
                source_signal_id: 0x0050,
                dest_signal_id: 0x0060,
                transform: TransformParams::Mask { mask: 0xDEADBEEF },
            }],
            functions: vec![],
        };
        let payload = build_xform_add(&info);
        let parsed = parse_xform_resp(&payload).unwrap();
        if let TransformParams::Mask { mask } = &parsed.mappings[0].transform {
            assert_eq!(*mask, 0xDEADBEEF);
        } else {
            panic!("expected Mask transform");
        }
    }

    #[test]
    fn parse_xform_resp_roundtrip_with_functions() {
        let info = TransformerInfo {
            transformer_id: 40,
            source_frame_def_id: 0x100,
            source_interface: 1,
            dest_frame_def_id: 0xFFFF,
            dest_interface: 0xFF,
            enabled: true,
            mappings: vec![],
            functions: vec![
                XformFunction {
                    function_id: FUNC_PALETTE,
                    source_signal_id: 0x0010,
                    dest_signal_id: 0xFF14,
                    params: FunctionParams::Palette {
                        palette_signal_start: 0x0200,
                        signal_max: 1000,
                    },
                },
                XformFunction {
                    function_id: FUNC_THRESHOLD,
                    source_signal_id: 0x0020,
                    dest_signal_id: 0xFF1D,
                    params: FunctionParams::Threshold {
                        threshold: 500,
                        value_above: 0xFF00FF00,
                        value_below: 0xFFFF0000,
                    },
                },
            ],
        };
        let payload = build_xform_add(&info);
        let parsed = parse_xform_resp(&payload).unwrap();
        assert_eq!(parsed.transformer_id, 40);
        assert_eq!(parsed.mappings.len(), 0);
        assert_eq!(parsed.functions.len(), 2);

        assert_eq!(parsed.functions[0].function_id, FUNC_PALETTE);
        assert_eq!(parsed.functions[0].source_signal_id, 0x0010);
        assert_eq!(parsed.functions[0].dest_signal_id, 0xFF14);
        if let FunctionParams::Palette {
            palette_signal_start,
            signal_max,
        } = &parsed.functions[0].params
        {
            assert_eq!(*palette_signal_start, 0x0200);
            assert_eq!(*signal_max, 1000);
        } else {
            panic!("expected Palette function");
        }

        assert_eq!(parsed.functions[1].function_id, FUNC_THRESHOLD);
        if let FunctionParams::Threshold {
            threshold,
            value_above,
            value_below,
        } = &parsed.functions[1].params
        {
            assert_eq!(*threshold, 500);
            assert_eq!(*value_above, 0xFF00FF00);
            assert_eq!(*value_below, 0xFFFF0000);
        } else {
            panic!("expected Threshold function");
        }
    }

    #[test]
    fn parse_xform_resp_roundtrip_clamp_function() {
        let info = TransformerInfo {
            transformer_id: 50,
            source_frame_def_id: 0x100,
            source_interface: 0,
            dest_frame_def_id: 0xFFFF,
            dest_interface: 0xFF,
            enabled: true,
            mappings: vec![],
            functions: vec![XformFunction {
                function_id: FUNC_CLAMP,
                source_signal_id: 0x0010,
                dest_signal_id: 0x0010,
                params: FunctionParams::Clamp { min: 100, max: 900 },
            }],
        };
        let payload = build_xform_add(&info);
        let parsed = parse_xform_resp(&payload).unwrap();
        assert_eq!(parsed.functions.len(), 1);
        if let FunctionParams::Clamp { min, max } = &parsed.functions[0].params {
            assert_eq!(*min, 100);
            assert_eq!(*max, 900);
        } else {
            panic!("expected Clamp function");
        }
    }

    #[test]
    fn parse_xform_resp_roundtrip_gate_function() {
        let info = TransformerInfo {
            transformer_id: 60,
            source_frame_def_id: 0xFFFF,
            source_interface: 0xFF,
            dest_frame_def_id: 0xFFFF,
            dest_interface: 0xFF,
            enabled: true,
            mappings: vec![],
            functions: vec![
                XformFunction {
                    function_id: FUNC_PALETTE,
                    source_signal_id: 0xFF37,
                    dest_signal_id: 0xFF18,
                    params: FunctionParams::Palette {
                        palette_signal_start: 0x0220,
                        signal_max: 5000,
                    },
                },
                XformFunction {
                    function_id: FUNC_GATE,
                    source_signal_id: 0xFF18,
                    dest_signal_id: 0xFF18,
                    params: FunctionParams::Gate {
                        guard_signal_id: 0xFF32,
                        compare_op: GateOp::NotEqual,
                        compare_value: 0,
                        fail_value: 0,
                    },
                },
            ],
        };
        let payload = build_xform_add(&info);
        let parsed = parse_xform_resp(&payload).unwrap();
        assert_eq!(parsed.functions.len(), 2);
        assert_eq!(parsed.functions[0].function_id, FUNC_PALETTE);
        assert_eq!(parsed.functions[1].function_id, FUNC_GATE);
        if let FunctionParams::Gate {
            guard_signal_id,
            compare_op,
            compare_value,
            fail_value,
        } = &parsed.functions[1].params
        {
            assert_eq!(*guard_signal_id, 0xFF32);
            assert_eq!(*compare_op, GateOp::NotEqual);
            assert_eq!(*compare_value, 0);
            assert_eq!(*fail_value, 0);
        } else {
            panic!("expected Gate function");
        }
    }

    #[test]
    fn parse_xform_resp_too_short() {
        assert!(parse_xform_resp(&[0; 9]).is_err());
    }

    #[test]
    fn parse_xform_resp_truncated_mapping() {
        // Valid header with 1 mapping claimed but no mapping data
        let mut payload = vec![0; 10];
        payload[9] = 1; // num_mappings = 1
        assert!(parse_xform_resp(&payload).is_err());
    }

    #[test]
    fn serialise_transform_params_internally_tagged() {
        let v = serde_json::to_value(TransformParams::Direct).unwrap();
        assert_eq!(v["kind"], "direct");

        let v = serde_json::to_value(TransformParams::Scale {
            scale: 2.0,
            offset: -1.0,
        })
        .unwrap();
        assert_eq!(v["kind"], "scale");
        assert_eq!(v["scale"], 2.0);
        assert_eq!(v["offset"], -1.0);
    }

    #[test]
    fn serialise_xform_function_names_and_gate_op() {
        let f = XformFunction {
            function_id: FUNC_GATE,
            source_signal_id: 0x18,
            dest_signal_id: 0x18,
            params: FunctionParams::Gate {
                guard_signal_id: 0x32,
                compare_op: GateOp::GreaterEqual,
                compare_value: 10,
                fail_value: 0,
            },
        };
        let v = serde_json::to_value(&f).unwrap();
        // Top-level field renders the human function name.
        assert_eq!(v["function"], "Gate");
        assert!(v["source_signal_id"].is_number());
        // Nested params carry the lowercase `kind` discriminant plus the operator symbol.
        assert_eq!(v["params"]["kind"], "gate");
        assert_eq!(v["params"]["compare_op"], ">=");
        assert!(v["params"]["compare_value"].is_number());
    }
}
