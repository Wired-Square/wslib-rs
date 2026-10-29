//! A Modbus manifest: a TOML register map, parsed, decoded and encoded.

use std::collections::BTreeMap;

use rust_decimal::prelude::*;
use serde::{Deserialize, Serialize};

use crate::protocol::{coils_to_bytes, registers_to_bytes};
use crate::{DisplayHint, Endianness, RegisterType, SignalFormat, WriteBank};
use wslib_bits::{BitOrder, extract_field, scale};

/// Poll interval used when neither the frame nor `[meta.modbus]` sets one.
const DEFAULT_INTERVAL_MS: u64 = 5000;

#[derive(Debug, thiserror::Error)]
pub enum ManifestError {
    #[error("manifest is not valid TOML: {0}")]
    Toml(#[from] toml::de::Error),
    #[error("manifest defines no [frame.modbus.*] frames")]
    NoFrames,
    #[error(
        "frame '{0}' has no register_number and its name is not a register address (decimal or 0x-hex)"
    )]
    BadRegister(String),
}

/// A single decoded field within a frame's register block.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub struct ModbusSignal {
    pub name: String,
    pub start_bit: u32,
    pub bit_length: u32,
    #[serde(default)]
    pub factor: Option<f64>,
    #[serde(default)]
    pub offset: Option<f64>,
    #[serde(default)]
    pub unit: Option<String>,
    #[serde(default)]
    pub signed: bool,
    /// Any format but `enum` is text-like, which [`decode_frame`] skips.
    #[serde(default)]
    pub format: Option<SignalFormat>,
    /// Overrides `[meta.modbus].default_byte_order`; also read as `endianness`.
    #[serde(default, alias = "endianness")]
    pub byte_order: Option<Endianness>,
    /// Overrides `[meta.modbus].default_word_order`.
    #[serde(default)]
    pub word_order: Option<Endianness>,
    /// Register value (as a string) to label, from the signal's `enum` table.
    #[serde(default, rename = "enum")]
    pub enum_map: Option<BTreeMap<String, String>>,
    /// Read leniently: a malformed hint is `None`, so it can't fail the parse.
    #[serde(
        default,
        deserialize_with = "lenient_display",
        skip_serializing_if = "Option::is_none"
    )]
    pub display: Option<DisplayHint>,
}

fn lenient_display<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<DisplayHint>, D::Error> {
    serde_json::Value::deserialize(deserializer).map(DisplayHint::from_authored)
}

impl ModbusSignal {
    /// Whether the signal has no `format`, so decodes to a number.
    pub fn is_numeric(&self) -> bool {
        self.format.is_none()
    }

    /// Text-like formats, which the decoder skips; `enum` still decodes.
    fn is_string_format(&self) -> bool {
        matches!(
            self.format,
            Some(
                SignalFormat::Ascii
                    | SignalFormat::Utf8
                    | SignalFormat::Hex
                    | SignalFormat::UnixTime
                    | SignalFormat::Other
            )
        )
    }

    /// The register value an `enum` label names.
    fn enum_value(&self, name: &str) -> Option<i128> {
        self.enum_map
            .as_ref()?
            .iter()
            .find(|(_, label)| label.as_str() == name)
            .and_then(|(value, _)| value.parse::<i128>().ok())
    }
}

/// One Modbus read: a register or coil block and the signals decoded from it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub struct ModbusFrame {
    /// The `[frame.modbus.<name>]` table key.
    pub name: String,
    pub register_number: u16,
    pub register_type: RegisterType,
    /// Registers or coils to read.
    pub length: u16,
    /// The frame's `interval_ms`, else `[meta.modbus].default_interval`, else 5 s.
    pub interval_ms: u64,
    /// The poll schedule skips a frame with `disabled = true`;
    /// [`set_frame_disabled`] writes it.
    pub disabled: bool,
    /// The name of the `[node.<name>]` table whose `device_address` matches.
    pub node: Option<String>,
    /// The frame's `node_address`, else `[meta.modbus].device_address`, else 1.
    pub device_address: u8,
    pub signals: Vec<ModbusSignal>,
}

/// `[meta.modbus]`: connection and decoding defaults.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub struct ModbusMeta {
    #[serde(default = "default_device_address")]
    pub device_address: u8,
    /// 0 for protocol addresses, 1 for traditional prefixed ones (4xxxx holding).
    #[serde(default)]
    pub register_base: u8,
    #[serde(default, rename = "default_interval")]
    pub default_interval_ms: Option<u64>,
    #[serde(default)]
    pub default_byte_order: Option<Endianness>,
    #[serde(default)]
    pub default_word_order: Option<Endianness>,
}

impl Default for ModbusMeta {
    fn default() -> Self {
        Self {
            device_address: 1,
            register_base: 0,
            default_interval_ms: None,
            default_byte_order: None,
            default_word_order: None,
        }
    }
}

/// A parsed manifest: its defaults and the frames to poll.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub struct ModbusManifest {
    pub meta: ModbusMeta,
    pub frames: Vec<ModbusFrame>,
}

impl ModbusManifest {
    /// Parse a manifest; one with no `[frame.modbus.*]` frame is an error.
    pub fn parse(text: &str) -> Result<Self, ManifestError> {
        let raw: RawManifest = toml::from_str(text)?;
        let meta = raw.meta.modbus;
        let default_interval = meta.default_interval_ms.unwrap_or(DEFAULT_INTERVAL_MS);

        let addr_to_name: BTreeMap<u8, &str> = raw
            .node
            .iter()
            .filter_map(|(name, n)| n.device_address.map(|a| (a, name.as_str())))
            .collect();
        let legacy_address = meta.device_address;

        let frames: Vec<ModbusFrame> = raw
            .frame
            .modbus
            .into_iter()
            .map(|(name, f)| {
                // A numeric table key stands in for `register_number`.
                let register_number = match f.register_number {
                    Some(r) => r,
                    None => parse_register_key(&name)
                        .ok_or_else(|| ManifestError::BadRegister(name.clone()))?,
                };
                // Frame-level decoding fields without signals make one signal.
                let signals: Vec<ModbusSignal> = if f.signals.is_empty() {
                    synth_frame_signal(&name, &f).into_iter().collect()
                } else {
                    f.signals
                };
                // A signal that can't be laid out is skipped, as `validate` reports.
                let signals = signals
                    .into_iter()
                    .filter(|s| {
                        layout_fits(
                            f.register_type,
                            !s.is_string_format(),
                            s.start_bit.into(),
                            s.bit_length.into(),
                        )
                    })
                    .collect();
                let device_address = f.node_address.unwrap_or(legacy_address);
                Ok(ModbusFrame {
                    name,
                    register_number,
                    register_type: f.register_type,
                    length: f.length,
                    interval_ms: f
                        .interval_ms
                        .or_else(|| f.tx.and_then(|t| t.interval_ms))
                        .or(f.tx_interval_ms)
                        .unwrap_or(default_interval),
                    disabled: f.disabled,
                    node: addr_to_name.get(&device_address).map(|s| s.to_string()),
                    device_address,
                    signals,
                })
            })
            .collect::<Result<Vec<ModbusFrame>, ManifestError>>()?;

        if frames.is_empty() {
            return Err(ManifestError::NoFrames);
        }
        Ok(Self { meta, frames })
    }

    /// A frame's 0-based protocol start address, with `register_base` applied.
    pub fn protocol_address(&self, frame: &ModbusFrame) -> u16 {
        if self.meta.register_base != 1 {
            return frame.register_number;
        }
        let prefix = frame.register_type.base_one_prefix() as u16;
        frame.register_number.saturating_sub(prefix)
    }

    /// A signal by name in a writable (holding or coil) frame.
    pub fn find_write_signal(&self, name: &str) -> Option<(&ModbusFrame, &ModbusSignal)> {
        self.frames
            .iter()
            .filter(|f| f.register_type.is_writable())
            .find_map(|f| f.signals.iter().find(|s| s.name == name).map(|s| (f, s)))
    }

    /// Each writable signal's name and 0-based address in its bank, one per
    /// name, in address order.
    pub fn write_signal_options(&self) -> Vec<(String, u16)> {
        let mut out: Vec<(String, u16)> = Vec::new();
        for f in self.frames.iter().filter(|f| f.register_type.is_writable()) {
            let base = self.protocol_address(f);
            for s in &f.signals {
                let offset = f.register_type.address_offset(s.start_bit);
                out.push((s.name.clone(), base.saturating_add(offset as u16)));
            }
        }
        out.sort_by(|a, b| a.0.cmp(&b.0));
        out.dedup_by(|a, b| a.0 == b.0);
        out.sort_by_key(|(_, reg)| *reg);
        out
    }

    /// Each writable signal with an `enum` map, and its labels in value order.
    pub fn write_signal_enums(&self) -> Vec<(String, Vec<(String, i64)>)> {
        let mut out = Vec::new();
        for f in self.frames.iter().filter(|f| f.register_type.is_writable()) {
            for s in &f.signals {
                let Some(em) = &s.enum_map else { continue };
                let mut entries: Vec<(String, i64)> = em
                    .iter()
                    .filter_map(|(v, label)| v.parse::<i64>().ok().map(|n| (label.clone(), n)))
                    .collect();
                if entries.is_empty() {
                    continue;
                }
                entries.sort_by_key(|(_, v)| *v);
                out.push((s.name.clone(), entries));
            }
        }
        out
    }
}

/// One register's or coil's worth of a write: `mask` marks the bits it owns
/// (`0xFFFF` a whole register, `1` a coil); a partly owned register is written
/// read-modify-write.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[non_exhaustive]
pub struct ModbusWrite {
    #[serde(default)]
    pub bank: WriteBank,
    pub address: u16,
    pub value: u16,
    #[serde(default = "full_register_mask")]
    pub mask: u16,
}

impl ModbusWrite {
    pub fn holding(address: u16, value: u16, mask: u16) -> Self {
        Self {
            bank: WriteBank::Holding,
            address,
            value,
            mask,
        }
    }

    pub fn coil(address: u16, on: bool) -> Self {
        Self {
            bank: WriteBank::Coil,
            address,
            value: on.into(),
            mask: 1,
        }
    }
}

fn full_register_mask() -> u16 {
    0xFFFF
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum EncodeError {
    #[error("signal '{0}' is in a read-only bank (input/discrete)")]
    NotWritable(String),
    #[error(
        "signal '{name}' has an unsupported write layout (start_bit {start_bit}, bit_length {bit_length}): whole 16 to 64-bit registers, a field within one register, or 1 to 64 coils"
    )]
    UnsupportedLayout {
        name: String,
        start_bit: u32,
        bit_length: u32,
    },
    #[error("signal '{name}' has no enum value for '{value}'")]
    UnknownEnumName { name: String, value: String },
    #[error("signal '{name}' can't be written a value that isn't a finite number")]
    NotFinite { name: String },
    #[error("signal '{name}' can't be written raw value {raw}: the field holds {min} to {max}")]
    OutOfRange {
        name: String,
        raw: i128,
        min: i128,
        max: i128,
    },
}

/// The writes that set a signal to `value`, one per register or coil: the
/// inverse of [`decode_frame`]. Layouts other than whole 16 to 64-bit registers,
/// a field within one register, or 1 to 64 coils are an error, as is a value
/// the field can't hold once unscaled and rounded.
pub fn encode_signal(
    manifest: &ModbusManifest,
    frame: &ModbusFrame,
    signal: &ModbusSignal,
    value: f64,
) -> Result<Vec<ModbusWrite>, EncodeError> {
    let raw = scale_to_raw(signal, value).ok_or_else(|| EncodeError::NotFinite {
        name: signal.name.clone(),
    })?;
    encode_raw(manifest, frame, signal, raw)
}

/// The writes that set a signal to the value its `enum` map gives `name`.
pub fn encode_enum(
    manifest: &ModbusManifest,
    frame: &ModbusFrame,
    signal: &ModbusSignal,
    name: &str,
) -> Result<Vec<ModbusWrite>, EncodeError> {
    let value = signal
        .enum_value(name)
        .ok_or_else(|| EncodeError::UnknownEnumName {
            name: signal.name.clone(),
            value: name.to_string(),
        })?;
    encode_raw(manifest, frame, signal, value)
}

/// `value` unscaled and rounded, or `None` when it isn't finite.
fn scale_to_raw(signal: &ModbusSignal, value: f64) -> Option<i128> {
    let factor = match signal.factor {
        Some(f) if f != 0.0 => f,
        _ => 1.0,
    };
    let raw = ((value - signal.offset.unwrap_or(0.0)) / factor).round();
    raw.is_finite().then_some(raw as i128)
}

fn encode_raw(
    manifest: &ModbusManifest,
    frame: &ModbusFrame,
    signal: &ModbusSignal,
    raw: i128,
) -> Result<Vec<ModbusWrite>, EncodeError> {
    let Some(bank) = frame.register_type.write_bank() else {
        return Err(EncodeError::NotWritable(signal.name.clone()));
    };
    let (start, len) = (signal.start_bit, signal.bit_length);
    let unsupported = || EncodeError::UnsupportedLayout {
        name: signal.name.clone(),
        start_bit: start,
        bit_length: len,
    };
    if !layout_fits(frame.register_type, true, start.into(), len.into()) {
        return Err(unsupported());
    }
    let (min, max) = if signal.signed {
        (-(1i128 << (len - 1)), (1i128 << (len - 1)) - 1)
    } else {
        (0, (1i128 << len) - 1)
    };
    if !(min..=max).contains(&raw) {
        return Err(EncodeError::OutOfRange {
            name: signal.name.clone(),
            raw,
            min,
            max,
        });
    }
    let raw_bits = (raw as u128) & ((1u128 << len) - 1);
    let base = manifest.protocol_address(frame);

    if bank == WriteBank::Coil {
        return Ok((0..len)
            .map(|i| {
                let address = base.saturating_add((start + i) as u16);
                ModbusWrite::coil(address, (raw_bits >> i) & 1 == 1)
            })
            .collect());
    }

    let aligned = start.is_multiple_of(16) && len.is_multiple_of(16);
    let within_one = start / 16 == (start + len - 1) / 16;
    if !(aligned || within_one) {
        return Err(unsupported());
    }
    let order = BitOrder::Registers {
        endianness: manifest.meta.default_byte_order.unwrap_or(Endianness::Big),
        word_order: manifest.meta.default_word_order,
    }
    .with_overrides(signal.byte_order, signal.word_order);
    let mut registers: BTreeMap<u16, (u16, u16)> = BTreeMap::new();
    for (bit, position) in field_positions(start, len, order).into_iter().enumerate() {
        let register = (position / 16) as u16;
        let shift = if (position / 8).is_multiple_of(2) {
            8
        } else {
            0
        } + position % 8;
        let (value, mask) = registers.entry(register).or_default();
        *mask |= 1 << shift;
        *value |= (((raw_bits >> bit) & 1) as u16) << shift;
    }
    Ok(registers
        .into_iter()
        .map(|(register, (value, mask))| {
            ModbusWrite::holding(base.saturating_add(register), value, mask)
        })
        .collect())
}

/// Where each bit of a field sits in a register block, least significant
/// first, as `byte * 8 + bit` with bit 0 the byte's least significant: the
/// inverse of [`extract_field`].
fn field_positions(start: u32, len: u32, order: BitOrder) -> Vec<u32> {
    let endianness = order.endianness();
    let swapped = matches!(
        order,
        BitOrder::Registers {
            word_order: Some(Endianness::Little),
            ..
        }
    ) && len > 16;
    let first_byte = start / 8;
    let words = len.div_ceil(8).div_ceil(2);
    let unswap = |byte: u32| {
        let offset = byte - first_byte;
        if swapped && offset < 2 * words {
            first_byte + 2 * (words - 1 - offset / 2) + offset % 2
        } else {
            byte
        }
    };
    (0..len)
        .map(|bit| {
            let position = match endianness {
                Endianness::Big => {
                    let walked = start + len - 1 - bit;
                    walked / 8 * 8 + 7 - walked % 8
                }
                Endianness::Little => start + bit,
            };
            unswap(position / 8) * 8 + position % 8
        })
        .collect()
}

/// Whether a signal can be read and written: 1 to 64 bits when `numeric`, and
/// within a bank's 65 536 addresses.
pub(crate) fn layout_fits(bank: RegisterType, numeric: bool, start: i64, len: i64) -> bool {
    let span = i64::from(bank.bits_per_address()) * 65_536;
    len >= 1 && (!numeric || len <= 64) && start >= 0 && start + len <= span
}

/// Per-address writes with bit fields of one target merged, in first-occurrence
/// order; `Err` when two claim the same bits. A coil and a register at one
/// number are different targets.
pub fn merge_register_writes(writes: Vec<ModbusWrite>) -> Result<Vec<ModbusWrite>, String> {
    let mut out: Vec<ModbusWrite> = Vec::with_capacity(writes.len());
    for w in writes {
        if let Some(existing) = out
            .iter_mut()
            .find(|e| (e.bank, e.address) == (w.bank, w.address))
        {
            if existing.mask & w.mask != 0 {
                return Err(format!(
                    "{} {} written by overlapping commands",
                    w.bank.noun(),
                    w.address
                ));
            }
            existing.value |= w.value & w.mask;
            existing.mask |= w.mask;
        } else {
            out.push(w);
        }
    }
    Ok(out)
}

/// As [`merge_register_writes`], but a later write wins the bits it owns.
pub fn overlay_register_writes(writes: Vec<ModbusWrite>) -> Vec<ModbusWrite> {
    let mut out: Vec<ModbusWrite> = Vec::with_capacity(writes.len());
    for w in writes {
        if let Some(existing) = out
            .iter_mut()
            .find(|e| (e.bank, e.address) == (w.bank, w.address))
        {
            existing.value = (existing.value & !w.mask) | (w.value & w.mask);
            existing.mask |= w.mask;
        } else {
            out.push(w);
        }
    }
    out
}

/// Writes split into runs of ascending contiguous addresses in one bank, in
/// order, each run one request. Expects merged writes.
pub fn group_contiguous(writes: &[ModbusWrite]) -> Vec<Vec<ModbusWrite>> {
    let mut runs: Vec<Vec<ModbusWrite>> = Vec::new();
    for &w in writes {
        match runs.last_mut() {
            Some(run) if continues(run.last().unwrap(), &w) => run.push(w),
            _ => runs.push(vec![w]),
        }
    }
    runs
}

fn continues(last: &ModbusWrite, next: &ModbusWrite) -> bool {
    last.bank == next.bank && last.address.checked_add(1) == Some(next.address)
}

/// The manifest with a frame's `disabled` key set or removed, comments and
/// formatting kept; `Err` for invalid TOML or a missing frame.
pub fn set_frame_disabled(text: &str, frame: &str, disabled: bool) -> Result<String, String> {
    let mut doc = text
        .parse::<toml_edit::DocumentMut>()
        .map_err(|e| format!("manifest is not valid TOML: {e}"))?;
    let frame_tbl = doc
        .get_mut("frame")
        .and_then(|f| f.get_mut("modbus"))
        .and_then(|m| m.as_table_like_mut())
        .and_then(|m| m.get_mut(frame))
        .and_then(|f| f.as_table_like_mut())
        .ok_or_else(|| format!("manifest has no frame '{frame}'"))?;
    if disabled {
        frame_tbl.insert("disabled", toml_edit::value(true));
    } else {
        frame_tbl.remove("disabled");
    }
    Ok(doc.to_string())
}

fn decode_signals(signals: &[ModbusSignal], bytes: &[u8], order: BitOrder) -> Vec<DecodedSignal> {
    signals
        .iter()
        .filter(|sig| !sig.is_string_format())
        .filter_map(|sig| {
            let order = order.with_overrides(sig.byte_order, sig.word_order);
            let raw = extract_field(bytes, sig.start_bit, sig.bit_length, order, sig.signed);
            Some(DecodedSignal {
                name: sig.name.clone(),
                value: scale(raw, sig.factor, sig.offset)?,
                unit: sig.unit.clone(),
            })
        })
        .collect()
}

/// Every numeric signal in an input or holding frame, from its registers;
/// text-like formats and values that can't be scaled are skipped.
pub fn decode_frame(frame: &ModbusFrame, regs: &[u16], meta: &ModbusMeta) -> Vec<DecodedSignal> {
    decode_signals(
        &frame.signals,
        &registers_to_bytes(regs),
        BitOrder::Registers {
            endianness: meta.default_byte_order.unwrap_or(Endianness::Big),
            word_order: meta.default_word_order,
        },
    )
}

/// Every numeric signal in a coil or discrete frame, one `bool` per coil; the
/// lowest coil is the least significant bit, and missing coils read as zero.
pub fn decode_coil_frame(frame: &ModbusFrame, coils: &[bool]) -> Vec<DecodedSignal> {
    decode_signals(&frame.signals, &coils_to_bytes(coils), BitOrder::Coils)
}

/// A scaled signal value decoded from a register block.
#[derive(Debug, Clone, PartialEq)]
pub struct DecodedSignal {
    pub name: String,
    /// Exact, so `3374 × 0.1` is `337.4`.
    pub value: Decimal,
    pub unit: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct RawManifest {
    #[serde(default)]
    meta: RawMeta,
    #[serde(default)]
    frame: RawFrames,
    #[serde(default)]
    node: BTreeMap<String, RawNode>,
}

#[derive(Debug, Default, Deserialize)]
struct RawNode {
    #[serde(default)]
    device_address: Option<u8>,
}

#[derive(Debug, Default, Deserialize)]
struct RawMeta {
    #[serde(default)]
    modbus: ModbusMeta,
}

fn default_device_address() -> u8 {
    1
}

#[derive(Debug, Default, Deserialize)]
struct RawFrames {
    #[serde(default)]
    modbus: BTreeMap<String, RawFrame>,
}

#[derive(Debug, Deserialize)]
struct RawFrame {
    /// Absent, the register is the table key.
    #[serde(default)]
    register_number: Option<u16>,
    #[serde(default)]
    register_type: RegisterType,
    #[serde(default = "default_length")]
    length: u16,
    /// Also read from the legacy `[tx]` table.
    #[serde(default, alias = "interval")]
    interval_ms: Option<u64>,
    #[serde(default)]
    tx: Option<RawTx>,
    #[serde(default)]
    tx_interval_ms: Option<u64>,
    #[serde(default)]
    disabled: bool,
    #[serde(default)]
    node_address: Option<u8>,
    #[serde(default)]
    signals: Vec<ModbusSignal>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    format: Option<SignalFormat>,
    #[serde(default)]
    factor: Option<f64>,
    #[serde(default)]
    offset: Option<f64>,
    #[serde(default)]
    unit: Option<String>,
    #[serde(default)]
    signed: Option<bool>,
    #[serde(default, rename = "enum")]
    enum_map: Option<BTreeMap<String, String>>,
}

fn default_length() -> u16 {
    1
}

#[derive(Debug, Deserialize)]
struct RawTx {
    #[serde(default, alias = "interval")]
    interval_ms: Option<u64>,
}

/// A frame's table key as a register address, decimal or `0x` hex.
fn parse_register_key(key: &str) -> Option<u16> {
    let k = key.trim();
    match k.strip_prefix("0x").or_else(|| k.strip_prefix("0X")) {
        Some(hex) => u16::from_str_radix(hex, 16).ok(),
        None => k.parse::<u16>().ok(),
    }
}

/// The one signal a frame's own decoding fields make, spanning its block.
fn synth_frame_signal(key: &str, f: &RawFrame) -> Option<ModbusSignal> {
    let has_fields = f.name.is_some()
        || f.format.is_some()
        || f.factor.is_some()
        || f.offset.is_some()
        || f.unit.is_some()
        || f.signed.is_some()
        || f.enum_map.is_some();
    if !has_fields {
        return None;
    }
    Some(ModbusSignal {
        name: f.name.clone().unwrap_or_else(|| key.to_string()),
        start_bit: 0,
        bit_length: f.register_type.bits_per_address() * f.length as u32,
        factor: f.factor,
        offset: f.offset,
        unit: f.unit.clone(),
        signed: f.signed.unwrap_or(false),
        format: f.format,
        byte_order: None,
        word_order: None,
        enum_map: f.enum_map.clone(),
        display: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rust_decimal_macros::dec;

    const SUNGROW: &str = include_str!("testdata/sungrow_shx.toml");

    fn parse_fixture() -> ModbusManifest {
        ModbusManifest::parse(SUNGROW).expect("fixture parses")
    }

    fn frame<'a>(m: &'a ModbusManifest, name: &str) -> &'a ModbusFrame {
        m.frames
            .iter()
            .find(|f| f.name == name)
            .unwrap_or_else(|| panic!("frame {name} present"))
    }

    fn signal<'a>(f: &'a ModbusFrame, name: &str) -> &'a ModbusSignal {
        f.signals
            .iter()
            .find(|s| s.name == name)
            .unwrap_or_else(|| panic!("signal {name} present"))
    }

    #[test]
    fn parses_frames_and_meta() {
        let m = parse_fixture();
        assert_eq!(m.meta.device_address, 1);
        assert_eq!(m.meta.register_base, 0);
        assert_eq!(m.meta.default_word_order, Some(Endianness::Little));

        let bs = frame(&m, "battery_status");
        assert_eq!(bs.register_number, 13019);
        assert_eq!(bs.length, 9);
        assert_eq!(bs.register_type, RegisterType::Input);
        assert_eq!(bs.interval_ms, 10000); // frame tx override

        let soc = signal(bs, "Battery_SoC");
        assert_eq!(soc.start_bit, 48);
        assert_eq!(soc.bit_length, 16);

        // solar_pv has no per-frame interval → meta default (5000).
        assert_eq!(frame(&m, "solar_pv").interval_ms, 5000);
    }

    #[test]
    fn decodes_register_aligned_soc() {
        let m = parse_fixture();
        let bs = frame(&m, "battery_status");
        // 9 registers; Battery_SoC at start_bit 48 = register index 3.
        let mut regs = [0u16; 9];
        regs[3] = 555; // ×0.1 → 55.5 %
        let decoded = decode_frame(bs, &regs, &m.meta);
        let soc = decoded.iter().find(|d| d.name == "Battery_SoC").unwrap();
        assert_eq!(soc.value, dec!(55.5));
        assert_eq!(soc.unit.as_deref(), Some("%"));
        // The ascii-free battery_status still skips nothing numeric; the
        // signed temperature decodes too.
        assert!(decoded.iter().any(|d| d.name == "Battery_Temperature"));
    }

    #[test]
    fn decodes_word_swapped_signed_32bit_charging() {
        let m = parse_fixture();
        let bp = frame(&m, "battery_power");
        // -1000 W (charging). S32 = 0xFFFFFC18. Sungrow word order is
        // little (low word first), so registers arrive [low, high].
        let regs = [0xFC18u16, 0xFFFFu16];
        let decoded = decode_frame(bp, &regs, &m.meta);
        let p = &decoded[0];
        assert_eq!(p.name, "Battery_Power");
        assert_eq!(p.value, dec!(-1000));
    }

    #[test]
    fn decodes_word_swapped_unsigned_32bit_discharging() {
        let m = parse_fixture();
        let bp = frame(&m, "battery_power");
        // +2000 W: 0x000007D0 → registers [low=0x07D0, high=0x0000].
        let regs = [0x07D0u16, 0x0000u16];
        let p = &decode_frame(bp, &regs, &m.meta)[0];
        assert_eq!(p.value, dec!(2000));
    }

    #[test]
    fn decodes_total_dc_power_mid_block() {
        let m = parse_fixture();
        let pv = frame(&m, "solar_pv");
        // length 8; Total_DC_Power at start_bit 96 = register index 6.
        // 5000 W word-swapped → [low=0x1388, high=0x0000] at idx 6,7.
        let mut regs = [0u16; 8];
        regs[0] = 2500; // MPPT1_Voltage ×0.1 = 250.0 V
        regs[6] = 0x1388;
        regs[7] = 0x0000;
        let decoded = decode_frame(pv, &regs, &m.meta);
        let dc = decoded.iter().find(|d| d.name == "Total_DC_Power").unwrap();
        assert_eq!(dc.value, dec!(5000));
        let v = decoded.iter().find(|d| d.name == "MPPT1_Voltage").unwrap();
        assert_eq!(v.value, dec!(250));
    }

    #[test]
    fn ascii_frame_decodes_to_nothing() {
        let m = parse_fixture();
        let v = frame(&m, "version_1");
        let regs = [0x4142u16; 11];
        assert!(decode_frame(v, &regs, &m.meta).is_empty());
    }

    #[test]
    fn a_catalogues_function_codes_are_no_concern_of_the_manifest() {
        let toml = r#"
[meta.modbus]
default_word_order = "little"
[meta.modbus.function_code.0x60]
name = "Dispatch"
lengths = [{ len = { count_at = 6, overhead = 9 } }]
[meta.modbus.function_code.0x65]

[frame.modbus.misc]
register_number = 100
register_type = "input"
"#;
        let m = ModbusManifest::parse(toml).unwrap();
        assert_eq!(m.meta.default_word_order, Some(Endianness::Little));
        assert_eq!(m.frames.len(), 1);
    }

    #[test]
    fn decodes_non_register_aligned_signal() {
        // A 16-bit signal at start_bit 8 spans the low byte of reg0 and
        // the high byte of reg1 (no word swap; ≤16 bits).
        let toml = r#"
[meta.modbus]
register_base = 0
default_byte_order = "big"

[frame.modbus.misc]
register_number = 100
register_type = "input"
length = 2

[[ frame.modbus.misc.signals ]]
name = "Spanning"
start_bit = 8
bit_length = 16
"#;
        let m = ModbusManifest::parse(toml).unwrap();
        let f = frame(&m, "misc");
        // regs = [0x00AB, 0xCD00] → bytes 00 AB CD 00 → bits[8..24] = AB CD.
        let regs = [0x00ABu16, 0xCD00u16];
        let d = &decode_frame(f, &regs, &m.meta)[0];
        assert_eq!(d.value.to_u32().unwrap(), 0xABCD);
    }

    #[test]
    fn register_base_one_strips_type_prefix() {
        let toml = r#"
[meta.modbus]
register_base = 1

[frame.modbus.cfg]
register_number = 40001
register_type = "holding"
length = 1

[[ frame.modbus.cfg.signals ]]
name = "X"
start_bit = 0
bit_length = 16
"#;
        let m = ModbusManifest::parse(toml).unwrap();
        let f = frame(&m, "cfg");
        assert_eq!(m.protocol_address(f), 0);
    }

    #[test]
    fn register_base_zero_passes_address_through() {
        let m = parse_fixture();
        let bs = frame(&m, "battery_status");
        assert_eq!(m.protocol_address(bs), 13019);
    }

    #[test]
    fn empty_manifest_is_rejected() {
        assert!(matches!(
            ModbusManifest::parse("[meta.modbus]\nregister_base = 0\n"),
            Err(ManifestError::NoFrames)
        ));
        assert!(matches!(
            ModbusManifest::parse("not = valid = toml ="),
            Err(ManifestError::Toml(_))
        ));
    }

    #[test]
    fn register_number_derived_from_hex_key() {
        let toml = r#"
[frame.modbus.0x32F9]
register_type = "holding"
length = 1
[[ frame.modbus.0x32F9.signals ]]
name = "EMS_Mode"
start_bit = 0
bit_length = 16
"#;
        let m = ModbusManifest::parse(toml).unwrap();
        assert_eq!(m.frames[0].register_number, 0x32F9); // 13049
    }

    #[test]
    fn register_number_from_decimal_key_and_explicit_overrides() {
        let toml = r#"
[frame.modbus.13050]
register_type = "holding"
length = 1
[[ frame.modbus.13050.signals ]]
name = "A"
start_bit = 0
bit_length = 16

[frame.modbus.named]
register_number = 200
register_type = "holding"
length = 1
[[ frame.modbus.named.signals ]]
name = "B"
start_bit = 0
bit_length = 16
"#;
        let m = ModbusManifest::parse(toml).unwrap();
        assert_eq!(frame(&m, "13050").register_number, 13050);
        // Explicit register_number wins even when the key isn't numeric.
        assert_eq!(frame(&m, "named").register_number, 200);
    }

    #[test]
    fn non_numeric_key_without_register_number_errors() {
        let toml = r#"
[frame.modbus.battery_status]
register_type = "input"
length = 1
[[ frame.modbus.battery_status.signals ]]
name = "A"
start_bit = 0
bit_length = 16
"#;
        assert!(matches!(
            ModbusManifest::parse(toml),
            Err(ManifestError::BadRegister(name)) if name == "battery_status"
        ));
    }

    #[test]
    fn signal_less_register_synthesises_full_width_signal() {
        // A register that IS a single scaled value — no signals array.
        let toml = r#"
[meta.modbus]
default_byte_order = "big"

[frame.modbus.0x138F]
register_type = "input"
length = 1
name = "Inverter_Temperature"
factor = 0.1
unit = "°C"
"#;
        let m = ModbusManifest::parse(toml).unwrap();
        let f = &m.frames[0];
        assert_eq!(f.register_number, 0x138F);
        assert_eq!(f.signals.len(), 1);
        let s = &f.signals[0];
        assert_eq!(s.name, "Inverter_Temperature");
        assert_eq!(s.start_bit, 0);
        assert_eq!(s.bit_length, 16);
        // 0x0199 = 409 ×0.1 = 40.9.
        let d = &decode_frame(f, &[0x0199], &m.meta)[0];
        assert_eq!(d.value, dec!(40.9));
        assert_eq!(d.unit.as_deref(), Some("°C"));
    }

    #[test]
    fn scaled_value_stringifies_without_float_artefacts() {
        // In f64, `3374 * 0.1` is 337.40000000000003.
        let toml = r#"
[frame.modbus.0x138F]
register_type = "input"
length = 1
name = "MPPT_Voltage"
factor = 0.1
unit = "V"
"#;
        let m = ModbusManifest::parse(toml).unwrap();
        let d = &decode_frame(&m.frames[0], &[3374], &m.meta)[0];
        assert_eq!(d.value, dec!(337.4));
        assert_eq!(d.value.to_string(), "337.4");
    }

    #[test]
    fn a_signal_whose_scale_overflows_is_skipped() {
        let toml = r#"
[frame.modbus.0x100]
register_type = "input"
length = 4
[[ frame.modbus.0x100.signals ]]
name = "Huge"
start_bit = 0
bit_length = 64
factor = 1e15
[[ frame.modbus.0x100.signals ]]
name = "Low"
start_bit = 48
bit_length = 16
factor = 0.1
"#;
        let m = ModbusManifest::parse(toml).unwrap();
        let d = decode_frame(&m.frames[0], &[0xFFFF; 4], &m.meta);
        let names: Vec<_> = d.iter().map(|d| (d.name.as_str(), d.value)).collect();
        assert_eq!(names, [("Low", dec!(6553.5))]);
    }

    #[test]
    fn signal_less_ascii_register_spans_block_and_skips_decode() {
        let toml = r#"
[frame.modbus.0x1359]
register_type = "input"
length = 11
name = "ARM_Software_Version"
format = "ascii"
"#;
        let m = ModbusManifest::parse(toml).unwrap();
        let f = &m.frames[0];
        assert_eq!(f.signals.len(), 1);
        assert_eq!(f.signals[0].bit_length, 11 * 16);
        assert_eq!(f.signals[0].format, Some(SignalFormat::Ascii));
        // String formats are skipped by the numeric decoder.
        assert!(decode_frame(f, &[0x4142u16; 11], &m.meta).is_empty());
    }

    #[test]
    fn bare_register_block_without_fields_stays_signal_less() {
        // No signals AND no frame-level fields → still zero signals (raw block).
        let toml = r#"
[frame.modbus.0x100]
register_type = "input"
length = 2
"#;
        let m = ModbusManifest::parse(toml).unwrap();
        assert!(m.frames[0].signals.is_empty());
    }

    #[test]
    fn combined_shorthands_key_and_signal_less() {
        // Both at once: register from the key, value from frame-level fields.
        let toml = r#"
[frame.modbus.0x145D]
register_type = "input"
length = 1
name = "Battery_Power"
signed = true
unit = "W"
"#;
        let m = ModbusManifest::parse(toml).unwrap();
        let f = &m.frames[0];
        assert_eq!(f.register_number, 0x145D);
        assert_eq!(f.signals.len(), 1);
        assert!(f.signals[0].signed);
        // 0xFF69 as signed 16-bit = -151.
        let d = &decode_frame(f, &[0xFF69], &m.meta)[0];
        assert_eq!(d.value, dec!(-151));
    }

    #[test]
    fn round_trips_through_json() {
        let m = parse_fixture();
        let s = serde_json::to_string(&m).unwrap();
        let back: ModbusManifest = serde_json::from_str(&s).unwrap();
        assert_eq!(m, back);
    }

    #[test]
    fn parses_disabled_frame_flag() {
        let toml = r#"
[frame.modbus.a]
register_number = 100
register_type = "input"
length = 1
disabled = true

[frame.modbus.b]
register_number = 200
register_type = "input"
length = 1
"#;
        let m = ModbusManifest::parse(toml).unwrap();
        assert!(frame(&m, "a").disabled);
        assert!(!frame(&m, "b").disabled); // default
    }

    #[test]
    fn set_frame_disabled_toggles_and_preserves_comments() {
        let toml = r#"# top comment
[frame.modbus.a]
register_number = 100  # inline
register_type = "input"
length = 1

[frame.modbus.b]
register_number = 200
register_type = "input"
length = 1
"#;
        // Disable: flag added under frame a; comments + frame b untouched.
        let disabled = set_frame_disabled(toml, "a", true).unwrap();
        assert!(disabled.contains("# top comment"));
        assert!(disabled.contains("# inline"));
        assert!(disabled.contains("disabled = true"));
        let m = ModbusManifest::parse(&disabled).unwrap();
        assert!(frame(&m, "a").disabled);
        assert!(!frame(&m, "b").disabled);

        // Re-enable: the key is removed, not set to false.
        let enabled = set_frame_disabled(&disabled, "a", false).unwrap();
        assert!(!enabled.contains("disabled"));
        assert!(!ModbusManifest::parse(&enabled).unwrap().frames[0].disabled);

        // Unknown frame is an error.
        assert!(set_frame_disabled(toml, "missing", true).is_err());
    }

    /// Byte and word order are set here *on purpose*: a coil block has neither.
    const COIL_FIXTURE: &str = r#"
[meta.modbus]
register_base = 0
default_byte_order = "big"
default_word_order = "little"

[frame.modbus.relays]
register_number = 20
register_type = "coil"
length = 24

[[ frame.modbus.relays.signals ]]
name = "Pump"
start_bit = 0
bit_length = 1

[[ frame.modbus.relays.signals ]]
name = "Heater"
start_bit = 3
bit_length = 1

[[ frame.modbus.relays.signals ]]
name = "Mode"
start_bit = 6
bit_length = 4

[[ frame.modbus.relays.signals ]]
name = "Wide_Flags"
start_bit = 0
bit_length = 20
byte_order = "big"

[[ frame.modbus.relays.signals ]]
name = "Trim"
start_bit = 10
bit_length = 5
signed = true

[[ frame.modbus.relays.signals ]]
name = "Serial"
start_bit = 0
bit_length = 16
format = "ascii"

[frame.modbus.inputs]
register_number = 40
register_type = "discrete"
length = 8

[[ frame.modbus.inputs.signals ]]
name = "Alarm"
start_bit = 2
bit_length = 1

[frame.modbus.pump_running]
register_number = 7
register_type = "coil"
length = 1
name = "Pump_Running"
"#;

    fn coil_manifest() -> ModbusManifest {
        ModbusManifest::parse(COIL_FIXTURE).expect("coil fixture parses")
    }

    /// Coils 0, 3, 8 and 17 on, out of 24. Coil 7 is deliberately off: it is
    /// what big-endian bit numbering would read for coil 0, so leaving it set
    /// would make that assertion pass either way.
    fn relay_coils() -> Vec<bool> {
        let mut coils = vec![false; 24];
        for i in [0, 3, 8, 17] {
            coils[i] = true;
        }
        coils
    }

    #[test]
    fn a_coil_block_decodes_least_significant_bit_first() {
        let m = coil_manifest();
        let d = decode_coil_frame(frame(&m, "relays"), &relay_coils());
        let v = |name: &str| d.iter().find(|d| d.name == name).unwrap().value;
        // Big-endian bit numbering would read coils 7 and 4 for these, both off.
        assert_eq!(v("Pump"), dec!(1));
        assert_eq!(v("Heater"), dec!(1));
    }

    #[test]
    fn a_coil_field_spans_a_byte_boundary_lowest_coil_first() {
        let m = coil_manifest();
        let d = decode_coil_frame(frame(&m, "relays"), &relay_coils());
        // Coils 6,7,8,9 = 0,0,1,0 with coil 6 the least significant bit.
        assert_eq!(d.iter().find(|d| d.name == "Mode").unwrap().value, dec!(4));
    }

    #[test]
    fn coil_decode_ignores_byte_and_word_order() {
        // The regression test. `Wide_Flags` is 20 bits, so the register path
        // would word-swap it under this fixture's meta `little` word order, and
        // its own `byte_order = "big"` would flip the bit numbering again.
        let m = coil_manifest();
        let d = decode_coil_frame(frame(&m, "relays"), &relay_coils());
        // Coils 0, 3, 8 and 17 → 1 + 8 + 256 + 131072.
        assert_eq!(
            d.iter().find(|d| d.name == "Wide_Flags").unwrap().value,
            dec!(131337)
        );
    }

    #[test]
    fn a_short_coil_block_reads_zero_past_its_end() {
        let m = coil_manifest();
        let d = decode_coil_frame(frame(&m, "relays"), &[true, false, false, true]);
        let v = |name: &str| d.iter().find(|d| d.name == name).unwrap().value;
        assert_eq!(v("Wide_Flags"), dec!(9));
        assert_eq!(v("Mode"), dec!(0));
    }

    #[test]
    fn coil_decode_skips_string_formats() {
        let m = coil_manifest();
        let d = decode_coil_frame(frame(&m, "relays"), &relay_coils());
        assert!(!d.iter().any(|d| d.name == "Serial"));
    }

    #[test]
    fn a_discrete_frame_decodes_like_a_coil_one() {
        let m = coil_manifest();
        let mut coils = vec![false; 8];
        coils[2] = true;
        let d = decode_coil_frame(frame(&m, "inputs"), &coils);
        assert_eq!(d[0].name, "Alarm");
        assert_eq!(d[0].value, dec!(1));
    }

    /// Encode `value` into `name`, lay the writes out as the relay block, and
    /// decode that block again.
    fn coil_round_trip(name: &str, value: f64) -> Decimal {
        let m = coil_manifest();
        let f = frame(&m, "relays");
        let s = signal(f, name);
        let base = m.protocol_address(f);
        let mut coils = vec![false; f.length as usize];
        for w in encode_signal(&m, f, s, value).unwrap() {
            assert_eq!((w.bank, w.mask), (WriteBank::Coil, 1));
            coils[(w.address - base) as usize] = w.value == 1;
        }
        let d = decode_coil_frame(f, &coils);
        d.iter().find(|d| d.name == name).unwrap().value
    }

    #[test]
    fn a_one_coil_signal_encodes_to_its_coil_and_round_trips() {
        let m = coil_manifest();
        let f = frame(&m, "relays");
        assert_eq!(
            encode_signal(&m, f, signal(f, "Heater"), 1.0).unwrap(),
            vec![ModbusWrite::coil(23, true)]
        );
        assert_eq!(coil_round_trip("Heater", 1.0), dec!(1));
        assert_eq!(coil_round_trip("Heater", 0.0), dec!(0));
    }

    #[test]
    fn a_multi_coil_signal_encodes_lowest_coil_first_and_round_trips() {
        let m = coil_manifest();
        let f = frame(&m, "relays");
        // 4 = 0b0100: coils 26..30 read 0, 0, 1, 0.
        assert_eq!(
            encode_signal(&m, f, signal(f, "Mode"), 4.0).unwrap(),
            [(26, false), (27, false), (28, true), (29, false)]
                .map(|(a, on)| ModbusWrite::coil(a, on))
        );
        assert_eq!(coil_round_trip("Mode", 11.0), dec!(11));
        // Byte and word order are ignored on the way out as on the way in.
        assert_eq!(coil_round_trip("Wide_Flags", 131337.0), dec!(131337));
    }

    #[test]
    fn a_signed_coil_signal_round_trips() {
        assert_eq!(coil_round_trip("Trim", -5.0), dec!(-5));
        assert_eq!(coil_round_trip("Trim", -16.0), dec!(-16));
        assert_eq!(coil_round_trip("Trim", 15.0), dec!(15));
    }

    #[test]
    fn a_signal_less_coil_frame_synthesises_one_bit_per_coil() {
        // Was `length × 16`, so a one-coil frame asked for a 16-bit numeric
        // extraction from a one-byte block.
        let m = coil_manifest();
        let f = frame(&m, "pump_running");
        assert_eq!(f.signals[0].bit_length, 1);
        assert_eq!(decode_coil_frame(f, &[true])[0].value, dec!(1));
    }

    const WRITE_FIXTURE: &str = r#"
[meta.modbus]
register_base = 0
default_byte_order = "big"
default_word_order = "little"

[frame.modbus.ems_control]
register_number = 13049
register_type = "holding"
length = 3
tx.interval_ms = 30000

[[ frame.modbus.ems_control.signals ]]
name = "EMS_Mode"
start_bit = 0
bit_length = 16
[frame.modbus.ems_control.signals.enum]
0 = "self_consume"
2 = "forced"

[[ frame.modbus.ems_control.signals ]]
name = "Forced_Charge_Discharge_Cmd"
start_bit = 16
bit_length = 16
format = "enum"
[frame.modbus.ems_control.signals.enum]
170 = "charge"
187 = "discharge"
204 = "stop"

[[ frame.modbus.ems_control.signals ]]
name = "Forced_Charge_Discharge_Power"
start_bit = 32
bit_length = 16
unit = "W"

[frame.modbus.battery_power_limits]
register_number = 33046
register_type = "holding"
length = 2

[[ frame.modbus.battery_power_limits.signals ]]
name = "Battery_Max_Charge_Power"
start_bit = 0
bit_length = 16
factor = 10
unit = "W"

[frame.modbus.wide]
register_number = 100
register_type = "holding"
length = 2

[[ frame.modbus.wide.signals ]]
name = "Wide_Signed"
start_bit = 0
bit_length = 32
signed = true

[frame.modbus.readonly_block]
register_number = 5213
register_type = "input"
length = 2

[[ frame.modbus.readonly_block.signals ]]
name = "Battery_Power"
start_bit = 0
bit_length = 32
signed = true
unit = "W"

[frame.modbus.coil_cmds]
register_number = 300
register_type = "coil"
length = 1

[[ frame.modbus.coil_cmds.signals ]]
name = "Force_Charge"
start_bit = 0
bit_length = 1
[frame.modbus.coil_cmds.signals.enum]
0 = "off"
1 = "on"
"#;

    fn write_manifest() -> ModbusManifest {
        ModbusManifest::parse(WRITE_FIXTURE).expect("write fixture parses")
    }

    fn wsig<'a>(m: &'a ModbusManifest, name: &str) -> (&'a ModbusFrame, &'a ModbusSignal) {
        m.find_write_signal(name)
            .unwrap_or_else(|| panic!("write signal {name} present"))
    }

    #[test]
    fn parses_enum_map_and_still_decodes_numeric() {
        let m = write_manifest();
        let (_, ems) = wsig(&m, "EMS_Mode");
        let map = ems.enum_map.as_ref().expect("enum map");
        assert_eq!(map.get("0").map(String::as_str), Some("self_consume"));
        assert_eq!(map.get("2").map(String::as_str), Some("forced"));
        // A `format = "enum"` signal still decodes to its numeric value.
        let (frame, _) = wsig(&m, "Forced_Charge_Discharge_Cmd");
        let regs = [0u16, 204, 0]; // cmd register = 204 ("stop")
        let decoded = decode_frame(frame, &regs, &m.meta);
        let cmd = decoded
            .iter()
            .find(|d| d.name == "Forced_Charge_Discharge_Cmd")
            .expect("enum signal decodes");
        assert_eq!(cmd.value, dec!(204));
    }

    fn reg(address: u16, value: u16) -> ModbusWrite {
        ModbusWrite::holding(address, value, 0xffff)
    }

    #[test]
    fn encode_enum_resolves_canonical_name() {
        let m = write_manifest();
        let (f, s) = wsig(&m, "Forced_Charge_Discharge_Cmd");
        assert_eq!(
            encode_enum(&m, f, s, "charge").unwrap(),
            vec![reg(13050, 170)]
        );
        assert_eq!(
            encode_enum(&m, f, s, "stop").unwrap(),
            vec![reg(13050, 204)]
        );
    }

    #[test]
    fn encode_signal_applies_scale_and_address_offset() {
        let m = write_manifest();
        // Forced power: register 13049 + start_bit 32/16 = 13051, factor 1.
        let (f, s) = wsig(&m, "Forced_Charge_Discharge_Power");
        assert_eq!(
            encode_signal(&m, f, s, 3000.0).unwrap(),
            vec![reg(13051, 3000)]
        );
        // Max charge: 33046, W/10 (factor 10) → 5000 W encodes to 500.
        let (f, s) = wsig(&m, "Battery_Max_Charge_Power");
        assert_eq!(
            encode_signal(&m, f, s, 5000.0).unwrap(),
            vec![reg(33046, 500)]
        );
    }

    #[test]
    fn encode_decode_round_trips_signed_32bit_word_swapped() {
        let m = write_manifest();
        let (f, s) = wsig(&m, "Wide_Signed");
        let writes = encode_signal(&m, f, s, -1000.0).unwrap();
        assert_eq!(writes.len(), 2);
        assert_eq!(writes[0].address, 100);
        assert_eq!(writes[1].address, 101);
        // Round-trip the written register block through the decoder.
        let regs: Vec<u16> = writes.iter().map(|w| w.value).collect();
        let decoded = decode_frame(f, &regs, &m.meta);
        assert_eq!(decoded[0].value, dec!(-1000));
    }

    #[test]
    fn encode_refuses_a_value_past_the_field() {
        let m = write_manifest();
        let (f, s) = wsig(&m, "Forced_Charge_Discharge_Power");
        let out_of_range = |raw| EncodeError::OutOfRange {
            name: "Forced_Charge_Discharge_Power".into(),
            raw,
            min: 0,
            max: 65535,
        };
        assert_eq!(encode_signal(&m, f, s, -50.0), Err(out_of_range(-50)));
        assert_eq!(
            encode_signal(&m, f, s, 1_000_000.0),
            Err(out_of_range(1_000_000))
        );
    }

    #[test]
    fn a_field_takes_its_exact_bounds_and_refuses_one_past_each() {
        for (signal, min, max) in [
            ("start_bit = 0\nbit_length = 16", 0.0, 65535.0),
            (
                "start_bit = 0\nbit_length = 16\nsigned = true",
                -32768.0,
                32767.0,
            ),
            ("start_bit = 4\nbit_length = 4", 0.0, 15.0),
            ("start_bit = 4\nbit_length = 4\nsigned = true", -8.0, 7.0),
            (
                "start_bit = 0\nbit_length = 32\nsigned = true",
                -2147483648.0,
                2147483647.0,
            ),
        ] {
            let m = one_signal("", "", signal);
            let (frame, s) = (&m.frames[0], &m.frames[0].signals[0]);
            for value in [min, max] {
                assert!(
                    encode_signal(&m, frame, s, value).is_ok(),
                    "{signal} {value}"
                );
            }
            for value in [min - 1.0, max + 1.0] {
                assert!(
                    matches!(
                        encode_signal(&m, frame, s, value),
                        Err(EncodeError::OutOfRange { .. })
                    ),
                    "{signal} {value}"
                );
            }
        }
    }

    #[test]
    fn a_scaled_field_is_bounded_after_unscaling() {
        let m = one_signal(
            "",
            "",
            "start_bit = 0\nbit_length = 16\nfactor = 0.1\noffset = -100",
        );
        let (frame, s) = (&m.frames[0], &m.frames[0].signals[0]);
        assert!(encode_signal(&m, frame, s, -100.0).is_ok());
        assert!(encode_signal(&m, frame, s, 6453.5).is_ok());
        assert_eq!(
            encode_signal(&m, frame, s, -100.1),
            Err(EncodeError::OutOfRange {
                name: "S".into(),
                raw: -1,
                min: 0,
                max: 65535
            })
        );
        assert!(matches!(
            encode_signal(&m, frame, s, 6453.6),
            Err(EncodeError::OutOfRange { raw: 65536, .. })
        ));
    }

    #[test]
    fn an_enum_value_past_the_field_is_refused() {
        let m = one_signal(
            "",
            "",
            "start_bit = 4\nbit_length = 4\nenum = { \"16\" = \"too_big\" }",
        );
        assert!(matches!(
            encode_enum(&m, &m.frames[0], &m.frames[0].signals[0], "too_big"),
            Err(EncodeError::OutOfRange {
                raw: 16,
                max: 15,
                ..
            })
        ));
    }

    #[test]
    fn a_coil_takes_zero_or_one() {
        let toml = "[frame.modbus.0]\nregister_type = \"coil\"\nlength = 1\n\
                    [[ frame.modbus.0.signals ]]\nname = \"On\"\nstart_bit = 0\nbit_length = 1\n";
        let m = ModbusManifest::parse(toml).unwrap();
        let (frame, s) = (&m.frames[0], &m.frames[0].signals[0]);
        assert_eq!(
            encode_signal(&m, frame, s, 0.0),
            Ok(vec![ModbusWrite::coil(0, false)])
        );
        assert_eq!(
            encode_signal(&m, frame, s, 1.0),
            Ok(vec![ModbusWrite::coil(0, true)])
        );
        for value in [-1.0, 2.0] {
            assert!(matches!(
                encode_signal(&m, frame, s, value),
                Err(EncodeError::OutOfRange { min: 0, max: 1, .. })
            ));
        }
    }

    #[test]
    fn encode_single_register_bitfield_is_masked() {
        // A 4-bit field at start_bit 4 of a holding register → masked write.
        let toml = r#"
[frame.modbus.flags]
register_number = 200
register_type = "holding"
length = 1

[[ frame.modbus.flags.signals ]]
name = "Nibble"
start_bit = 4
bit_length = 4
"#;
        let m = ModbusManifest::parse(toml).unwrap();
        let (f, s) = m.find_write_signal("Nibble").unwrap();
        // value 0b1010 = 10, field at bits [4,8) from the MSB → shift 8.
        let w = encode_signal(&m, f, s, 10.0).unwrap();
        assert_eq!(w, vec![ModbusWrite::holding(200, 0x0A00, 0x0F00)]);
    }

    #[test]
    fn merge_combines_bitfields_and_rejects_overlap() {
        let a = ModbusWrite::holding(5, 0x0A00, 0x0F00);
        let b = ModbusWrite::holding(5, 0x000B, 0x000F);
        // Disjoint bit-fields in one register merge into a single write.
        let merged = merge_register_writes(vec![a, b]).unwrap();
        assert_eq!(merged, vec![ModbusWrite::holding(5, 0x0A0B, 0x0F0F)]);
        // Overlapping masks are a conflict.
        let c = ModbusWrite::holding(5, 0x0100, 0x0F00);
        assert_eq!(
            merge_register_writes(vec![a, c]).unwrap_err(),
            "register 5 written by overlapping commands"
        );
    }

    #[test]
    fn a_coil_and_a_register_at_one_number_stay_two_writes() {
        let writes = vec![reg(5, 1), ModbusWrite::coil(5, true)];
        assert_eq!(merge_register_writes(writes.clone()).unwrap(), writes);
        assert_eq!(
            merge_register_writes(vec![
                ModbusWrite::coil(5, true),
                ModbusWrite::coil(5, false)
            ])
            .unwrap_err(),
            "coil 5 written by overlapping commands"
        );
    }

    #[test]
    fn overlay_last_wins_per_register_keeping_order() {
        let out =
            overlay_register_writes(vec![reg(33046, 6000), reg(33047, 6000), reg(33046, 1000)]);
        assert_eq!(out, vec![reg(33046, 1000), reg(33047, 6000)]);
    }

    #[test]
    fn overlay_merges_disjoint_bitfields() {
        let lo = ModbusWrite::holding(13049, 0x0002, 0x00ff);
        let hi = ModbusWrite::holding(13049, 0xAA00, 0xff00);
        assert_eq!(
            overlay_register_writes(vec![lo, hi]),
            vec![ModbusWrite::holding(13049, 0xAA02, 0xffff)]
        );
    }

    #[test]
    fn overlay_keeps_a_coil_and_a_register_at_one_number_apart() {
        let out = overlay_register_writes(vec![
            reg(33046, 6000),
            ModbusWrite::coil(33046, true),
            ModbusWrite::coil(33046, false),
        ]);
        assert_eq!(out, vec![reg(33046, 6000), ModbusWrite::coil(33046, false)]);
    }

    #[test]
    fn overlay_ignores_a_later_writes_bits_outside_its_mask() {
        let hi = ModbusWrite::holding(5, 0x1200, 0xff00);
        let lo_with_stray_bits = ModbusWrite::holding(5, 0xFFAB, 0x00ff);
        assert_eq!(
            overlay_register_writes(vec![hi, lo_with_stray_bits]),
            vec![ModbusWrite::holding(5, 0x12AB, 0xffff)]
        );
    }

    #[test]
    fn group_contiguous_starts_a_run_on_a_change_of_bank() {
        let writes = vec![
            reg(5, 1),
            reg(6, 2),
            ModbusWrite::coil(7, true),
            ModbusWrite::coil(8, false),
            reg(9, 3),
        ];
        let runs = group_contiguous(&writes);
        assert_eq!(
            runs,
            vec![
                writes[..2].to_vec(),
                writes[2..4].to_vec(),
                writes[4..].to_vec()
            ]
        );
    }

    #[test]
    fn a_write_without_a_bank_deserialises_as_holding() {
        let w: ModbusWrite = serde_json::from_str(r#"{"address":5,"value":1}"#).unwrap();
        assert_eq!(w, reg(5, 1));
        let json = serde_json::to_string(&ModbusWrite::coil(5, true)).unwrap();
        assert_eq!(json, r#"{"bank":"coil","address":5,"value":1,"mask":1}"#);
    }

    #[test]
    fn group_contiguous_runs_and_preserves_order() {
        // 13049,13050,13051 contiguous → one run; 13073 a separate run; order
        // kept (13086 before 13073 stays two runs in that order).
        let writes = vec![
            reg(13049, 2),
            reg(13050, 170),
            reg(13051, 3000),
            reg(13086, 1),
            reg(13073, 0),
        ];
        let runs = group_contiguous(&writes);
        assert_eq!(runs.len(), 3);
        assert_eq!(
            runs[0].iter().map(|w| w.address).collect::<Vec<_>>(),
            vec![13049, 13050, 13051]
        );
        assert_eq!(runs[1], vec![reg(13086, 1)]);
        assert_eq!(runs[2], vec![reg(13073, 0)]);
    }

    #[test]
    fn encode_rejects_read_only_and_unknown_enum() {
        let m = write_manifest();
        // A signal that only exists in an input frame isn't a write target.
        assert!(m.find_write_signal("Battery_Power").is_none());
        let (f, s) = wsig(&m, "Forced_Charge_Discharge_Cmd");
        assert_eq!(
            encode_enum(&m, f, s, "frobnicate").unwrap_err(),
            EncodeError::UnknownEnumName {
                name: "Forced_Charge_Discharge_Cmd".into(),
                value: "frobnicate".into(),
            }
        );
    }

    #[test]
    fn coil_signals_are_offered_as_write_targets_at_their_coil() {
        let m = write_manifest();
        assert!(m.find_write_signal("Force_Charge").is_some());
        let opts = m.write_signal_options();
        assert!(opts.contains(&("Force_Charge".into(), 300)), "{opts:?}");
        let enums = m.write_signal_enums();
        assert!(enums.iter().any(|(n, _)| n == "Force_Charge"));
    }

    #[test]
    fn a_coil_signal_encodes_as_a_coil_and_a_read_only_one_is_refused() {
        let m = write_manifest();
        let (f, s) = wsig(&m, "Force_Charge");
        assert_eq!(
            encode_enum(&m, f, s, "on").unwrap(),
            vec![ModbusWrite::coil(300, true)]
        );
        assert_eq!(
            encode_signal(&m, f, s, 0.0).unwrap(),
            vec![ModbusWrite::coil(300, false)]
        );
        let ro = frame(&m, "readonly_block");
        assert_eq!(
            encode_signal(&m, ro, signal(ro, "Battery_Power"), 1.0).unwrap_err(),
            EncodeError::NotWritable("Battery_Power".into())
        );
    }

    #[test]
    fn write_bank_bridges_only_the_writable_register_types() {
        assert_eq!(RegisterType::Holding.write_bank(), Some(WriteBank::Holding));
        assert_eq!(RegisterType::Coil.write_bank(), Some(WriteBank::Coil));
        assert_eq!(RegisterType::Input.write_bank(), None);
        assert_eq!(RegisterType::Discrete.write_bank(), None);
    }

    #[test]
    fn write_signal_options_carry_register_and_list_writable_only() {
        let opts = write_manifest().write_signal_options();
        let reg = |name: &str| opts.iter().find(|(n, _)| n == name).map(|(_, r)| *r);
        // ems_control @ 13049: EMS_Mode @ +0, Forced_Cmd @ +1 (start_bit 16).
        assert_eq!(reg("EMS_Mode"), Some(13049));
        assert_eq!(reg("Forced_Charge_Discharge_Cmd"), Some(13050));
        // battery_power_limits @ 33046.
        assert_eq!(reg("Battery_Max_Charge_Power"), Some(33046));
        // Input-frame signals aren't offered (read-only).
        assert_eq!(reg("Battery_Power"), None);
        // Register-sorted.
        assert!(opts.windows(2).all(|w| w[0].1 <= w[1].1));
    }

    #[test]
    fn write_signal_enums_lists_only_enum_signals_value_sorted() {
        let m = write_manifest();
        let enums = m.write_signal_enums();
        let get = |name: &str| {
            enums
                .iter()
                .find(|(n, _)| n == name)
                .map(|(_, e)| e.clone())
        };
        // The enum command register, value-sorted.
        assert_eq!(
            get("Forced_Charge_Discharge_Cmd"),
            Some(vec![
                ("charge".into(), 170),
                ("discharge".into(), 187),
                ("stop".into(), 204),
            ])
        );
        // A plain numeric signal has no enum entry.
        assert_eq!(get("Forced_Charge_Discharge_Power"), None);
    }

    fn one_signal(meta: &str, frame: &str, signal: &str) -> ModbusManifest {
        ModbusManifest::parse(&format!(
            "[meta.modbus]\n{meta}\n[frame.modbus.0x10]\nregister_type = \"holding\"\nlength = 4\n{frame}\n\
             [[ frame.modbus.0x10.signals ]]\nname = \"S\"\n{signal}\n"
        ))
        .unwrap()
    }

    /// Writes `value` over a block of 0xA5A5, as a read-modify-write would, and
    /// decodes it back.
    fn round_trip(m: &ModbusManifest, value: f64) -> Decimal {
        let (frame, signal) = (&m.frames[0], &m.frames[0].signals[0]);
        let mut regs = [0xA5A5u16; 4];
        for w in encode_signal(m, frame, signal, value).unwrap() {
            let at = usize::from(w.address - m.protocol_address(frame));
            regs[at] = (regs[at] & !w.mask) | (w.value & w.mask);
        }
        decode_frame(frame, &regs, &m.meta)[0].value
    }

    #[test]
    fn a_write_decodes_back_to_its_value_in_every_byte_and_word_order() {
        let orders = [
            "",
            "default_byte_order = \"big\"",
            "default_byte_order = \"little\"",
        ];
        let words = [
            "",
            "default_word_order = \"big\"",
            "default_word_order = \"little\"",
        ];
        let fields = [
            ("start_bit = 0\nbit_length = 16", -1234.0),
            ("start_bit = 16\nbit_length = 32", -123_456_789.0),
            ("start_bit = 0\nbit_length = 64", -1_234_567_890_123.0),
            ("start_bit = 0\nbit_length = 48", 98_765_432_101.0),
            ("start_bit = 19\nbit_length = 9", -200.0),
            ("start_bit = 32\nbit_length = 16", 4321.0),
        ];
        for byte_order in orders {
            for word_order in words {
                for (field, value) in fields {
                    let meta = format!("{byte_order}\n{word_order}");
                    let m = one_signal(&meta, "", &format!("{field}\nsigned = true"));
                    assert_eq!(
                        round_trip(&m, value),
                        Decimal::from_f64(value).unwrap(),
                        "{byte_order} {word_order} {field}"
                    );
                }
            }
        }
    }

    #[test]
    fn a_signal_s_own_orders_override_the_meta_on_a_write() {
        for signal_orders in [
            "byte_order = \"little\"",
            "word_order = \"little\"",
            "byte_order = \"little\"\nword_order = \"little\"",
        ] {
            let m = one_signal(
                "default_byte_order = \"big\"\ndefault_word_order = \"big\"",
                "",
                &format!("start_bit = 0\nbit_length = 32\n{signal_orders}"),
            );
            assert_eq!(
                round_trip(&m, 305_419_896.0),
                dec!(305419896),
                "{signal_orders}"
            );
        }
    }

    #[test]
    fn a_little_byte_order_write_swaps_the_bytes() {
        let m = one_signal(
            "default_byte_order = \"little\"",
            "",
            "start_bit = 0\nbit_length = 16",
        );
        let w = encode_signal(&m, &m.frames[0], &m.frames[0].signals[0], 0x1234 as f64).unwrap();
        assert_eq!(w, [ModbusWrite::holding(0x10, 0x3412, 0xFFFF)]);
    }

    #[test]
    fn a_field_across_two_registers_but_not_aligned_is_refused() {
        let m = one_signal("", "", "start_bit = 8\nbit_length = 16");
        let err = encode_signal(&m, &m.frames[0], &m.frames[0].signals[0], 1.0).unwrap_err();
        assert!(
            matches!(err, EncodeError::UnsupportedLayout { .. }),
            "{err:?}"
        );
    }

    #[test]
    fn a_value_that_is_not_finite_is_refused() {
        let m = one_signal("", "", "start_bit = 0\nbit_length = 16\nfactor = 1e-300");
        let (frame, signal) = (&m.frames[0], &m.frames[0].signals[0]);
        for value in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY, 1e300] {
            assert_eq!(
                encode_signal(&m, frame, signal, value),
                Err(EncodeError::NotFinite { name: "S".into() }),
                "{value}"
            );
        }
    }

    #[test]
    fn a_signal_that_cannot_be_laid_out_is_skipped() {
        for (bank, signal) in [
            ("holding", "start_bit = 0\nbit_length = 0"),
            ("holding", "start_bit = 0\nbit_length = 65"),
            ("holding", "start_bit = 0\nbit_length = 128"),
            ("holding", "start_bit = 1048570\nbit_length = 16"),
            ("coil", "start_bit = 65530\nbit_length = 8"),
        ] {
            let toml = format!(
                "[frame.modbus.0x10]\nregister_type = \"{bank}\"\nlength = 4\n\
                 [[ frame.modbus.0x10.signals ]]\nname = \"S\"\n{signal}\n"
            );
            let m = ModbusManifest::parse(&toml).unwrap();
            assert!(m.frames[0].signals.is_empty(), "{bank} {signal}");
        }
        let text = ModbusManifest::parse(
            "[frame.modbus.0x10]\nlength = 10\n\
             [[ frame.modbus.0x10.signals ]]\nname = \"Serial\"\nstart_bit = 0\nbit_length = 160\nformat = \"ascii\"\n",
        )
        .unwrap();
        assert_eq!(text.frames[0].signals.len(), 1);
    }

    #[test]
    fn a_coil_write_at_the_top_of_the_bank_fits() {
        let toml = "[frame.modbus.0]\nregister_type = \"coil\"\nlength = 1\n\
                    [[ frame.modbus.0.signals ]]\nname = \"Last\"\nstart_bit = 65535\nbit_length = 1\n";
        let m = ModbusManifest::parse(toml).unwrap();
        let w = encode_signal(&m, &m.frames[0], &m.frames[0].signals[0], 1.0).unwrap();
        assert_eq!(w, [ModbusWrite::coil(65535, true)]);
    }
}
