//! The board TOML's serde types. `[signals]` are keyed by
//! `dsig::format_signal_key`'s slug; signal ids never appear.

use std::collections::HashMap;

use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct BoardFile {
    pub board: BoardInfo,
    #[serde(default)]
    pub interfaces: HashMap<String, InterfaceDef>,
    #[serde(default)]
    pub peripherals: HashMap<String, PeripheralDef>,
    #[serde(default)]
    pub signals: HashMap<String, SignalDef>,
    #[serde(default)]
    pub user_signals: HashMap<String, SignalDef>,
    #[serde(default)]
    pub frame_defs: HashMap<String, FrameDefDef>,
    #[serde(default)]
    pub palettes: HashMap<String, PaletteDef>,
    #[serde(default)]
    pub functions: HashMap<String, FunctionDef>,
    #[serde(default)]
    pub generators: HashMap<String, GeneratorLabelDef>,
    #[serde(default)]
    pub transformers: HashMap<String, TransformerLabelDef>,
    #[serde(default)]
    pub mcus: Vec<McuDef>,
}

#[derive(Debug, Deserialize)]
pub struct McuDef {
    pub chip: String,
    pub usb: UsbAccessDef,
    #[serde(default)]
    pub baud: Option<u32>,
    #[serde(default)]
    pub dfu_alt: Option<u8>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum UsbAccessDef {
    Named(String),
    Cdc { cdc_interface: u8 },
}

#[derive(Debug, Deserialize)]
pub struct BoardInfo {
    pub name: String,
    pub revision: String,
    #[serde(default)]
    pub description: String,
}

#[derive(Debug, Deserialize)]
pub struct InterfaceDef {
    pub name: String,
    #[serde(rename = "type")]
    pub iface_type: String,
    #[serde(default)]
    pub description: String,
}

#[derive(Debug, Deserialize)]
pub struct PeripheralDef {
    pub name: String,
    /// Dataflow kind slug: `sensor`, `actuator`, `controller`, or `link`.
    pub kind: String,
    #[serde(default)]
    pub description: String,
}

#[derive(Debug, Deserialize)]
pub struct SignalDef {
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub group: String,
    #[serde(default)]
    pub unit: String,
    #[serde(default)]
    pub format: String,
    #[serde(default, rename = "enum")]
    pub enum_values: HashMap<String, String>,
}

#[derive(Debug, Deserialize)]
pub struct FrameDefDef {
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub interface_type: String,
    #[serde(default)]
    pub can: Option<CanHeaderDef>,
    #[serde(default)]
    pub rs485: Option<Rs485HeaderDef>,
    #[serde(default)]
    pub signals: HashMap<String, FrameSignalDefToml>,
}

#[derive(Debug, Deserialize)]
pub struct CanHeaderDef {
    pub can_id: u32,
    #[serde(default = "default_dlc")]
    pub dlc: u8,
    #[serde(default)]
    pub flags: Vec<String>,
}

fn default_dlc() -> u8 {
    8
}

#[derive(Debug, Deserialize)]
pub struct Rs485HeaderDef {
    #[serde(default)]
    pub framing_mode: String,
}

#[derive(Debug, Deserialize)]
pub struct FrameSignalDefToml {
    pub name: String,
    pub bits: String,
    #[serde(default = "default_byte_order")]
    pub byte_order: String,
    #[serde(default = "default_value_type")]
    pub value_type: String,
    #[serde(default = "default_scale")]
    pub scale: f32,
    #[serde(default)]
    pub offset: f32,
    #[serde(default)]
    pub unit: String,
    #[serde(default)]
    pub format: String,
    #[serde(rename = "enum", default)]
    pub enum_values: HashMap<String, String>,
}

fn default_byte_order() -> String {
    "le".to_string()
}
fn default_value_type() -> String {
    "unsigned".to_string()
}
fn default_scale() -> f32 {
    1.0
}

/// A named colour palette stored as user signals.
#[derive(Debug, Deserialize)]
pub struct PaletteDef {
    pub name: String,
    #[serde(default)]
    pub description: String,
    pub signal_start: String,
    pub entries: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct FunctionDef {
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub params: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct GeneratorLabelDef {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub description: String,
}

#[derive(Debug, Deserialize)]
pub struct TransformerLabelDef {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub description: String,
}

/// A `0x`-prefixed hex or a decimal key.
pub fn parse_hex_key(s: &str) -> Result<u16, std::num::ParseIntError> {
    match s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        Some(hex) => u16::from_str_radix(hex, 16),
        None => s.parse(),
    }
}
