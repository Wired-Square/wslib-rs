//! FrameLink board definitions: TOML naming a board's interfaces,
//! peripherals and signals for display. Signals are keyed by
//! [`SignalKey`], never by the id a device renumbers. The known boards are
//! embedded, so nothing here reads a file to find one.

pub mod compress;
pub mod display;
pub mod editable;
mod error;
pub mod resolve;
pub mod scaffold;
pub mod selectable;
pub mod sync;
pub mod toml_schema;

use std::collections::HashMap;

pub use error::Error;
use toml_schema::{BoardFile, parse_hex_key};
use wslib_framelink_protocol::dsig::{self, SignalKey, parse_signal_key};

/// A board definition compiled into the crate.
#[derive(Debug, Clone, Copy)]
pub struct EmbeddedBoard {
    pub name: &'static str,
    pub revision: &'static str,
    pub toml: &'static str,
}

static EMBEDDED_BOARDS: &[EmbeddedBoard] = &[
    EmbeddedBoard {
        name: "wiredflexlink",
        revision: "esp32c6-v0.0.2",
        toml: include_str!("../boards/wiredflexlink_esp32c6-v0.0.2.toml"),
    },
    EmbeddedBoard {
        name: "wiredflexlink-t2can",
        revision: "esp32s3-v1.0",
        toml: include_str!("../boards/wiredflexlink-t2can_esp32s3-v1.0.toml"),
    },
];

pub fn embedded_boards() -> &'static [EmbeddedBoard] {
    EMBEDDED_BOARDS
}

#[derive(Debug)]
pub struct BoardDef {
    pub name: String,
    pub revision: String,
    pub description: String,
    pub interfaces: HashMap<u8, InterfaceInfo>,
    pub peripherals: HashMap<u8, PeripheralInfo>,
    pub signals: HashMap<SignalKey, SignalInfo>,
    /// User signals have no tuple, so they are keyed by id.
    pub user_signals: HashMap<u16, SignalInfo>,
    pub frame_defs: HashMap<u16, FrameDefDisplayInfo>,
    pub palettes: Vec<PaletteInfo>,
    pub functions: HashMap<u8, FunctionInfo>,
    pub generators: HashMap<u16, GeneratorLabelInfo>,
    pub transformers: HashMap<u16, TransformerLabelInfo>,
    pub mcus: Vec<McuInfo>,
}

pub const DEFAULT_DFU_ALT: u8 = 0;

const USB_ACCESS_SELF: &str = "self";
const USB_ACCESS_NONE: &str = "none";

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
#[non_exhaustive]
pub enum UsbAccess {
    Native,
    CdcInterface { interface: u8 },
    None,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McuInfo {
    pub chip: String,
    pub usb: UsbAccess,
    pub baud: Option<u32>,
    pub dfu_alt: u8,
}

fn parse_mcus(defs: Vec<toml_schema::McuDef>) -> Result<Vec<McuInfo>, Error> {
    let mut mcus: Vec<McuInfo> = Vec::with_capacity(defs.len());
    for (index, def) in defs.into_iter().enumerate() {
        let usb = match def.usb {
            toml_schema::UsbAccessDef::Cdc { cdc_interface } => UsbAccess::CdcInterface {
                interface: cdc_interface,
            },
            toml_schema::UsbAccessDef::Named(word) if word == USB_ACCESS_SELF => UsbAccess::Native,
            toml_schema::UsbAccessDef::Named(word) if word == USB_ACCESS_NONE => UsbAccess::None,
            toml_schema::UsbAccessDef::Named(word) => {
                return Err(Error::UsbAccess { index, word });
            }
        };
        if mcus.iter().any(|m| m.chip == def.chip) {
            return Err(Error::DuplicateMcu(def.chip));
        }
        mcus.push(McuInfo {
            chip: def.chip,
            usb,
            baud: def.baud,
            dfu_alt: def.dfu_alt.unwrap_or(DEFAULT_DFU_ALT),
        });
    }
    Ok(mcus)
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct PaletteInfo {
    pub name: String,
    pub description: String,
    pub signal_start: u16,
    pub entries: Vec<u32>,
}

#[derive(Debug, Clone)]
pub struct FunctionInfo {
    pub name: String,
    pub description: String,
    pub params: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct GeneratorLabelInfo {
    pub name: String,
    pub description: String,
}

#[derive(Debug, Clone)]
pub struct TransformerLabelInfo {
    pub name: String,
    pub description: String,
}

#[derive(Debug, Clone)]
pub struct InterfaceInfo {
    pub name: String,
    pub iface_type: String,
    pub description: String,
}

#[derive(Debug, Clone)]
pub struct PeripheralInfo {
    pub name: String,
    /// Dataflow kind slug: `sensor`, `actuator`, `controller`, or `link`.
    pub kind: String,
    pub description: String,
}

#[derive(Debug, Clone)]
pub struct SignalInfo {
    pub name: String,
    pub description: String,
    pub group: String,
    pub unit: String,
    pub format: String,
    pub enum_values: HashMap<u32, String>,
}

#[derive(Debug, Clone)]
pub struct FrameDefDisplayInfo {
    pub name: String,
    pub description: String,
    pub interface_type: String,
    pub signals: Vec<FrameSignalDisplayInfo>,
}

#[derive(Debug, Clone)]
pub struct FrameSignalDisplayInfo {
    pub slug: String,
    pub name: String,
    pub start_bit: u16,
    pub bit_length: u16,
    pub byte_order: String,
    pub value_type: String,
    pub scale: f32,
    pub offset: f32,
    pub unit: String,
}

impl BoardDef {
    pub fn signal_name(&self, key: &SignalKey) -> Option<&str> {
        self.signals.get(key).map(|s| s.name.as_str())
    }

    pub fn signal_group(&self, key: &SignalKey) -> Option<&str> {
        self.signals
            .get(key)
            .filter(|s| !s.group.is_empty())
            .map(|s| s.group.as_str())
    }

    pub fn signal_info(&self, key: &SignalKey) -> Option<&SignalInfo> {
        self.signals.get(key)
    }

    pub fn user_signal_info(&self, id: u16) -> Option<&SignalInfo> {
        self.user_signals.get(&id)
    }

    pub fn interface_name(&self, index: u8) -> Option<&str> {
        self.interfaces.get(&index).map(|i| i.name.as_str())
    }

    pub fn peripheral_name(&self, index: u8) -> Option<&str> {
        self.peripherals.get(&index).map(|p| p.name.as_str())
    }

    pub fn frame_def_name(&self, id: u16) -> Option<&str> {
        self.frame_defs.get(&id).map(|f| f.name.as_str())
    }

    pub fn frame_def_info(&self, id: u16) -> Option<&FrameDefDisplayInfo> {
        self.frame_defs.get(&id)
    }

    pub fn function_name(&self, id: u8) -> Option<&str> {
        self.functions.get(&id).map(|f| f.name.as_str())
    }

    /// Fills the sections this definition leaves empty from `defaults`. A
    /// device's own definition is authoritative, so nothing it has is
    /// overwritten.
    pub fn merge_defaults(&mut self, defaults: &BoardDef) {
        if self.functions.is_empty() {
            self.functions = defaults.functions.clone();
        }
        if self.palettes.is_empty() {
            self.palettes = defaults.palettes.clone();
        }
        if self.generators.is_empty() {
            self.generators = defaults.generators.clone();
        }
        if self.transformers.is_empty() {
            self.transformers = defaults.transformers.clone();
        }
    }

    /// `raw` as the signal's `format` and `enum` say.
    pub fn format_value(&self, key: &SignalKey, raw: u64) -> String {
        let Some(sig) = self.signals.get(key) else {
            return raw.to_string();
        };

        match sig.format.as_str() {
            "bool" => {
                if raw == 0 {
                    "false".to_string()
                } else {
                    "true".to_string()
                }
            }
            "enum" => sig
                .enum_values
                .get(&(raw as u32))
                .cloned()
                .unwrap_or_else(|| raw.to_string()),
            "temperature_0.1" => {
                let temp = raw as i32 as f64 / 10.0;
                if sig.unit.is_empty() {
                    format!("{temp:.1}")
                } else {
                    format!("{temp:.1} {}", sig.unit)
                }
            }
            "color_brgb" => format!("0x{raw:08X}"),
            _ => {
                if sig.unit.is_empty() {
                    raw.to_string()
                } else {
                    format!("{raw} {}", sig.unit)
                }
            }
        }
    }
}

/// The embedded definition for this name and revision, else the first for
/// the name: board revisions differ in pinout, not in their signals.
pub fn load_board_def(board_name: &str, board_revision: &str) -> Option<BoardDef> {
    let toml_str = EMBEDDED_BOARDS
        .iter()
        .find(|b| b.name == board_name && b.revision == board_revision)
        .or_else(|| EMBEDDED_BOARDS.iter().find(|b| b.name == board_name))
        .map(|b| b.toml)?;

    parse_board_def(toml_str).ok()
}

pub fn parse_board_def(toml_str: &str) -> Result<BoardDef, Error> {
    let file: BoardFile = toml_edit::de::from_str(toml_str)?;
    let mcus = parse_mcus(file.mcus)?;

    let mut interfaces = HashMap::new();
    for (key, def) in file.interfaces {
        interfaces.insert(
            index_key("interface", key)?,
            InterfaceInfo {
                name: def.name,
                iface_type: def.iface_type,
                description: def.description,
            },
        );
    }

    let mut peripherals = HashMap::new();
    for (key, def) in file.peripherals {
        peripherals.insert(
            index_key("peripheral", key)?,
            PeripheralInfo {
                name: def.name,
                kind: def.kind,
                description: def.description,
            },
        );
    }

    let mut signals = HashMap::new();
    for (key, def) in file.signals {
        let sig_key = parse_signal_key(&key)?;
        let enum_values: HashMap<u32, String> = def
            .enum_values
            .into_iter()
            .filter_map(|(k, v)| k.parse::<u32>().ok().map(|n| (n, v)))
            .collect();
        signals.insert(
            sig_key,
            SignalInfo {
                name: def.name,
                description: def.description,
                group: def.group,
                unit: def.unit,
                format: def.format,
                enum_values,
            },
        );
    }

    let mut user_signals = HashMap::new();
    for (key, def) in file.user_signals {
        if let Ok(id) = parse_hex_key(&key) {
            let enum_values: HashMap<u32, String> = def
                .enum_values
                .into_iter()
                .filter_map(|(k, v)| k.parse::<u32>().ok().map(|n| (n, v)))
                .collect();
            user_signals.insert(
                id,
                SignalInfo {
                    name: def.name,
                    description: def.description,
                    group: def.group,
                    unit: def.unit,
                    format: def.format,
                    enum_values,
                },
            );
        }
    }

    let mut frame_defs = HashMap::new();
    for (key, def) in file.frame_defs {
        if let Ok(id) = parse_hex_key(&key) {
            let mut frame_signals = Vec::new();
            for (slug, sig) in def.signals {
                let parts: Vec<&str> = sig.bits.split(':').collect();
                if parts.len() == 2
                    && let (Ok(start), Ok(len)) = (parts[0].parse::<u16>(), parts[1].parse::<u16>())
                {
                    frame_signals.push(FrameSignalDisplayInfo {
                        slug,
                        name: sig.name,
                        start_bit: start,
                        bit_length: len,
                        byte_order: sig.byte_order,
                        value_type: sig.value_type,
                        scale: sig.scale,
                        offset: sig.offset,
                        unit: sig.unit,
                    });
                }
            }
            frame_signals.sort_by_key(|s| s.start_bit);
            frame_defs.insert(
                id,
                FrameDefDisplayInfo {
                    name: def.name,
                    description: def.description,
                    interface_type: def.interface_type,
                    signals: frame_signals,
                },
            );
        }
    }

    let mut palettes = Vec::new();
    for (_key, def) in file.palettes {
        let signal_start = parse_hex_key(&def.signal_start).map_err(|source| Error::Key {
            section: "palette signal_start",
            key: def.signal_start.clone(),
            source,
        })?;
        let entries: Vec<u32> = def
            .entries
            .iter()
            .filter_map(|s| u32::from_str_radix(s, 16).ok())
            .collect();
        palettes.push(PaletteInfo {
            name: def.name,
            description: def.description,
            signal_start,
            entries,
        });
    }

    let mut functions = HashMap::new();
    for (key, def) in file.functions {
        if let Ok(id) = parse_hex_key(&key) {
            functions.insert(
                id as u8,
                FunctionInfo {
                    name: def.name,
                    description: def.description,
                    params: def.params,
                },
            );
        }
    }

    let mut generators = HashMap::new();
    for (key, def) in file.generators {
        if let Ok(id) = parse_hex_key(&key) {
            generators.insert(
                id,
                GeneratorLabelInfo {
                    name: def.name,
                    description: def.description,
                },
            );
        }
    }

    let mut transformers = HashMap::new();
    for (key, def) in file.transformers {
        if let Ok(id) = parse_hex_key(&key) {
            transformers.insert(
                id,
                TransformerLabelInfo {
                    name: def.name,
                    description: def.description,
                },
            );
        }
    }

    Ok(BoardDef {
        name: file.board.name,
        revision: file.board.revision,
        description: file.board.description,
        interfaces,
        peripherals,
        signals,
        user_signals,
        frame_defs,
        palettes,
        functions,
        generators,
        transformers,
        mcus,
    })
}

fn index_key(section: &'static str, key: String) -> Result<u8, Error> {
    key.parse().map_err(|source| Error::Key {
        section,
        key,
        source,
    })
}

/// An LED found among a device's signals.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DiscoveredLed {
    /// The signals' channel.
    pub index: usize,
    /// From the board's name for it, such as `"CAN0"`.
    pub label: String,
    pub colour_signal_id: u16,
    pub state_signal_id: u16,
    pub blink_period_signal_id: u16,
    pub toggle_signal_id: u16,
    /// The interface it indicates, if any.
    pub interface_index: Option<u8>,
    pub interface_type: Option<u8>,
    /// Discovery leaves it default for the caller to read.
    #[serde(flatten)]
    pub state: IndicatorState,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct IndicatorState {
    /// BRGB: brightness in the top byte.
    pub colour: u32,
    /// 0 off, 1 on, 2 blinking.
    pub state: u8,
    /// Milliseconds.
    pub blink_period: u16,
}

/// An LED is a peripheral's SETPOINT COLOUR_RGB signal; its state, blink
/// period and toggle are the same peripheral's signals on its channel. A
/// board name's parenthesised suffix, as in `"LED5 Colour (CAN0)"`, labels it
/// and ties it to that interface.
pub fn discover_leds(
    dsigs: &[dsig::SignalInfo],
    board_def: Option<&BoardDef>,
) -> Vec<DiscoveredLed> {
    use wslib_framelink_protocol::types::*;

    let mut colour_sigs: HashMap<(u8, usize), &dsig::SignalInfo> = HashMap::new();
    let mut state_sigs: HashMap<(u8, usize), u16> = HashMap::new();
    let mut blink_sigs: HashMap<(u8, usize), u16> = HashMap::new();
    let mut toggle_sigs: HashMap<(u8, usize), u16> = HashMap::new();

    for sig in dsigs {
        if sig.target_type != SIGNAL_TARGET_PERIPHERAL
            || sig.channel == SIGNAL_CHANNEL_NONE
            || sig.aspect != ASPECT_DEFAULT
        {
            continue;
        }
        let slot = (sig.target_index, sig.channel as usize);
        match (sig.role, sig.quantity & QTY_BASE_MASK) {
            (ROLE_SETPOINT, QTY_COLOUR_RGB) => {
                colour_sigs.insert(slot, sig);
            }
            (ROLE_SETPOINT, QTY_ENUM) => {
                state_sigs.insert(slot, sig.signal_id);
            }
            (ROLE_CONFIG, QTY_DURATION) => {
                blink_sigs.insert(slot, sig.signal_id);
            }
            (ROLE_COMMAND, QTY_BOOL) => {
                toggle_sigs.insert(slot, sig.signal_id);
            }
            _ => {}
        }
    }

    // Aliases as the board names them: "CAN0", "CAN1", "RS0".
    let iface_aliases: Vec<(u8, String, u8)> = board_def
        .map(|bd| {
            let mut type_counts: HashMap<&str, u8> = HashMap::new();
            let mut sorted_keys: Vec<u8> = bd.interfaces.keys().copied().collect();
            sorted_keys.sort();
            let mut aliases = Vec::new();
            for &iface_idx in &sorted_keys {
                if let Some(iface) = bd.interfaces.get(&iface_idx) {
                    let ordinal = type_counts.entry(&iface.iface_type).or_insert(0);
                    let prefix = match iface.iface_type.as_str() {
                        "can" => "CAN",
                        "canfd" => "CANFD",
                        "rs485" => "RS",
                        "rs232" => "RS232",
                        "lin" => "LIN",
                        _ => "IF",
                    };
                    let iface_type_id = match iface.iface_type.as_str() {
                        "can" => IFACE_CAN,
                        "canfd" => IFACE_CANFD,
                        "rs485" => IFACE_RS485,
                        _ => 0,
                    };
                    aliases.push((iface_idx, format!("{}{}", prefix, ordinal), iface_type_id));
                    *ordinal += 1;
                }
            }
            aliases
        })
        .unwrap_or_default();

    let mut slots: Vec<(u8, usize)> = colour_sigs.keys().copied().collect();
    slots.sort();

    let mut leds = Vec::new();
    for slot in slots {
        let colour = colour_sigs[&slot];
        let idx = slot.1;

        let label = board_def
            .and_then(|bd| bd.signal_name(&colour.key()))
            .and_then(|name| {
                let start = name.find('(')?;
                let end = name.find(')')?;
                Some(name[start + 1..end].to_string())
            })
            .unwrap_or_else(|| format!("LED{}", idx));

        let (interface_index, interface_type) = iface_aliases
            .iter()
            .find(|(_, alias, _)| *alias == label)
            .map(|(iface_idx, _, iface_type_id)| (Some(*iface_idx), Some(*iface_type_id)))
            .unwrap_or((None, None));

        leds.push(DiscoveredLed {
            index: idx,
            label,
            colour_signal_id: colour.signal_id,
            state_signal_id: state_sigs.get(&slot).copied().unwrap_or(0),
            blink_period_signal_id: blink_sigs.get(&slot).copied().unwrap_or(0),
            toggle_signal_id: toggle_sigs.get(&slot).copied().unwrap_or(0),
            interface_index,
            interface_type,
            state: IndicatorState::default(),
        });
    }

    leds
}

/// An LED's activity trigger takes the frame definition and transformer ids
/// from here up, offset by the LED's index, and its signal from
/// [`INDICATOR_SIGNAL_ID_BASE`] up.
pub const INDICATOR_FD_ID_BASE: u16 = 0xFE00;
pub const INDICATOR_XFORM_ID_BASE: u16 = 0xFE00;
pub const INDICATOR_SIGNAL_ID_BASE: u16 = 0xFD00;

/// What frame toggles an LED.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(tag = "type")]
#[non_exhaustive]
pub enum ActivityTrigger {
    AnyFrame,
    FrameId { can_id: u32 },
    FrameMatch { can_id: u32, mask: [u8; 8] },
}

/// `(msg_type, payload)` pairs adding the trigger: the frame definition, then
/// the transformer.
pub fn build_indicator_trigger_messages(
    led: &DiscoveredLed,
    trigger: &ActivityTrigger,
) -> Vec<(u8, Vec<u8>)> {
    use wslib_framelink_protocol::{frame_def, types, xform};

    let fd_id = INDICATOR_FD_ID_BASE + led.index as u16;
    let xform_id = INDICATOR_XFORM_ID_BASE + led.index as u16;
    let sig_id = INDICATOR_SIGNAL_ID_BASE + led.index as u16;
    let toggle_sig = led.toggle_signal_id;
    let interface_index = led.interface_index.unwrap_or(0);
    let interface_type = led.interface_type.unwrap_or(types::IFACE_CAN);

    let (can_id, can_flags) = match trigger {
        ActivityTrigger::AnyFrame => (0u32, frame_def::CAN_FLAG_MATCH_ANY),
        ActivityTrigger::FrameId { can_id } => (*can_id, 0u8),
        ActivityTrigger::FrameMatch { can_id, .. } => (*can_id, 0u8),
    };

    let header = if interface_type == types::IFACE_CAN || interface_type == types::IFACE_CANFD {
        frame_def::FrameHeader::Can {
            can_id,
            dlc: 8,
            flags: can_flags,
        }
    } else {
        frame_def::FrameHeader::Rs485 { framing_mode: 0 }
    };

    let frame_def_info = frame_def::FrameDefInfo {
        frame_def_id: fd_id,
        interface_type,
        header,
        signals: vec![frame_def::FrameSignalDef {
            signal_id: sig_id,
            start_bit: 0,
            bit_length: 1,
            byte_order: 0,
            value_type: 0,
            scale: 1.0,
            offset: 0.0,
        }],
    };

    let xform_info = xform::TransformerInfo {
        transformer_id: xform_id,
        source_frame_def_id: fd_id,
        source_interface: interface_index,
        dest_frame_def_id: types::FRAME_DEF_ID_DEVICE,
        dest_interface: 0xFF,
        enabled: true,
        mappings: vec![xform::SignalMapping {
            source_signal_id: sig_id,
            dest_signal_id: toggle_sig,
            transform: xform::TransformParams::Direct,
        }],
        functions: vec![],
    };

    vec![
        (
            types::MSG_FRAME_DEF_ADD,
            frame_def::build_frame_def_add(&frame_def_info),
        ),
        (types::MSG_XFORM_ADD, xform::build_xform_add(&xform_info)),
    ]
}

/// `(msg_type, payload)` pairs removing the trigger: the transformer first,
/// since it references the frame definition.
pub fn build_indicator_trigger_remove_messages(led_index: usize) -> Vec<(u8, Vec<u8>)> {
    use wslib_framelink_protocol::{frame_def, types, xform};

    let fd_id = INDICATOR_FD_ID_BASE + led_index as u16;
    let xform_id = INDICATOR_XFORM_ID_BASE + led_index as u16;
    vec![
        (types::MSG_XFORM_REMOVE, xform::build_xform_remove(xform_id)),
        (
            types::MSG_FRAME_DEF_REMOVE,
            frame_def::build_frame_def_remove(fd_id),
        ),
    ]
}

/// What drives an LED.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[non_exhaustive]
pub enum IndicatorSource {
    Activity(ActivityTrigger),
    /// Its colour from a palette lookup.
    Palette,
    /// Its colour from a threshold function.
    Threshold,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct IndicatorConfig {
    #[serde(rename = "color")]
    pub colour: u32,
    pub state: u8,
    pub blink_period: u16,
    pub source: Option<IndicatorSource>,
    pub trigger: Option<ActivityTrigger>,
    pub owned_frame_def_id: Option<u16>,
    pub owned_transformer_id: Option<u16>,
    pub gated: bool,
}

impl Default for IndicatorConfig {
    fn default() -> Self {
        Self {
            colour: 0,
            state: 0,
            blink_period: 500,
            source: None,
            trigger: None,
            owned_frame_def_id: None,
            owned_transformer_id: None,
            gated: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wslib_framelink_protocol::types;

    fn key(slug: &str) -> SignalKey {
        parse_signal_key(slug).unwrap()
    }

    #[test]
    fn parse_board_def_reads_mcus_in_declaration_order() {
        let toml = r#"mcus = [
            { chip = "stm32g474", usb = "self" },
            { chip = "esp32", usb = { cdc_interface = 3 }, baud = 115200 },
        ]
        [board]
        name = "t"
        revision = "a""#;
        let bd = parse_board_def(toml).unwrap();
        assert_eq!(
            bd.mcus,
            vec![
                McuInfo {
                    chip: "stm32g474".into(),
                    usb: UsbAccess::Native,
                    baud: None,
                    dfu_alt: DEFAULT_DFU_ALT,
                },
                McuInfo {
                    chip: "esp32".into(),
                    usb: UsbAccess::CdcInterface { interface: 3 },
                    baud: Some(115200),
                    dfu_alt: DEFAULT_DFU_ALT,
                },
            ]
        );
    }

    #[test]
    fn parse_board_def_without_mcus_yields_empty_list() {
        let bd = parse_board_def("[board]\nname=\"t\"\nrevision=\"a\"\n").unwrap();
        assert!(bd.mcus.is_empty());
    }

    #[test]
    fn parse_board_def_rejects_unknown_usb_access_word() {
        let toml = r#"mcus = [{ chip = "esp32", usb = "bogus" }]
        [board]
        name = "t"
        revision = "a""#;
        let err = parse_board_def(toml).unwrap_err().to_string();
        assert!(err.contains("usb"), "{err}");
        assert!(err.contains("bogus"), "{err}");
    }

    #[test]
    fn parse_board_def_rejects_duplicate_mcu_chip() {
        let toml = r#"mcus = [
            { chip = "esp32", usb = "self" },
            { chip = "esp32", usb = "none" },
        ]
        [board]
        name = "t"
        revision = "a""#;
        let err = parse_board_def(toml).unwrap_err().to_string();
        assert!(err.contains("esp32"), "{err}");
    }

    #[test]
    fn parse_board_def_reads_user_signals() {
        let toml = "[board]\nname=\"t\"\nrevision=\"a\"\n\
                    [user_signals.0x0200]\nname=\"Battery SOC\"\nunit=\"%\"\n";
        let bd = parse_board_def(toml).unwrap();
        let info = bd.user_signal_info(0x0200).expect("user signal present");
        assert_eq!(info.name, "Battery SOC");
        assert_eq!(info.unit, "%");
    }

    #[test]
    fn load_board_def_falls_back_to_name_for_unknown_revision() {
        let def = load_board_def("wiredflexlink", "esp32c6-v0.0.1")
            .expect("unknown rev should fall back to the board's def");
        assert_eq!(def.name, "wiredflexlink");
    }

    #[test]
    fn load_wiredflexlink_board() {
        let def = load_board_def("wiredflexlink", "esp32c6-v0.0.2")
            .expect("should find embedded board def");

        assert_eq!(def.name, "wiredflexlink");
        assert_eq!(def.revision, "esp32c6-v0.0.2");

        assert_eq!(def.interface_name(0), Some("CAN0"));
        assert_eq!(def.interface_name(1), Some("CAN1"));
        assert_eq!(def.interface_name(2), Some("RS-485 Port 0"));
        assert_eq!(def.interface_name(3), Some("RS-485 Port 1"));

        assert_eq!(def.peripheral_name(0), Some("Status LEDs"));
        assert_eq!(def.peripheral_name(1), Some("VN9D Load Switch"));
        assert_eq!(def.peripheral_name(2), Some("SoC Temperature"));

        assert!(def.signals.len() >= 93);

        assert_eq!(
            def.signal_name(&key("interface.0.config.datarate")),
            Some("CAN0 Bitrate")
        );
        assert_eq!(
            def.signal_group(&key("interface.0.config.datarate")),
            Some("CAN0")
        );
        assert_eq!(
            def.signal_name(&key("peripheral.0.setpoint.colour_rgb.ch0")),
            Some("LED0 Colour (Status)")
        );
        assert_eq!(
            def.signal_name(&key("peripheral.2.measurement.temperature")),
            Some("SoC Temperature")
        );

        assert_eq!(def.palettes.len(), 3);
        let temp_pal = def
            .palettes
            .iter()
            .find(|p| p.name == "Temperature")
            .unwrap();
        assert_eq!(temp_pal.signal_start, 0x0200);
        assert_eq!(temp_pal.entries.len(), 6);
        let curr_pal = def.palettes.iter().find(|p| p.name == "Current").unwrap();
        assert_eq!(curr_pal.entries.len(), 10);

        assert_eq!(def.functions.len(), 4);
        assert_eq!(def.function_name(0x10), Some("Palette Lookup"));
        assert_eq!(def.function_name(0x13), Some("Gate"));
    }

    #[test]
    fn load_unknown_board_returns_none() {
        assert!(load_board_def("nonexistent", "v0.0").is_none());
    }

    #[test]
    fn embedded_boards_listed() {
        let all = embedded_boards();
        assert!(!all.is_empty());
        assert!(
            all.iter()
                .any(|b| b.name == "wiredflexlink" && b.revision == "esp32c6-v0.0.2")
        );
        // Each entry's TOML must parse cleanly with the board's own parser.
        for b in all {
            parse_board_def(b.toml).unwrap_or_else(|e| {
                panic!(
                    "embedded board {} {} failed to parse: {e}",
                    b.name, b.revision
                )
            });
        }
    }

    #[test]
    fn format_bool_value() {
        let def = load_board_def("wiredflexlink", "esp32c6-v0.0.2").unwrap();
        let k = key("interface.0.config.bool.termination");
        assert_eq!(def.format_value(&k, 1), "true");
        assert_eq!(def.format_value(&k, 0), "false");
    }

    #[test]
    fn format_enum_value() {
        let def = load_board_def("wiredflexlink", "esp32c6-v0.0.2").unwrap();
        let k = key("peripheral.0.setpoint.enum.ch0");
        assert_eq!(def.format_value(&k, 0), "Off");
        assert_eq!(def.format_value(&k, 1), "On");
        assert_eq!(def.format_value(&k, 2), "Blink");
    }

    #[test]
    fn format_temperature() {
        let def = load_board_def("wiredflexlink", "esp32c6-v0.0.2").unwrap();
        let k = key("peripheral.2.measurement.temperature");
        assert_eq!(def.format_value(&k, 250), "25.0 \u{b0}C");
    }

    #[test]
    fn discover_leds_from_board_def() {
        use dsig::SignalInfo;
        use wslib_framelink_protocol::types::*;

        let def = load_board_def("wiredflexlink", "esp32c6-v0.0.2").unwrap();

        let led_sig = |id: u16, role: u8, quantity: u8, channel: u8, value_len: u8| SignalInfo {
            signal_id: id,
            target_type: SIGNAL_TARGET_PERIPHERAL,
            target_index: 0,
            role,
            quantity,
            aspect: ASPECT_DEFAULT,
            channel,
            flags: DSIG_FLAG_WRITABLE,
            value_type: 0,
            value_len,
            scale: 1.0,
            offset: 0.0,
            min_raw: 0,
            max_raw: 0,
        };

        // Build a minimal signal list mimicking what the device would report
        // for 6 LEDs (channels 0-5) — Status + SW0-3 + CAN0
        let mut dsigs = Vec::new();
        for ch in 0u8..6 {
            let base = 0xFF40 + ch as u16 * 4;
            dsigs.push(led_sig(base, ROLE_SETPOINT, QTY_COLOUR_RGB, ch, 4));
            dsigs.push(led_sig(base + 1, ROLE_SETPOINT, QTY_ENUM, ch, 1));
            dsigs.push(led_sig(base + 2, ROLE_CONFIG, QTY_DURATION, ch, 2));
            dsigs.push(led_sig(base + 3, ROLE_COMMAND, QTY_BOOL, ch, 1));
        }

        let leds = discover_leds(&dsigs, Some(&def));

        assert_eq!(leds.len(), 6);

        // Channel 0 = Status (from board def name "LED0 Colour (Status)")
        assert_eq!(leds[0].index, 0);
        assert_eq!(leds[0].label, "Status");

        // Channel 5 = CAN0 indicator, matched to interface 0
        assert_eq!(leds[5].label, "CAN0");
        assert_eq!(leds[5].interface_index, Some(0));
        assert_eq!(leds[5].interface_type, Some(types::IFACE_CAN));

        for led in &leds {
            assert_ne!(led.colour_signal_id, 0);
            assert_ne!(led.state_signal_id, 0);
            assert_ne!(led.blink_period_signal_id, 0);
            assert_ne!(led.toggle_signal_id, 0);
        }
    }
}
