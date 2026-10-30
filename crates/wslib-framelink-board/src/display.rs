//! Display names for interfaces, frame definitions, signals and targets: the
//! board's where it has one, else one derived from the capabilities.

use crate::BoardDef;
use wslib_framelink_protocol::capabilities::Capabilities;
use wslib_framelink_protocol::{dsig, types};

/// The board's name for the interface, else `"IF{index}"`.
pub fn resolve_iface_display(
    index: u8,
    board_def: Option<&BoardDef>,
    caps: Option<&Capabilities>,
) -> String {
    if let Some(bd) = board_def
        && let Some(name) = bd.interface_name(index)
    {
        return name.to_string();
    }
    if let Some(c) = caps {
        for iface in &c.interfaces {
            if iface.index == index {
                return format!("IF{}", index);
            }
        }
    }
    format!("IF{}", index)
}

/// `"Device Signals"` for the device's sentinel, else the board's name, else
/// `"FD:0xNNNN"`.
pub fn resolve_frame_def_display(id: u16, board_def: Option<&BoardDef>) -> String {
    if id == types::FRAME_DEF_ID_DEVICE {
        return "Device Signals".to_string();
    }
    board_def
        .and_then(|bd| bd.frame_def_name(id))
        .map(|s| s.to_string())
        .unwrap_or_else(|| format!("FD:0x{:04X}", id))
}

/// The board's name for the signal at these bits, else `"Bit start:length"`.
pub fn resolve_signal_name(
    frame_def_id: u16,
    start_bit: u16,
    bit_length: u16,
    board_def: Option<&BoardDef>,
) -> String {
    if let Some(bd) = board_def
        && let Some(fd_info) = bd.frame_def_info(frame_def_id)
    {
        for fs in &fd_info.signals {
            if fs.start_bit == start_bit && fs.bit_length == bit_length {
                return fs.name.clone();
            }
        }
    }
    format!("Bit {}:{}", start_bit, bit_length)
}

pub fn resolve_target_name(
    sig: &dsig::SignalInfo,
    def: &BoardDef,
    caps: Option<&Capabilities>,
) -> String {
    match sig.target_type {
        types::SIGNAL_TARGET_INTERFACE => def
            .interface_name(sig.target_index)
            .map(|n| n.to_string())
            .or_else(|| {
                caps.and_then(|c| c.iface_type(sig.target_index))
                    .map(|t| types::interface_name(t).to_string())
            })
            .unwrap_or_else(|| "Interface".to_string()),
        types::SIGNAL_TARGET_PERIPHERAL => def
            .peripheral_name(sig.target_index)
            .map(|n| n.to_string())
            .or_else(|| {
                caps.and_then(|c| {
                    c.peripherals
                        .iter()
                        .find(|p| p.index == sig.target_index)
                        .map(|p| types::peripheral_kind_name(p.kind).to_string())
                })
            })
            .unwrap_or_else(|| "Peripheral".to_string()),
        types::SIGNAL_TARGET_DEVICE => "Device".to_string(),
        _ => "Unknown".to_string(),
    }
}

/// The interface's signal with this role, quantity and aspect, the writable
/// twin first.
pub fn find_iface_signal(
    signals: &[dsig::SignalInfo],
    iface_index: u8,
    role: u8,
    quantity: u8,
    aspect: u8,
) -> Option<u16> {
    let mut matches = signals.iter().filter(|s| {
        s.target_type == types::SIGNAL_TARGET_INTERFACE
            && s.target_index == iface_index
            && s.role == role
            && s.quantity & types::QTY_BASE_MASK == quantity & types::QTY_BASE_MASK
            && s.aspect == aspect
    });
    let first = matches.next()?;
    let writable = std::iter::once(first)
        .chain(matches)
        .find(|s| s.is_writable());
    Some(writable.unwrap_or(first).signal_id)
}

pub fn format_iface_value(sig: &dsig::SignalInfo, value: u64) -> String {
    let tuple = (sig.role, sig.quantity & types::QTY_BASE_MASK, sig.aspect);
    match tuple {
        (types::ROLE_CONFIG, types::QTY_DATARATE, types::ASPECT_DEFAULT) => {
            format!("{} bps", value)
        }
        (types::ROLE_CONFIG, types::QTY_BOOL, types::ASPECT_STANDBY) => {
            if value != 0 {
                "Standby".to_string()
            } else {
                "Active".to_string()
            }
        }
        (_, types::QTY_BOOL, _) => {
            if value != 0 {
                "On".to_string()
            } else {
                "Off".to_string()
            }
        }
        (types::ROLE_CONFIG, types::QTY_ENUM, types::ASPECT_PARITY) => match value {
            0 => "None".to_string(),
            1 => "Odd".to_string(),
            2 => "Even".to_string(),
            _ => format!("{}", value),
        },
        (types::ROLE_CONFIG, types::QTY_ENUM, types::ASPECT_STOP_BITS) => match value {
            0 => "0.5".to_string(),
            1 => "1".to_string(),
            2 => "1.5".to_string(),
            3 => "2".to_string(),
            _ => format!("{}", value),
        },
        (types::ROLE_CONFIG, types::QTY_ENUM, types::ASPECT_DATA_BITS) => match value {
            0 => "5".to_string(),
            1 => "6".to_string(),
            2 => "7".to_string(),
            3 => "8".to_string(),
            4 => "9".to_string(),
            _ => format!("{}", value),
        },
        _ => format!("{}", value),
    }
}

/// An interface by the board's name for it (ignoring case, spaces and
/// hyphens), by type and index such as `"can0"`, or by its bare index.
pub fn resolve_iface_index(
    name: &str,
    board_def: Option<&BoardDef>,
    caps: Option<&Capabilities>,
) -> Option<u8> {
    if let Some(def) = board_def {
        let input = name.replace([' ', '-'], "").to_lowercase();
        for idx in 0..=255u8 {
            if let Some(iface_name) = def.interface_name(idx) {
                let normalised = iface_name.replace([' ', '-'], "").to_lowercase();
                if normalised == input {
                    return Some(idx);
                }
            }
        }
    }

    if let Some(caps) = caps {
        let lower = name.to_lowercase();
        for iface in &caps.interfaces {
            let type_name = types::interface_name(iface.iface_type)
                .replace([' ', '-'], "")
                .to_lowercase();
            let pattern = format!("{}{}", type_name, iface.index);
            if lower == pattern {
                return Some(iface.index);
            }
        }
    }

    name.parse::<u8>().ok()
}

/// By the capabilities, else by whether the board's name for it says CAN.
pub fn is_can_interface(
    index: u8,
    board_def: Option<&BoardDef>,
    caps: Option<&Capabilities>,
) -> bool {
    if let Some(caps) = caps
        && let Some(iface) = caps.interfaces.iter().find(|i| i.index == index)
    {
        return iface.iface_type == types::IFACE_CAN || iface.iface_type == types::IFACE_CANFD;
    }

    if let Some(def) = board_def
        && let Some(name) = def.interface_name(index)
    {
        return name.to_lowercase().contains("can");
    }

    false
}

#[derive(Debug, Clone)]
pub struct ColourPreset {
    pub name: &'static str,
    pub brgb: u32,
}

/// Named BRGB colours for an LED.
pub const COLOUR_PRESETS: &[ColourPreset] = &[
    ColourPreset {
        name: "Green",
        brgb: 0xFF00FF00,
    },
    ColourPreset {
        name: "Red",
        brgb: 0xFFFF0000,
    },
    ColourPreset {
        name: "Blue",
        brgb: 0xFF0000FF,
    },
    ColourPreset {
        name: "Yellow",
        brgb: 0xFFFFFF00,
    },
    ColourPreset {
        name: "Orange",
        brgb: 0xFFFF8000,
    },
    ColourPreset {
        name: "White",
        brgb: 0xFFFFFFFF,
    },
    ColourPreset {
        name: "Dim Green",
        brgb: 0x4000FF00,
    },
    ColourPreset {
        name: "Dim Red",
        brgb: 0x40FF0000,
    },
];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::load_board_def;

    #[test]
    fn resolve_iface_from_board_def() {
        let bd = load_board_def("wiredflexlink", "esp32c6-v0.0.2").unwrap();
        assert_eq!(resolve_iface_display(0, Some(&bd), None), "CAN0");
        assert_eq!(resolve_iface_display(2, Some(&bd), None), "RS-485 Port 0");
    }

    #[test]
    fn resolve_iface_fallback() {
        assert_eq!(resolve_iface_display(99, None, None), "IF99");
    }

    #[test]
    fn resolve_frame_def_device() {
        assert_eq!(
            resolve_frame_def_display(types::FRAME_DEF_ID_DEVICE, None),
            "Device Signals"
        );
    }

    #[test]
    fn resolve_frame_def_from_board() {
        let bd = load_board_def("wiredflexlink", "esp32c6-v0.0.2").unwrap();
        assert_eq!(resolve_frame_def_display(0x9999, Some(&bd)), "FD:0x9999");
    }

    #[test]
    fn resolve_signal_fallback() {
        assert_eq!(resolve_signal_name(0, 8, 16, None), "Bit 8:16");
    }

    fn iface_sig(role: u8, quantity: u8, aspect: u8) -> dsig::SignalInfo {
        dsig::SignalInfo {
            signal_id: 0xFF00,
            target_type: types::SIGNAL_TARGET_INTERFACE,
            target_index: 0,
            role,
            quantity,
            aspect,
            channel: types::SIGNAL_CHANNEL_NONE,
            flags: 0,
            value_type: 0,
            value_len: 4,
            scale: 1.0,
            offset: 0.0,
            min_raw: 0,
            max_raw: 0,
        }
    }

    #[test]
    fn format_bitrate() {
        let sig = iface_sig(
            types::ROLE_CONFIG,
            types::QTY_DATARATE,
            types::ASPECT_DEFAULT,
        );
        assert_eq!(format_iface_value(&sig, 500000), "500000 bps");
    }

    #[test]
    fn format_termination() {
        let sig = iface_sig(
            types::ROLE_CONFIG,
            types::QTY_BOOL,
            types::ASPECT_TERMINATION,
        );
        assert_eq!(format_iface_value(&sig, 1), "On");
        assert_eq!(format_iface_value(&sig, 0), "Off");
    }

    #[test]
    fn format_standby() {
        let sig = iface_sig(types::ROLE_CONFIG, types::QTY_BOOL, types::ASPECT_STANDBY);
        assert_eq!(format_iface_value(&sig, 1), "Standby");
        assert_eq!(format_iface_value(&sig, 0), "Active");
    }

    #[test]
    fn find_iface_signal_prefers_writable_twin() {
        let mut ro = iface_sig(types::ROLE_CONFIG, types::QTY_BOOL, types::ASPECT_DEFAULT);
        ro.signal_id = 0xFF10;
        let mut rw = ro.clone();
        rw.signal_id = 0xFF11;
        rw.flags = types::DSIG_FLAG_WRITABLE;

        let found = find_iface_signal(
            &[ro, rw],
            0,
            types::ROLE_CONFIG,
            types::QTY_BOOL,
            types::ASPECT_DEFAULT,
        );
        assert_eq!(found, Some(0xFF11));
    }

    #[test]
    fn resolve_iface_index_from_board_def() {
        let bd = load_board_def("wiredflexlink", "esp32c6-v0.0.2").unwrap();
        assert_eq!(resolve_iface_index("CAN0", Some(&bd), None), Some(0));
        assert_eq!(resolve_iface_index("can0", Some(&bd), None), Some(0));
        assert_eq!(
            resolve_iface_index("RS-485 Port 0", Some(&bd), None),
            Some(2)
        );
        assert_eq!(resolve_iface_index("rs485port0", Some(&bd), None), Some(2));
    }

    #[test]
    fn resolve_iface_index_numeric_fallback() {
        assert_eq!(resolve_iface_index("3", None, None), Some(3));
        assert_eq!(resolve_iface_index("nope", None, None), None);
    }

    #[test]
    fn is_can_interface_from_board_def() {
        let bd = load_board_def("wiredflexlink", "esp32c6-v0.0.2").unwrap();
        assert!(is_can_interface(0, Some(&bd), None));
        assert!(is_can_interface(1, Some(&bd), None));
        assert!(!is_can_interface(2, Some(&bd), None)); // RS-485
    }
}
