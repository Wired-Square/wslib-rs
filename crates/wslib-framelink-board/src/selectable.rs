//! The signals a picker offers, in three tiers: from frame definitions, the
//! device's own, and user-created.

use std::collections::HashSet;

use serde::Serialize;

use crate::BoardDef;
use crate::display::resolve_signal_name;
use wslib_framelink_protocol::{dsig, frame_def, types};

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum SignalTier {
    FrameDef,
    Device,
    User,
}

/// For a device signal reporting no length.
const DEFAULT_VALUE_LEN_BYTES: u8 = 4;

#[derive(Debug, Clone, Serialize)]
pub struct SelectableSignal {
    pub signal_id: u16,
    pub name: String,
    pub group: String,
    pub tier: SignalTier,
    /// A frame definition's width, else the value's.
    pub bit_length: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub frame_def_id: Option<u16>,
}

/// Sorts a device's frame definitions and signals into tiers, named from the
/// board where it can. A signal in the device's reserved id range is the
/// device's; anything else no frame definition owns is the user's.
pub fn categorise_signals(
    frame_defs: &[frame_def::FrameDefInfo],
    device_signals: &[dsig::SignalInfo],
    board_def: Option<&BoardDef>,
) -> Vec<SelectableSignal> {
    let mut result = Vec::new();

    let mut frame_def_signal_ids = HashSet::new();

    for fd in frame_defs {
        let group = board_def
            .and_then(|bd| bd.frame_def_name(fd.frame_def_id))
            .map(|s| s.to_string())
            .unwrap_or_else(|| format!("Frame 0x{:04X}", fd.frame_def_id));

        for sig in &fd.signals {
            frame_def_signal_ids.insert(sig.signal_id);

            let name =
                resolve_signal_name(fd.frame_def_id, sig.start_bit, sig.bit_length, board_def);

            result.push(SelectableSignal {
                signal_id: sig.signal_id,
                name,
                group: group.clone(),
                tier: SignalTier::FrameDef,
                bit_length: sig.bit_length,
                frame_def_id: Some(fd.frame_def_id),
            });
        }
    }

    for sig in device_signals {
        if frame_def_signal_ids.contains(&sig.signal_id) {
            continue;
        }

        let is_device_signal = sig.signal_id >= types::DEVICE_SIGNAL_ID_BASE
            && sig.signal_id <= types::DEVICE_SIGNAL_ID_MAX;

        let key = sig.key();
        let board_info = board_def.and_then(|bd| bd.signal_info(&key));

        let (name, group, tier) = if is_device_signal {
            let name = board_info
                .map(|i| i.name.clone())
                .unwrap_or_else(|| sig.semantic_name(None));
            let group = board_info
                .filter(|i| !i.group.is_empty())
                .map(|i| i.group.clone())
                .unwrap_or_else(|| default_group(sig));
            (name, group, SignalTier::Device)
        } else {
            let user_info = board_def.and_then(|bd| bd.user_signal_info(sig.signal_id));
            let name = user_info
                .map(|i| i.name.clone())
                .unwrap_or_else(|| format!("User Signal 0x{:04X}", sig.signal_id));
            let group = user_info
                .filter(|i| !i.group.is_empty())
                .map(|i| i.group.clone())
                .unwrap_or_else(|| "User".to_string());
            (name, group, SignalTier::User)
        };

        let bit_length = if sig.value_len > 0 {
            sig.value_len as u16 * 8
        } else {
            DEFAULT_VALUE_LEN_BYTES as u16 * 8
        };

        result.push(SelectableSignal {
            signal_id: sig.signal_id,
            name,
            group,
            tier,
            bit_length,
            frame_def_id: None,
        });
    }

    result
}

fn default_group(sig: &dsig::SignalInfo) -> String {
    match sig.target_type {
        types::SIGNAL_TARGET_INTERFACE => format!("IF{}", sig.target_index),
        types::SIGNAL_TARGET_PERIPHERAL => format!("Peripheral {}", sig.target_index),
        _ => "Device".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wslib_framelink_protocol::dsig::{SignalInfo as DsigInfo, SignalKey};
    use wslib_framelink_protocol::frame_def::{FrameDefInfo, FrameHeader, FrameSignalDef};

    fn bitrate_key() -> SignalKey {
        SignalKey {
            target_type: types::SIGNAL_TARGET_INTERFACE,
            target_index: 0,
            role: types::ROLE_CONFIG,
            quantity: types::QTY_DATARATE,
            aspect: types::ASPECT_DEFAULT,
            channel: types::SIGNAL_CHANNEL_NONE,
        }
    }

    fn termination_key() -> SignalKey {
        SignalKey {
            target_type: types::SIGNAL_TARGET_INTERFACE,
            target_index: 0,
            role: types::ROLE_CONFIG,
            quantity: types::QTY_BOOL,
            aspect: types::ASPECT_TERMINATION,
            channel: types::SIGNAL_CHANNEL_NONE,
        }
    }

    fn test_board_def() -> BoardDef {
        use std::collections::HashMap;

        let mut signals = HashMap::new();
        signals.insert(
            bitrate_key(),
            crate::SignalInfo {
                name: "CAN0 Bitrate".to_string(),
                description: String::new(),
                group: "CAN0".to_string(),
                unit: "bps".to_string(),
                format: "number".to_string(),
                enum_values: HashMap::new(),
            },
        );
        signals.insert(
            termination_key(),
            crate::SignalInfo {
                name: "CAN0 Termination".to_string(),
                description: String::new(),
                group: "CAN0".to_string(),
                unit: String::new(),
                format: "bool".to_string(),
                enum_values: HashMap::new(),
            },
        );

        let mut frame_defs = HashMap::new();
        frame_defs.insert(
            0x0001,
            crate::FrameDefDisplayInfo {
                name: "Engine Status".to_string(),
                description: String::new(),
                interface_type: "can".to_string(),
                signals: vec![crate::FrameSignalDisplayInfo {
                    slug: "engine_rpm".to_string(),
                    name: "Engine RPM".to_string(),
                    start_bit: 0,
                    bit_length: 16,
                    byte_order: "le".to_string(),
                    value_type: "unsigned".to_string(),
                    scale: 1.0,
                    offset: 0.0,
                    unit: "rpm".to_string(),
                }],
            },
        );

        BoardDef {
            name: "testboard".to_string(),
            revision: "v1.0".to_string(),
            description: "Test board".to_string(),
            interfaces: HashMap::new(),
            peripherals: HashMap::new(),
            signals,
            user_signals: HashMap::new(),
            frame_defs,
            palettes: Vec::new(),
            functions: HashMap::new(),
            generators: HashMap::new(),
            transformers: HashMap::new(),
            mcus: Vec::new(),
        }
    }

    fn make_frame_def(id: u16, signal_ids: &[u16]) -> FrameDefInfo {
        FrameDefInfo {
            frame_def_id: id,
            interface_type: 1,
            header: FrameHeader::Can {
                can_id: 0x100,
                dlc: 8,
                flags: 0,
            },
            signals: signal_ids
                .iter()
                .enumerate()
                .map(|(i, &sid)| FrameSignalDef {
                    signal_id: sid,
                    start_bit: (i as u16) * 16,
                    bit_length: 16,
                    byte_order: 0,
                    value_type: 0,
                    scale: 1.0,
                    offset: 0.0,
                })
                .collect(),
        }
    }

    fn make_dsig(signal_id: u16) -> DsigInfo {
        DsigInfo {
            signal_id,
            target_type: types::SIGNAL_TARGET_DEVICE,
            target_index: 0,
            role: types::ROLE_STATUS,
            quantity: types::QTY_RAW,
            aspect: types::ASPECT_DEFAULT,
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

    fn make_keyed_dsig(signal_id: u16, key: SignalKey) -> DsigInfo {
        DsigInfo {
            signal_id,
            target_type: key.target_type,
            target_index: key.target_index,
            role: key.role,
            quantity: key.quantity,
            aspect: key.aspect,
            channel: key.channel,
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
    fn frame_def_signals_get_correct_tier_and_names() {
        let bd = test_board_def();
        let frame_defs = vec![make_frame_def(0x0001, &[0x0010, 0x0011])];

        let result = categorise_signals(&frame_defs, &[], Some(&bd));

        let fd_signals: Vec<_> = result
            .iter()
            .filter(|s| s.tier == SignalTier::FrameDef)
            .collect();

        assert_eq!(fd_signals.len(), 2);
        assert_eq!(fd_signals[0].group, "Engine Status");
        assert_eq!(fd_signals[0].frame_def_id, Some(0x0001));

        assert_eq!(fd_signals[0].name, "Engine RPM");

        assert_eq!(fd_signals[1].name, "Bit 16:16");
    }

    #[test]
    fn user_signal_name_resolves_from_board_def() {
        use std::collections::HashMap;
        let mut bd = test_board_def();
        bd.user_signals.insert(
            0x0200,
            crate::SignalInfo {
                name: "Battery SOC".to_string(),
                description: String::new(),
                group: "Pack".to_string(),
                unit: "%".to_string(),
                format: "number".to_string(),
                enum_values: HashMap::new(),
            },
        );

        let user_signals = vec![make_dsig(0x0200)];
        let result = categorise_signals(&[], &user_signals, Some(&bd));

        let us = result.iter().find(|s| s.signal_id == 0x0200).unwrap();
        assert_eq!(us.tier, SignalTier::User);
        assert_eq!(us.name, "Battery SOC");
        assert_eq!(us.group, "Pack");
    }

    #[test]
    fn user_signal_without_board_def_falls_back() {
        let user_signals = vec![make_dsig(0x0200)];
        let result = categorise_signals(&[], &user_signals, None);
        let us = result.iter().find(|s| s.signal_id == 0x0200).unwrap();
        assert_eq!(us.tier, SignalTier::User);
        assert_eq!(us.name, "User Signal 0x0200");
        assert_eq!(us.group, "User");
    }

    #[test]
    fn unknown_frame_def_falls_back_to_hex_group() {
        let frame_defs = vec![make_frame_def(0x0099, &[0x0010])];

        let result = categorise_signals(&frame_defs, &[], None);

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].group, "Frame 0x0099");
        assert_eq!(result[0].tier, SignalTier::FrameDef);
    }

    #[test]
    fn device_range_signals_get_device_tier_with_board_names() {
        let bd = test_board_def();
        let device_signals = vec![
            make_keyed_dsig(0xFF00, bitrate_key()),
            make_keyed_dsig(0xFF01, termination_key()),
        ];

        let result = categorise_signals(&[], &device_signals, Some(&bd));

        let device_tier: Vec<_> = result
            .iter()
            .filter(|s| s.tier == SignalTier::Device)
            .collect();

        assert_eq!(device_tier.len(), 2);

        let bitrate = device_tier
            .iter()
            .find(|s| s.signal_id == 0xFF00)
            .expect("should find CAN0 Bitrate");
        assert_eq!(bitrate.name, "CAN0 Bitrate");
        assert_eq!(bitrate.group, "CAN0");
        assert!(bitrate.frame_def_id.is_none());
    }

    #[test]
    fn device_range_signals_without_board_def_use_semantic_names() {
        let device_signals = vec![make_keyed_dsig(0xFF00, bitrate_key())];

        let result = categorise_signals(&[], &device_signals, None);

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].tier, SignalTier::Device);
        assert_eq!(result[0].name, "Bitrate");
        assert_eq!(result[0].group, "IF0");
    }

    #[test]
    fn unknown_device_signals_get_user_tier() {
        let bd = test_board_def();
        let frame_defs = vec![make_frame_def(0x0001, &[0x0010])];
        let device_signals = vec![
            make_keyed_dsig(0xFF00, bitrate_key()), // device range — Device tier
            make_dsig(0x0010),                      // frame def signal — should be excluded
            make_dsig(0x0200),                      // unknown — should be User tier
            make_dsig(0x0201),                      // unknown — should be User tier
        ];

        let result = categorise_signals(&frame_defs, &device_signals, Some(&bd));

        let user_signals: Vec<_> = result
            .iter()
            .filter(|s| s.tier == SignalTier::User)
            .collect();

        assert_eq!(user_signals.len(), 2);
        assert_eq!(user_signals[0].signal_id, 0x0200);
        assert_eq!(user_signals[0].name, "User Signal 0x0200");
        assert_eq!(user_signals[0].group, "User");
        assert!(user_signals[0].frame_def_id.is_none());
    }

    #[test]
    fn empty_inputs_produce_empty_result() {
        let result = categorise_signals(&[], &[], None);
        assert!(result.is_empty());
    }

    #[test]
    fn device_signals_with_empty_group_default_by_target() {
        // A device-target signal with no board-def group falls back to
        // "Device"; interface targets fall back to "IF<n>".
        let result = categorise_signals(&[], &[make_dsig(0xFF40)], None);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].tier, SignalTier::Device);
        assert_eq!(result[0].group, "Device");
    }

    #[test]
    fn all_three_tiers_coexist() {
        let bd = test_board_def();
        let frame_defs = vec![make_frame_def(0x0001, &[0x0010])];
        let device_signals = vec![
            make_keyed_dsig(0xFF00, bitrate_key()),
            make_keyed_dsig(0xFF01, termination_key()),
            make_dsig(0x0300),
        ];

        let result = categorise_signals(&frame_defs, &device_signals, Some(&bd));

        let fd_count = result
            .iter()
            .filter(|s| s.tier == SignalTier::FrameDef)
            .count();
        let dev_count = result
            .iter()
            .filter(|s| s.tier == SignalTier::Device)
            .count();
        let user_count = result.iter().filter(|s| s.tier == SignalTier::User).count();

        assert_eq!(fd_count, 1);
        assert_eq!(dev_count, 2); // the two device-range signals
        assert_eq!(user_count, 1); // 0x0300
    }
}
