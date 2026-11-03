//! A board TOML brought up to date with a live device, edited in place.

use std::collections::HashSet;

use crate::{editable, toml_schema};
use wslib_framelink_protocol::dsig::{format_signal_key, parse_signal_key};
use wslib_framelink_protocol::{capabilities, dsig, frame_def, generator, types, xform};

/// What a sync added, and what the TOML has that the device does not.
#[derive(Debug, Default)]
pub struct SyncResult {
    pub added: Vec<String>,
    pub stale: Vec<String>,
}

pub fn iface_type_to_toml(iface_type: u8) -> &'static str {
    types::interface_slug(iface_type)
}

pub fn periph_kind_to_toml(kind: u8) -> &'static str {
    types::peripheral_kind_slug(kind)
}

pub fn sync_interfaces(
    doc: &mut toml_edit::DocumentMut,
    caps: &capabilities::Capabilities,
) -> SyncResult {
    let mut result = SyncResult::default();

    if doc.get("interfaces").is_none() {
        doc["interfaces"] = toml_edit::Item::Table(toml_edit::Table::new());
    }

    for iface in &caps.interfaces {
        let key = iface.index.to_string();
        let ifaces_table = doc["interfaces"].as_table_mut().unwrap();

        if ifaces_table.get(&key).is_none() {
            let type_name = types::interface_name(iface.iface_type);
            let placeholder = format!("{}{}", type_name, iface.index);

            let mut entry = toml_edit::InlineTable::new();
            entry.insert("name", placeholder.into());
            entry.insert("type", iface_type_to_toml(iface.iface_type).into());

            ifaces_table[&key] = toml_edit::Item::Value(toml_edit::Value::InlineTable(entry));

            result.added.push(format!(
                "interface {} ({} index {})",
                key, type_name, iface.index
            ));
        }
    }

    result
}

pub fn sync_peripherals(
    doc: &mut toml_edit::DocumentMut,
    caps: &capabilities::Capabilities,
) -> SyncResult {
    let mut result = SyncResult::default();

    if doc.get("peripherals").is_none() {
        doc["peripherals"] = toml_edit::Item::Table(toml_edit::Table::new());
    }

    for periph in &caps.peripherals {
        let key = periph.index.to_string();
        let periphs_table = doc["peripherals"].as_table_mut().unwrap();

        if periphs_table.get(&key).is_none() {
            let kind_name = types::peripheral_kind_name(periph.kind);
            let placeholder = format!("{} {}", kind_name, periph.index);

            let mut entry = toml_edit::InlineTable::new();
            entry.insert("name", placeholder.into());
            entry.insert("kind", periph_kind_to_toml(periph.kind).into());

            periphs_table[&key] = toml_edit::Item::Value(toml_edit::Value::InlineTable(entry));

            result.added.push(format!(
                "peripheral {} ({} index {})",
                key, kind_name, periph.index
            ));
        }
    }

    result
}

pub fn sync_device_signals(
    doc: &mut toml_edit::DocumentMut,
    device_signals: &[dsig::SignalInfo],
) -> SyncResult {
    let mut result = SyncResult::default();

    if doc.get("signals").is_none() {
        doc["signals"] = toml_edit::Item::Table(toml_edit::Table::new());
    }

    let device_keys: HashSet<dsig::SignalKey> = device_signals.iter().map(|s| s.key()).collect();

    let signals_table = doc["signals"].as_table_mut().unwrap();

    for sig in device_signals {
        let key = format_signal_key(&sig.key());

        // A user signal's zeroed descriptor slugs to an unparseable
        // `unknown.*`, which would stop the TOML loading.
        if parse_signal_key(&key).is_err() {
            continue;
        }

        if signals_table.get(&key).is_none() {
            let mut entry = toml_edit::Table::new();
            entry.insert(
                "name",
                toml_edit::Item::Value(sig.semantic_name(None).into()),
            );
            entry.insert("group", toml_edit::Item::Value("".into()));
            entry.insert("format", toml_edit::Item::Value("number".into()));

            signals_table[&key] = toml_edit::Item::Table(entry);

            result.added.push(format!(
                "signal {} (target: {}, index: {})",
                key,
                types::signal_target_name(sig.target_type),
                sig.target_index
            ));
        }
    }

    let existing_keys: Vec<String> = signals_table.iter().map(|(k, _)| k.to_string()).collect();

    for key in existing_keys {
        if let Ok(parsed) = parse_signal_key(&key)
            && !device_keys.contains(&parsed)
        {
            result.stale.push(format!("signal {}", key));
        }
    }

    result
}

pub fn sync_frame_defs(
    doc: &mut toml_edit::DocumentMut,
    device_frame_defs: &[frame_def::FrameDefInfo],
) -> SyncResult {
    let mut result = SyncResult::default();

    if doc.get("frame_defs").is_none() {
        doc["frame_defs"] = toml_edit::Item::Table(toml_edit::Table::new());
    }

    let device_fd_ids: HashSet<u16> = device_frame_defs.iter().map(|f| f.frame_def_id).collect();

    let fd_table = doc["frame_defs"].as_table_mut().unwrap();

    for fdef in device_frame_defs {
        let key = format!("0x{:04X}", fdef.frame_def_id);

        if fd_table.get(&key).is_none() {
            fd_table[&key] = toml_edit::Item::Table(editable::frame_def_table(
                &editable::frame_def_from_device(fdef),
            ));

            let header_desc = match &fdef.header {
                frame_def::FrameHeader::Can { can_id, dlc, .. } => {
                    format!("CAN 0x{:03X} DLC:{}", can_id, dlc)
                }
                frame_def::FrameHeader::Rs485 { framing_mode } => {
                    format!("RS-485 mode:{}", framing_mode)
                }
                _ => "unknown header".to_string(),
            };

            result.added.push(format!(
                "frame_def {} ({}, {} signals)",
                key,
                header_desc,
                fdef.signals.len()
            ));
        }
    }

    let existing_keys: Vec<String> = fd_table.iter().map(|(k, _)| k.to_string()).collect();

    for key in existing_keys {
        if let Ok(id) = toml_schema::parse_hex_key(&key)
            && !device_fd_ids.contains(&id)
        {
            result
                .stale
                .push(format!("frame_def {} (0x{:04X})", key, id));
        }
    }

    result
}

pub fn sync_generators(
    doc: &mut toml_edit::DocumentMut,
    generators: &[generator::GeneratorInfo],
) -> SyncResult {
    let mut result = SyncResult::default();

    if doc.get("generators").is_none() {
        doc["generators"] = toml_edit::Item::Table(toml_edit::Table::new());
    }

    let device_gen_ids: HashSet<u16> = generators.iter().map(|g| g.generator_id).collect();

    let gen_table = doc["generators"].as_table_mut().unwrap();

    for generator in generators {
        let key = format!("0x{:04X}", generator.generator_id);

        if gen_table.get(&key).is_none() {
            let mut entry = toml_edit::Table::new();
            entry.insert(
                "name",
                toml_edit::Item::Value(
                    format!("Generator 0x{:04X}", generator.generator_id).into(),
                ),
            );
            entry.insert("description", toml_edit::Item::Value("".into()));

            gen_table[&key] = toml_edit::Item::Table(entry);

            result.added.push(format!(
                "generator {} (frame_def: 0x{:04X}, iface: {})",
                key, generator.frame_def_id, generator.interface_index
            ));
        }
    }

    let existing_keys: Vec<String> = gen_table.iter().map(|(k, _)| k.to_string()).collect();

    for key in existing_keys {
        if let Ok(id) = toml_schema::parse_hex_key(&key)
            && !device_gen_ids.contains(&id)
        {
            result
                .stale
                .push(format!("generator {} (0x{:04X})", key, id));
        }
    }

    result
}

pub fn sync_transformers(
    doc: &mut toml_edit::DocumentMut,
    transformers: &[xform::TransformerInfo],
) -> SyncResult {
    let mut result = SyncResult::default();

    if doc.get("transformers").is_none() {
        doc["transformers"] = toml_edit::Item::Table(toml_edit::Table::new());
    }

    let device_xform_ids: HashSet<u16> = transformers.iter().map(|x| x.transformer_id).collect();

    let xform_table = doc["transformers"].as_table_mut().unwrap();

    for xf in transformers {
        let key = format!("0x{:04X}", xf.transformer_id);

        if xform_table.get(&key).is_none() {
            let mut entry = toml_edit::Table::new();
            entry.insert(
                "name",
                toml_edit::Item::Value(format!("Transformer 0x{:04X}", xf.transformer_id).into()),
            );
            entry.insert("description", toml_edit::Item::Value("".into()));

            xform_table[&key] = toml_edit::Item::Table(entry);

            result.added.push(format!(
                "transformer {} (src_fd: 0x{:04X}, dst_fd: 0x{:04X})",
                key, xf.source_frame_def_id, xf.dest_frame_def_id
            ));
        }
    }

    let existing_keys: Vec<String> = xform_table.iter().map(|(k, _)| k.to_string()).collect();

    for key in existing_keys {
        if let Ok(id) = toml_schema::parse_hex_key(&key)
            && !device_xform_ids.contains(&id)
        {
            result
                .stale
                .push(format!("transformer {} (0x{:04X})", key, id));
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use wslib_framelink_protocol::capabilities::{Capabilities, Interface, Peripheral};

    fn empty_doc() -> toml_edit::DocumentMut {
        "[board]\nname = \"test\"\n".parse().unwrap()
    }

    fn dsig(signal_id: u16, key: dsig::SignalKey) -> dsig::SignalInfo {
        dsig::SignalInfo {
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
    fn sync_device_signals_skips_zeroed_user_tuple() {
        let mut doc: toml_edit::DocumentMut = "[board]\nname = \"test\"\nrevision = \"a\"\n"
            .parse()
            .unwrap();

        // A user signal's zeroed descriptor slugs to `unknown.*`.
        let user = dsig(
            0x0200,
            dsig::SignalKey {
                target_type: 0,
                target_index: 0,
                role: 0,
                quantity: 0,
                aspect: 0,
                channel: 0,
            },
        );
        let device = dsig(
            0xFF00,
            dsig::SignalKey {
                target_type: types::SIGNAL_TARGET_INTERFACE,
                target_index: 0,
                role: types::ROLE_CONFIG,
                quantity: types::QTY_DATARATE,
                aspect: types::ASPECT_DEFAULT,
                channel: types::SIGNAL_CHANNEL_NONE,
            },
        );

        let result = sync_device_signals(&mut doc, &[user, device]);

        assert_eq!(result.added.len(), 1);
        let sigs = doc["signals"].as_table().unwrap();
        assert_eq!(sigs.len(), 1);
        assert!(sigs.get("unknown.0.unknown.raw.ch0").is_none());

        // Must still parse — no poison entry.
        let toml = doc.to_string();
        assert!(crate::parse_board_def(&toml).is_ok(), "poisoned:\n{toml}");
    }

    #[test]
    fn sync_interfaces_adds_new() {
        let mut doc = empty_doc();
        let caps = Capabilities {
            interfaces: vec![
                Interface {
                    index: 0,
                    iface_type: types::IFACE_CAN,
                    meta: vec![],
                },
                Interface {
                    index: 1,
                    iface_type: types::IFACE_RS485,
                    meta: vec![],
                },
            ],
            peripherals: vec![],
            device_meta: vec![],
        };

        let result = sync_interfaces(&mut doc, &caps);
        assert_eq!(result.added.len(), 2);
        assert!(result.stale.is_empty());

        let ifaces = doc["interfaces"].as_table().unwrap();
        assert!(ifaces.get("0").is_some());
        assert!(ifaces.get("1").is_some());
    }

    #[test]
    fn sync_interfaces_idempotent() {
        let mut doc = empty_doc();
        let caps = Capabilities {
            interfaces: vec![Interface {
                index: 0,
                iface_type: types::IFACE_CAN,
                meta: vec![],
            }],
            peripherals: vec![],
            device_meta: vec![],
        };

        sync_interfaces(&mut doc, &caps);
        let result = sync_interfaces(&mut doc, &caps);
        assert!(result.added.is_empty());
    }

    #[test]
    fn sync_peripherals_adds_new() {
        let mut doc = empty_doc();
        let caps = Capabilities {
            interfaces: vec![],
            peripherals: vec![Peripheral {
                index: 0,
                kind: types::PERIPH_KIND_ACTUATOR,
                meta: vec![],
            }],
            device_meta: vec![],
        };

        let result = sync_peripherals(&mut doc, &caps);
        assert_eq!(result.added.len(), 1);
        let entry = doc["peripherals"]["0"].as_inline_table().unwrap();
        assert_eq!(entry.get("kind").unwrap().as_str(), Some("actuator"));
    }

    #[test]
    fn sync_device_signals_detects_stale() {
        let mut doc: toml_edit::DocumentMut = concat!(
            "[board]\nname = \"test\"\n",
            "[signals.\"interface.0.config.datarate\"]\nname = \"Sig1\"\ngroup = \"\"\nformat = \"number\"\n",
        )
        .parse()
        .unwrap();

        // Device has no signals — the existing one is stale
        let result = sync_device_signals(&mut doc, &[]);
        assert!(result.added.is_empty());
        assert_eq!(result.stale.len(), 1);
        assert!(result.stale[0].contains("interface.0.config.datarate"));
    }

    #[test]
    fn sync_frame_defs_adds_can_frame() {
        let mut doc = empty_doc();
        let fds = vec![frame_def::FrameDefInfo {
            frame_def_id: 0x0001,
            interface_type: frame_def::IFACE_TYPE_CAN,
            header: frame_def::FrameHeader::Can {
                can_id: 0x100,
                dlc: 8,
                flags: 0,
            },
            signals: vec![frame_def::FrameSignalDef {
                signal_id: 0x0010,
                start_bit: 0,
                bit_length: 8,
                byte_order: frame_def::BYTE_ORDER_LE,
                value_type: frame_def::VALUE_TYPE_UNSIGNED,
                quantity: types::QTY_RAW,
                scale: 1.0,
                offset: 0.0,
            }],
        }];

        let result = sync_frame_defs(&mut doc, &fds);
        assert_eq!(result.added.len(), 1);
        assert!(result.added[0].contains("0x0001"));

        let fd_table = doc["frame_defs"].as_table().unwrap();
        let entry = fd_table.get("0x0001").unwrap().as_table().unwrap();
        assert_eq!(entry["name"].as_str().unwrap(), "Frame 0x0001");
        assert_eq!(entry["interface_type"].as_str().unwrap(), "can");
    }

    #[test]
    fn sync_frame_defs_writes_a_quantity_only_when_not_raw() {
        let mut doc = empty_doc();
        let signal = |signal_id, quantity| frame_def::FrameSignalDef {
            signal_id,
            start_bit: 0,
            bit_length: 8,
            byte_order: frame_def::BYTE_ORDER_LE,
            value_type: frame_def::VALUE_TYPE_UNSIGNED,
            quantity,
            scale: 1.0,
            offset: 0.0,
        };
        let fds = [frame_def::FrameDefInfo {
            frame_def_id: 0x0001,
            interface_type: frame_def::IFACE_TYPE_CAN,
            header: frame_def::FrameHeader::Can {
                can_id: 0x100,
                dlc: 8,
                flags: 0,
            },
            signals: vec![
                signal(0x0010, types::QTY_TEMPERATURE),
                signal(0x0011, types::QTY_RAW),
            ],
        }];
        sync_frame_defs(&mut doc, &fds);
        let signals = doc["frame_defs"]["0x0001"]["signals"].as_table().unwrap();
        let quantities: Vec<_> = signals
            .iter()
            .map(|(_, sig)| sig.get("quantity").and_then(|q| q.as_str()))
            .collect();
        assert!(quantities.contains(&Some("temperature")), "{quantities:?}");
        assert!(quantities.contains(&None), "{quantities:?}");
    }

    #[test]
    fn sync_frame_defs_names_every_value_type_and_byte_order() {
        let mut doc = empty_doc();
        let signals = frame_def::VALUE_TYPE_NAMES
            .iter()
            .enumerate()
            .map(|(i, &(value_type, _))| frame_def::FrameSignalDef {
                signal_id: i as u16,
                start_bit: 0,
                bit_length: 8,
                byte_order: frame_def::BYTE_ORDER_BE,
                value_type,
                quantity: types::QTY_RAW,
                scale: 1.0,
                offset: 0.0,
            })
            .collect();
        sync_frame_defs(
            &mut doc,
            &[frame_def::FrameDefInfo {
                frame_def_id: 0x0001,
                interface_type: frame_def::IFACE_TYPE_CAN,
                header: frame_def::FrameHeader::Can {
                    can_id: 0x100,
                    dlc: 8,
                    flags: 0,
                },
                signals,
            }],
        );
        let written = doc["frame_defs"]["0x0001"]["signals"].as_table().unwrap();
        for (i, &(_, name)) in frame_def::VALUE_TYPE_NAMES.iter().enumerate() {
            let sig = &written[&format!("0x{i:04X}")];
            assert_eq!(sig["value_type"].as_str(), Some(name));
            assert_eq!(sig["byte_order"].as_str(), Some("be"));
        }
    }

    fn synced_can_flag_labels(flags: u8) -> Vec<String> {
        let mut doc = empty_doc();
        let fds = [frame_def::FrameDefInfo {
            frame_def_id: 0x0001,
            interface_type: frame_def::IFACE_TYPE_CAN,
            header: frame_def::FrameHeader::Can {
                can_id: 0x100,
                dlc: 8,
                flags,
            },
            signals: vec![],
        }];
        sync_frame_defs(&mut doc, &fds);
        doc["frame_defs"]["0x0001"]["can"]["flags"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_owned())
            .collect()
    }

    #[test]
    fn can_flag_extended_is_labelled_extended() {
        assert_eq!(
            synced_can_flag_labels(frame_def::CAN_FLAG_EXTENDED),
            ["extended"]
        );
    }

    #[test]
    fn can_flag_fd_is_labelled_fd() {
        assert_eq!(synced_can_flag_labels(frame_def::CAN_FLAG_FD), ["fd"]);
    }

    #[test]
    fn can_flag_brs_is_labelled_brs() {
        assert_eq!(synced_can_flag_labels(frame_def::CAN_FLAG_BRS), ["brs"]);
    }

    #[test]
    fn can_flag_rtr_is_labelled_rtr() {
        assert_eq!(synced_can_flag_labels(frame_def::CAN_FLAG_RTR), ["rtr"]);
    }

    #[test]
    fn can_flags_combine_in_bit_order() {
        let all = frame_def::CAN_FLAG_EXTENDED
            | frame_def::CAN_FLAG_FD
            | frame_def::CAN_FLAG_BRS
            | frame_def::CAN_FLAG_RTR
            | frame_def::CAN_FLAG_MATCH_ANY;
        assert_eq!(
            synced_can_flag_labels(all),
            ["extended", "fd", "brs", "rtr", "match_any"]
        );
    }

    #[test]
    fn an_unlabelled_can_flag_is_written_as_hex_not_dropped() {
        const UNLABELLED: u8 = 0x20;
        assert_eq!(
            synced_can_flag_labels(frame_def::CAN_FLAG_EXTENDED | UNLABELLED),
            ["extended", "0x20"]
        );
    }

    #[test]
    fn iface_type_mapping() {
        assert_eq!(iface_type_to_toml(types::IFACE_CAN), "can");
        assert_eq!(iface_type_to_toml(types::IFACE_CANFD), "canfd");
        assert_eq!(iface_type_to_toml(types::IFACE_RS485), "rs485");
        assert_eq!(iface_type_to_toml(0xFF), "unknown");
    }

    #[test]
    fn periph_kind_mapping() {
        assert_eq!(periph_kind_to_toml(types::PERIPH_KIND_SENSOR), "sensor");
        assert_eq!(periph_kind_to_toml(types::PERIPH_KIND_ACTUATOR), "actuator");
        assert_eq!(
            periph_kind_to_toml(types::PERIPH_KIND_CONTROLLER),
            "controller"
        );
        assert_eq!(periph_kind_to_toml(types::PERIPH_KIND_LINK), "link");
        assert_eq!(periph_kind_to_toml(0xFF), "unknown");
    }
}
