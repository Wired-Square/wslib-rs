//! A board TOML scaffolded from a live device: its interfaces, peripherals
//! and signals, named from each signal's tuple and its target's prefix.

use toml_edit::{DocumentMut, Item, Table, value};

use wslib_framelink_protocol::capabilities::Capabilities;
use wslib_framelink_protocol::{dsig, types};

pub struct BoardSkeleton {
    pub name: String,
    pub revision: String,
    /// `(index, type slug)`, such as `(0, "can")`.
    pub interfaces: Vec<(u8, String)>,
    /// `(index, kind slug)`, such as `(0, "actuator")`.
    pub peripherals: Vec<(u8, String)>,
    pub signals: Vec<SkeletonSignal>,
}

pub struct SkeletonSignal {
    /// Only orders the rows as the device lists them.
    pub id: u16,
    pub key: dsig::SignalKey,
    pub name: String,
    pub group: String,
    pub format: String,
}

pub fn skeleton_from_device(caps: &Capabilities, signals: &[dsig::SignalInfo]) -> BoardSkeleton {
    let interfaces = caps
        .interfaces
        .iter()
        .map(|i| (i.index, types::interface_slug(i.iface_type).to_string()))
        .collect();
    let peripherals = caps
        .peripherals
        .iter()
        .map(|p| (p.index, types::peripheral_kind_slug(p.kind).to_string()))
        .collect();
    let signals = signals
        .iter()
        .map(|s| {
            let derived = derive_signal(s, caps);
            SkeletonSignal {
                id: s.signal_id,
                key: s.key(),
                name: derived.name,
                group: derived.group.unwrap_or_else(|| "Device".to_string()),
                format: format_hint(s.quantity).to_string(),
            }
        })
        .collect();

    BoardSkeleton {
        name: caps.board_name().unwrap_or("unknown").to_string(),
        revision: caps.board_revision().unwrap_or("unknown").to_string(),
        interfaces,
        peripherals,
        signals,
    }
}

pub struct DerivedSignalName {
    pub name: String,
    /// `name`'s first word, such as `"CAN0"`; `None` on the device itself.
    pub group: Option<String>,
    /// `name` without the group, such as `"Colour 6"`.
    pub detail: String,
}

/// `"CAN0 Bitrate"` on an interface, `"Actuator0 Colour 6"` on a peripheral,
/// the bare [`dsig::semantic_signal_name`] on the device.
pub fn derive_signal(sig: &dsig::SignalInfo, caps: &Capabilities) -> DerivedSignalName {
    let (group, detail) = match sig.target_type {
        types::SIGNAL_TARGET_INTERFACE => {
            let iface_type = caps.iface_type(sig.target_index);
            (
                interface_name(sig.target_index, caps).unwrap_or_default(),
                sig.semantic_name(iface_type),
            )
        }
        types::SIGNAL_TARGET_PERIPHERAL => (
            peripheral_prefix(sig.target_index, caps).unwrap_or_default(),
            sig.semantic_name(None),
        ),
        _ => (String::new(), sig.semantic_name(None)),
    };

    if group.is_empty() {
        DerivedSignalName {
            name: detail.clone(),
            group: None,
            detail,
        }
    } else {
        DerivedSignalName {
            name: format!("{group} {detail}"),
            group: Some(group),
            detail,
        }
    }
}

pub fn derive_signal_name(sig: &dsig::SignalInfo, caps: &Capabilities) -> String {
    derive_signal(sig, caps).name
}

pub fn derive_signal_group(sig: &dsig::SignalInfo, caps: &Capabilities) -> Option<String> {
    derive_signal(sig, caps).group
}

/// `"CAN0"`, `"RS0"`: the prefix and the count of same-type interfaces below
/// it. Resolution keys on this, whatever the board TOML calls it.
pub fn derive_interface_name(
    iface: &wslib_framelink_protocol::capabilities::Interface,
    caps: &Capabilities,
) -> String {
    let ordinal = caps
        .interfaces
        .iter()
        .filter(|i| i.iface_type == iface.iface_type && i.index < iface.index)
        .count();
    format!(
        "{}{ordinal}",
        iface_label(types::interface_slug(iface.iface_type))
    )
}

fn interface_name(index: u8, caps: &Capabilities) -> Option<String> {
    caps.interfaces
        .iter()
        .find(|i| i.index == index)
        .map(|i| derive_interface_name(i, caps))
}

/// `"Sensor0"`, `"Actuator1"`: the kind and the count of same-kind
/// peripherals below it.
fn peripheral_prefix(index: u8, caps: &Capabilities) -> Option<String> {
    let periph = caps.peripherals.iter().find(|p| p.index == index)?;
    let ordinal = caps
        .peripherals
        .iter()
        .filter(|p| p.kind == periph.kind && p.index < index)
        .count();
    Some(format!(
        "{}{ordinal}",
        types::peripheral_kind_name(periph.kind)
    ))
}

/// A format hint from the quantity, for a real board to refine.
fn format_hint(quantity: u8) -> &'static str {
    match quantity & types::QTY_BASE_MASK {
        types::QTY_BOOL => "bool",
        types::QTY_ENUM => "enum",
        types::QTY_DATARATE => "bps",
        types::QTY_TEMPERATURE => "temperature_0.1",
        types::QTY_COLOUR_RGB => "color_brgb",
        _ => "number",
    }
}

/// Edits `existing` in place when given: only missing entries and fields are
/// added, so its names, other sections and comments survive verbatim.
pub fn to_toml(skeleton: &BoardSkeleton, existing: Option<&str>) -> String {
    let mut doc = existing
        .and_then(|s| s.parse::<DocumentMut>().ok())
        .unwrap_or_default();

    if let Some(board) = doc
        .entry("board")
        .or_insert(Item::Table(Table::new()))
        .as_table_mut()
    {
        board.insert("name", value(skeleton.name.as_str()));
        board.insert("revision", value(skeleton.revision.as_str()));
    }

    upsert_targets(
        &mut doc,
        "interfaces",
        "type",
        &skeleton.interfaces,
        iface_label,
    );
    upsert_targets(
        &mut doc,
        "peripherals",
        "kind",
        &skeleton.peripherals,
        periph_label,
    );
    upsert_signals(&mut doc, skeleton);

    doc.to_string()
}

fn upsert_targets(
    doc: &mut DocumentMut,
    section: &str,
    type_field: &str,
    targets: &[(u8, String)],
    label: fn(&str) -> &str,
) {
    let Some(tbl) = doc
        .entry(section)
        .or_insert(implicit_table())
        .as_table_mut()
    else {
        return;
    };
    for (index, slug) in sorted_by_index(targets) {
        let Some(entry) = tbl
            .entry(&index.to_string())
            .or_insert(Item::Table(Table::new()))
            .as_table_mut()
        else {
            continue;
        };
        if !entry.contains_key("name") {
            entry.insert(
                "name",
                value(derived_target_name(index, &slug, targets, label)),
            );
        }
        if !entry.contains_key(type_field) {
            entry.insert(type_field, value(slug.as_str()));
        }
    }
}

fn upsert_signals(doc: &mut DocumentMut, skeleton: &BoardSkeleton) {
    let Some(tbl) = doc
        .entry("signals")
        .or_insert(implicit_table())
        .as_table_mut()
    else {
        return;
    };
    let mut sorted: Vec<&SkeletonSignal> = skeleton.signals.iter().collect();
    sorted.sort_by_key(|s| s.id);
    for sig in sorted {
        let Some(entry) = tbl
            .entry(&dsig::format_signal_key(&sig.key))
            .or_insert(Item::Table(Table::new()))
            .as_table_mut()
        else {
            continue;
        };
        if !entry.contains_key("name") {
            entry.insert("name", value(sig.name.as_str()));
        }
        if !entry.contains_key("group") && !sig.group.is_empty() {
            entry.insert("group", value(sig.group.as_str()));
        }
        if !entry.contains_key("format") && !sig.format.is_empty() {
            entry.insert("format", value(sig.format.as_str()));
        }
    }
}

/// Implicit, so a section holding only subtables writes no header of its own.
fn implicit_table() -> Item {
    let mut t = Table::new();
    t.set_implicit(true);
    Item::Table(t)
}

fn sorted_by_index(targets: &[(u8, String)]) -> Vec<(u8, String)> {
    let mut sorted = targets.to_vec();
    sorted.sort_by_key(|(index, _)| *index);
    sorted
}

fn derived_target_name(
    index: u8,
    slug: &str,
    all: &[(u8, String)],
    label: fn(&str) -> &str,
) -> String {
    let ordinal = all
        .iter()
        .filter(|(i, s)| *i < index && s.as_str() == slug)
        .count();
    format!("{}{}", label(slug), ordinal)
}

/// The silkscreen's prefixes: CAN0, RS0.
fn iface_label(slug: &str) -> &str {
    match slug {
        "can" | "canfd" => "CAN",
        "rs485" => "RS",
        "rs232" => "RS232",
        "lin" => "LIN",
        other => other,
    }
}

fn periph_label(slug: &str) -> &str {
    match slug {
        "sensor" => "Sensor",
        "actuator" => "Actuator",
        "controller" => "Controller",
        "link" => "Link",
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wslib_framelink_protocol::capabilities::{
        Capabilities, Interface, Meta, MetaValue, Peripheral,
    };
    use wslib_framelink_protocol::dsig::SignalInfo;
    use wslib_framelink_protocol::frame_def;

    fn iface(index: u8, iface_type: u8) -> Interface {
        Interface {
            index,
            iface_type,
            meta: vec![],
        }
    }

    fn periph(index: u8, kind: u8) -> Peripheral {
        Peripheral {
            index,
            kind,
            meta: vec![],
        }
    }

    fn sig(
        id: u16,
        target_type: u8,
        target_index: u8,
        role: u8,
        quantity: u8,
        aspect: u8,
        channel: u8,
    ) -> SignalInfo {
        SignalInfo {
            signal_id: id,
            target_type,
            target_index,
            role,
            quantity,
            aspect,
            channel,
            flags: 0,
            value_type: frame_def::VALUE_TYPE_UNSIGNED,
            value_len: 4,
            scale: 1.0,
            offset: 0.0,
            min_raw: 0,
            max_raw: 0,
        }
    }

    fn caps_single_can() -> Capabilities {
        Capabilities {
            device_meta: vec![],
            interfaces: vec![iface(0, types::IFACE_CAN)],
            peripherals: vec![],
        }
    }

    fn bitrate(iface_index: u8) -> SignalInfo {
        sig(
            0xFF00 + iface_index as u16 * 0x10,
            types::SIGNAL_TARGET_INTERFACE,
            iface_index,
            types::ROLE_CONFIG,
            types::QTY_DATARATE,
            types::ASPECT_DEFAULT,
            types::SIGNAL_CHANNEL_NONE,
        )
    }

    #[test]
    fn derive_interface_signal_name() {
        let caps = caps_single_can();
        assert_eq!(derive_signal_name(&bitrate(0), &caps), "CAN0 Bitrate");
    }

    #[test]
    fn derive_rs485_signal_name_uses_short_prefix() {
        let caps = Capabilities {
            device_meta: vec![],
            interfaces: vec![iface(0, types::IFACE_RS485)],
            peripherals: vec![],
        };
        assert_eq!(derive_signal_name(&bitrate(0), &caps), "RS0 Bitrate");
    }

    #[test]
    fn status_bool_names_follow_interface_type() {
        let caps = Capabilities {
            device_meta: vec![],
            interfaces: vec![iface(0, types::IFACE_CAN), iface(2, types::IFACE_RS485)],
            peripherals: vec![],
        };
        let running = sig(
            0xFF0C,
            types::SIGNAL_TARGET_INTERFACE,
            0,
            types::ROLE_STATUS,
            types::QTY_BOOL,
            types::ASPECT_DEFAULT,
            types::SIGNAL_CHANNEL_NONE,
        );
        assert_eq!(derive_signal_name(&running, &caps), "CAN0 Running");

        let duplex = sig(
            0xFF28,
            types::SIGNAL_TARGET_INTERFACE,
            2,
            types::ROLE_STATUS,
            types::QTY_BOOL,
            types::ASPECT_DEFAULT,
            types::SIGNAL_CHANNEL_NONE,
        );
        assert_eq!(derive_signal_name(&duplex, &caps), "RS0 Half Duplex");
    }

    #[test]
    fn derive_device_signal_name_has_no_prefix() {
        let caps = caps_single_can();
        let temp = sig(
            0xFFC0,
            types::SIGNAL_TARGET_DEVICE,
            0,
            types::ROLE_MEASUREMENT,
            types::QTY_TEMPERATURE,
            types::ASPECT_DEFAULT,
            types::SIGNAL_CHANNEL_NONE,
        );
        assert_eq!(derive_signal_name(&temp, &caps), "Temperature");
        assert_eq!(derive_signal_group(&temp, &caps), None);
    }

    #[test]
    fn diag_counters_named_by_interface_target() {
        let caps = Capabilities {
            device_meta: vec![],
            interfaces: vec![iface(0, types::IFACE_CAN), iface(1, types::IFACE_CAN)],
            peripherals: vec![],
        };
        let client_can1 = sig(
            0xFF19,
            types::SIGNAL_TARGET_INTERFACE,
            1,
            types::ROLE_DIAGNOSTIC,
            types::QTY_COUNT,
            types::ASPECT_CLIENT,
            types::SIGNAL_CHANNEL_NONE,
        );
        assert_eq!(derive_signal_name(&client_can1, &caps), "CAN1 Client Drops");
        assert_eq!(
            derive_signal_group(&client_can1, &caps).as_deref(),
            Some("CAN1")
        );
    }

    #[test]
    fn led_elements_are_channel_numbered() {
        let caps = Capabilities {
            device_meta: vec![],
            interfaces: vec![],
            peripherals: vec![periph(0, types::PERIPH_KIND_ACTUATOR)],
        };
        let led5_colour = sig(
            0xFF54,
            types::SIGNAL_TARGET_PERIPHERAL,
            0,
            types::ROLE_SETPOINT,
            types::QTY_COLOUR_RGB,
            types::ASPECT_DEFAULT,
            5,
        );
        assert_eq!(
            derive_signal_name(&led5_colour, &caps),
            "Actuator0 Colour 6"
        );
    }

    #[test]
    fn same_kind_peripherals_get_ordinals() {
        let caps = Capabilities {
            device_meta: vec![],
            interfaces: vec![],
            peripherals: vec![
                periph(0, types::PERIPH_KIND_ACTUATOR),
                periph(1, types::PERIPH_KIND_ACTUATOR),
                periph(2, types::PERIPH_KIND_SENSOR),
            ],
        };
        let ch2_enable = sig(
            0xFF8C,
            types::SIGNAL_TARGET_PERIPHERAL,
            1,
            types::ROLE_SETPOINT,
            types::QTY_BOOL,
            types::ASPECT_DEFAULT,
            2,
        );
        assert_eq!(derive_signal_name(&ch2_enable, &caps), "Actuator1 Enable 3");

        let soc_temp = sig(
            0xFFC0,
            types::SIGNAL_TARGET_PERIPHERAL,
            2,
            types::ROLE_MEASUREMENT,
            types::QTY_TEMPERATURE,
            types::ASPECT_DEFAULT,
            types::SIGNAL_CHANNEL_NONE,
        );
        assert_eq!(derive_signal_name(&soc_temp, &caps), "Sensor0 Temperature");
    }

    #[test]
    fn skeleton_from_device_maps_caps_and_signals() {
        let caps = Capabilities {
            device_meta: vec![
                Meta {
                    id: types::META_BOARD_NAME,
                    quantity: types::QTY_STRING,
                    value: MetaValue::Bytes(b"waveshare".to_vec()),
                },
                Meta {
                    id: types::META_BOARD_REVISION,
                    quantity: types::QTY_STRING,
                    value: MetaValue::Bytes(b"esp32s3-v1.0".to_vec()),
                },
            ],
            interfaces: vec![iface(0, types::IFACE_CAN)],
            peripherals: vec![periph(0, types::PERIPH_KIND_ACTUATOR)],
        };
        let signals = vec![
            bitrate(0),
            sig(
                0xFFC0,
                types::SIGNAL_TARGET_DEVICE,
                0,
                types::ROLE_MEASUREMENT,
                types::QTY_TEMPERATURE,
                types::ASPECT_DEFAULT,
                types::SIGNAL_CHANNEL_NONE,
            ),
        ];

        let sk = skeleton_from_device(&caps, &signals);
        assert_eq!(sk.name, "waveshare");
        assert_eq!(sk.revision, "esp32s3-v1.0");
        assert_eq!(sk.interfaces, vec![(0u8, "can".to_string())]);
        assert_eq!(sk.peripherals, vec![(0u8, "actuator".to_string())]);

        assert_eq!(sk.signals.len(), 2);
        assert_eq!(sk.signals[0].key, signals[0].key());
        assert_eq!(sk.signals[0].name, "CAN0 Bitrate");
        assert_eq!(sk.signals[0].group, "CAN0");
        assert_eq!(sk.signals[0].format, "bps");
        assert_eq!(sk.signals[1].name, "Temperature");
        assert_eq!(sk.signals[1].group, "Device");
        assert_eq!(sk.signals[1].format, "temperature_0.1");
    }

    fn skeleton_one_can(signals: &[SignalInfo]) -> BoardSkeleton {
        let caps = Capabilities {
            device_meta: vec![
                Meta {
                    id: types::META_BOARD_NAME,
                    quantity: types::QTY_STRING,
                    value: MetaValue::Bytes(b"wiredflexlink".to_vec()),
                },
                Meta {
                    id: types::META_BOARD_REVISION,
                    quantity: types::QTY_STRING,
                    value: MetaValue::Bytes(b"esp32c6-v1.0".to_vec()),
                },
            ],
            interfaces: vec![iface(0, types::IFACE_CAN)],
            peripherals: vec![],
        };
        skeleton_from_device(&caps, signals)
    }

    fn enabled(iface_index: u8) -> SignalInfo {
        sig(
            0xFF02 + iface_index as u16 * 0x10,
            types::SIGNAL_TARGET_INTERFACE,
            iface_index,
            types::ROLE_CONFIG,
            types::QTY_BOOL,
            types::ASPECT_DEFAULT,
            types::SIGNAL_CHANNEL_NONE,
        )
    }

    #[test]
    fn to_toml_prefers_existing_then_round_trips() {
        let skeleton = skeleton_one_can(&[bitrate(0), enabled(0)]);

        let existing = r#"
[board]
name = "wiredflexlink"
revision = "esp32c6-v1.0"

[signals."interface.0.config.datarate"]
name = "Custom Bus Speed"
group = "CAN0"

[functions.0x10]
name = "Palette Lookup"
description = "look up a colour"
params = ["palette_signal_start:u16"]
"#;

        let out = to_toml(&skeleton, Some(existing));
        let parsed = crate::parse_board_def(&out).expect("generated TOML should parse");

        // Existing name wins for the bitrate; the derived default fills enabled.
        assert_eq!(
            parsed.signal_name(&bitrate(0).key()),
            Some("Custom Bus Speed")
        );
        assert_eq!(parsed.signal_name(&enabled(0).key()), Some("CAN0 Enabled"));
        // Interface name derived (the existing TOML carried none).
        assert_eq!(parsed.interface_name(0), Some("CAN0"));
        // Protocol-level function carried through verbatim.
        assert_eq!(parsed.function_name(0x10), Some("Palette Lookup"));
    }

    #[test]
    fn to_toml_preserves_existing_comments_and_sections() {
        let skeleton = skeleton_one_can(&[bitrate(0)]);
        let existing = r#"
[board]
name = "wiredflexlink"
revision = "esp32c6-v1.0"

# hand-authored — must survive regen
[functions.0x11]
name = "Clamp"
"#;
        let out = to_toml(&skeleton, Some(existing));
        assert!(out.contains("# hand-authored — must survive regen"));
        assert!(out.contains("[functions.0x11]"));

        let parsed = crate::parse_board_def(&out).unwrap();
        assert_eq!(parsed.signal_name(&bitrate(0).key()), Some("CAN0 Bitrate"));
        assert_eq!(parsed.function_name(0x11), Some("Clamp"));
    }

    #[test]
    fn to_toml_without_existing_synthesises_no_functions() {
        let skeleton = skeleton_one_can(&[bitrate(0)]);
        let out = to_toml(&skeleton, None);
        let parsed = crate::parse_board_def(&out).unwrap();

        assert_eq!(parsed.signal_name(&bitrate(0).key()), Some("CAN0 Bitrate"));
        assert_eq!(parsed.interface_name(0), Some("CAN0"));
        assert!(parsed.functions.is_empty());
    }
}
