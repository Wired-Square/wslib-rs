// Shared with the generator that wrote `goldens.json` from the
// source this crate was moved from; `p` is the protocol crate, `b` this one.

fn json<T: serde::Serialize>(value: &T) -> String {
    serde_json::to_string(value).unwrap()
}

const INDICATOR_CONFIG: &str = r#"{"color":4278255360,"state":2,"blink_period":250,"source":{"Activity":{"type":"FrameMatch","can_id":291,"mask":[255,0,0,0,0,0,0,1]}},"trigger":{"type":"FrameId","can_id":16},"owned_frame_def_id":65024,"owned_transformer_id":null,"gated":true}"#;

fn led_signals() -> Vec<p::dsig::SignalInfo> {
    use p::types::*;
    let sig = |signal_id, role, quantity, channel| p::dsig::SignalInfo {
        signal_id,
        target_type: SIGNAL_TARGET_PERIPHERAL,
        target_index: 0,
        role,
        quantity,
        aspect: ASPECT_DEFAULT,
        channel,
        flags: DSIG_FLAG_WRITABLE,
        value_type: 0,
        value_len: 4,
        scale: 1.0,
        offset: 0.0,
        min_raw: 0,
        max_raw: 0,
    };
    let mut out = Vec::new();
    for ch in 0u8..6 {
        let base = 0xFF40 + u16::from(ch) * 4;
        out.push(sig(base, ROLE_SETPOINT, QTY_COLOUR_RGB, ch));
        out.push(sig(base + 1, ROLE_SETPOINT, QTY_ENUM, ch));
        out.push(sig(base + 2, ROLE_CONFIG, QTY_DURATION, ch));
        out.push(sig(base + 3, ROLE_COMMAND, QTY_BOOL, ch));
    }
    out.push(p::dsig::SignalInfo {
        signal_id: 0xFF00,
        target_type: SIGNAL_TARGET_INTERFACE,
        role: ROLE_CONFIG,
        quantity: QTY_DATARATE,
        channel: SIGNAL_CHANNEL_NONE,
        ..sig(0, 0, 0, 0)
    });
    out.push(p::dsig::SignalInfo {
        signal_id: 0x0200,
        target_type: SIGNAL_TARGET_DEVICE,
        role: ROLE_STATUS,
        quantity: QTY_RAW,
        channel: SIGNAL_CHANNEL_NONE,
        ..sig(0, 0, 0, 0)
    });
    out
}

fn board_goldens() -> Vec<(&'static str, String)> {
    let c6 = b::embedded_boards()
        .iter()
        .find(|e| e.name == "wiredflexlink")
        .unwrap()
        .toml;
    let def = b::load_board_def("wiredflexlink", "esp32c6-v0.0.2").unwrap();
    let signals = led_signals();
    let caps = p::capabilities::decode_capabilities(&[
        0,
        2,
        0,
        p::types::IFACE_CAN,
        0,
        1,
        p::types::IFACE_RS485,
        0,
        1,
        0,
        p::types::PERIPH_KIND_ACTUATOR,
        0,
    ])
    .unwrap();

    let leds = b::discover_leds(&signals, Some(&def));
    let mut palettes = def.palettes.clone();
    palettes.sort_by(|x, y| x.name.cmp(&y.name));
    let usb = [
        b::UsbAccess::Native,
        b::UsbAccess::CdcInterface { interface: 3 },
        b::UsbAccess::None,
    ];
    let config: b::IndicatorConfig = serde_json::from_str(INDICATOR_CONFIG).unwrap();
    let triggers = b::build_indicator_trigger_messages(
        &leds[5],
        &serde_json::from_str(r#"{"type":"AnyFrame"}"#).unwrap(),
    );

    let editable = b::editable::EditableBoardDef::from_toml(c6).unwrap();
    let editable_from_def = b::editable::EditableBoardDef::from_board_def(&def);
    let first_signals: Vec<_> = editable.signals.values().take(3).collect();

    let skeleton = b::scaffold::skeleton_from_device(&caps, &signals);
    let mut synced: toml_edit::DocumentMut = c6.parse().unwrap();
    let mut sync_log = Vec::new();
    for result in [
        b::sync::sync_interfaces(&mut synced, &caps),
        b::sync::sync_peripherals(&mut synced, &caps),
        b::sync::sync_device_signals(&mut synced, &signals),
    ] {
        sync_log.extend(result.added);
        sync_log.extend(result.stale);
    }

    let resolver = b::resolve::SignalResolver::from_device(&caps, &signals);
    let selectable = b::selectable::categorise_signals(&[], &signals, Some(&def));
    let formatted: Vec<String> = def
        .signals
        .keys()
        .map(|k| (p::dsig::format_signal_key(k), def.format_value(k, 1)))
        .collect::<std::collections::BTreeMap<_, _>>()
        .into_iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect();

    vec![
        ("usb_access", json(&usb)),
        ("palettes", json(&palettes)),
        ("discovered_leds", json(&leds)),
        ("indicator_config", json(&config)),
        ("indicator_trigger_wire", format!("{triggers:?}")),
        ("editable_signals", json(&first_signals)),
        ("editable_from_toml", editable.to_toml()),
        ("editable_from_def", editable_from_def.to_toml()),
        ("scaffold_fresh", b::scaffold::to_toml(&skeleton, None)),
        (
            "scaffold_existing",
            b::scaffold::to_toml(&skeleton, Some(c6)),
        ),
        ("synced", synced.to_string()),
        ("sync_log", sync_log.join("\n")),
        (
            "resolve_errors",
            [
                resolver.resolve_signal("Nope").unwrap_err().to_string(),
                resolver.resolve_interface("Nope").unwrap_err().to_string(),
            ]
            .join("\n"),
        ),
        ("selectable", json(&selectable)),
        ("format_values", formatted.join("\n")),
    ]
}
