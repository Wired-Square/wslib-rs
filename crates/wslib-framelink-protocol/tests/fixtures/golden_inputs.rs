// Shared with the generator that wrote `goldens.json` from the
// source this crate was moved from; `p` is the protocol crate.

fn json<T: serde::Serialize>(value: &T) -> String {
    serde_json::to_string(value).unwrap()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn signal(
    signal_id: u16,
    key: (u8, u8, u8, u8, u8, u8),
    flags: u8,
    bounds: (i64, i64),
) -> p::dsig::SignalInfo {
    p::dsig::SignalInfo {
        signal_id,
        target_type: key.0,
        target_index: key.1,
        role: key.2,
        quantity: key.3,
        aspect: key.4,
        channel: key.5,
        flags,
        value_type: p::frame_def::VALUE_TYPE_SIGNED,
        value_len: 2,
        scale: 0.1,
        offset: -40.0,
        min_raw: bounds.0,
        max_raw: bounds.1,
    }
}

fn capabilities_payload() -> Vec<u8> {
    use p::types::*;
    let mut b = vec![4];
    b.extend([META_MAX_FRAME_DEFS, QTY_COUNT, 2, 16, 0]);
    b.extend([META_BOARD_NAME, QTY_STRING, 13]);
    b.extend(b"wiredflexlink");
    b.extend([META_DEVICE_ID, QTY_STRING, 3, 0xFF, 0x00, 0x41]);
    b.extend([META_SUPPORTED_FUNCTIONS, QTY_RAW, 4, 0x10, 0x11, 0x12, 0x13]);
    b.extend([2, 0, IFACE_CAN, 1, META_CAN_MAX_DLC, QTY_COUNT, 1, 8]);
    b.extend([2, IFACE_RS485, 0]);
    b.extend([1, 0, PERIPH_KIND_ACTUATOR, 0]);
    b
}

fn mappings() -> Vec<p::xform::SignalMapping> {
    use p::xform::{SignalMapping, TransformParams};
    vec![
        SignalMapping {
            source_signal_id: 1,
            dest_signal_id: 2,
            transform: TransformParams::Direct,
        },
        SignalMapping {
            source_signal_id: 3,
            dest_signal_id: 4,
            transform: TransformParams::Scale {
                scale: 0.5,
                offset: 1.25,
            },
        },
        SignalMapping {
            source_signal_id: 5,
            dest_signal_id: 6,
            transform: TransformParams::Invert,
        },
        SignalMapping {
            source_signal_id: 7,
            dest_signal_id: 8,
            transform: TransformParams::Mask { mask: 0xF0F0 },
        },
    ]
}

fn protocol_goldens() -> Vec<(&'static str, String)> {
    use p::types::*;
    use p::{bridge, counter, dsig, frame_def, generator, xform};

    let temp = signal(
        0xFFC0,
        (
            SIGNAL_TARGET_PERIPHERAL,
            2,
            ROLE_MEASUREMENT,
            QTY_TEMPERATURE | QTY_PER_SECOND,
            ASPECT_RAMPED,
            3,
        ),
        DSIG_FLAG_WRITABLE | DSIG_FLAG_RULE_DEST,
        (-100, 1000),
    );
    let bitrate = signal(
        0xFF00,
        (
            SIGNAL_TARGET_INTERFACE,
            0,
            ROLE_CONFIG,
            QTY_DATARATE,
            ASPECT_DEFAULT,
            SIGNAL_CHANNEL_NONE,
        ),
        DSIG_FLAG_PERSISTABLE | DSIG_FLAG_FRAME_DEST,
        (0, 0),
    );
    let caps = p::capabilities::decode_capabilities(&capabilities_payload()).unwrap();

    let can_def = frame_def::FrameDefInfo {
        frame_def_id: 0x0102,
        interface_type: IFACE_CANFD,
        header: frame_def::FrameHeader::Can {
            can_id: 0x18FF_0001,
            dlc: 15,
            flags: frame_def::CAN_FLAG_MATCH_ANY | frame_def::CAN_FLAG_EXTENDED,
        },
        signals: vec![frame_def::FrameSignalDef {
            signal_id: 0x0010,
            start_bit: 7,
            bit_length: 12,
            byte_order: frame_def::BYTE_ORDER_BE,
            value_type: frame_def::VALUE_TYPE_FLOAT,
            quantity: p::types::QTY_TEMPERATURE,
            scale: 0.25,
            offset: -3.5,
        }],
    };
    let rs_def = frame_def::FrameDefInfo {
        frame_def_id: 7,
        interface_type: IFACE_RS485,
        header: frame_def::FrameHeader::Rs485 { framing_mode: 2 },
        signals: vec![],
    };

    let bridge_info = bridge::BridgeInfo {
        bridge_id: 9,
        source_interface: 0,
        dest_interface: 1,
        interface_type: IFACE_CAN,
        enabled: true,
        default_action: bridge::BridgeDefaultAction::Block,
        filters: vec![
            bridge::BridgeFilter::mask(0x100, 0x7F0),
            bridge::BridgeFilter {
                kind: bridge::BridgeFilterType::Range,
                ide: bridge::BridgeFilterIde::ExtOnly,
                a: 0x1000,
                b: 0x1FFF,
            },
        ],
    };

    let xform_info = xform::TransformerInfo {
        transformer_id: 0x0203,
        source_frame_def_id: 0x0102,
        source_interface: 0,
        dest_frame_def_id: FRAME_DEF_ID_DEVICE,
        dest_interface: 0xFF,
        enabled: false,
        mappings: mappings(),
        functions: vec![
            xform::XformFunction {
                function_id: xform::FUNC_PALETTE,
                source_signal_id: 1,
                dest_signal_id: 2,
                params: xform::FunctionParams::Palette {
                    palette_signal_start: 0x0200,
                    signal_max: 100,
                },
            },
            xform::XformFunction {
                function_id: xform::FUNC_CLAMP,
                source_signal_id: 3,
                dest_signal_id: 4,
                params: xform::FunctionParams::Clamp { min: 1, max: 9 },
            },
            xform::XformFunction {
                function_id: xform::FUNC_THRESHOLD,
                source_signal_id: 5,
                dest_signal_id: 6,
                params: xform::FunctionParams::Threshold {
                    threshold: 50,
                    value_above: 0xFF00_FF00,
                    value_below: 0xFFFF_0000,
                },
            },
            xform::XformFunction {
                function_id: xform::FUNC_GATE,
                source_signal_id: 7,
                dest_signal_id: 8,
                params: xform::FunctionParams::Gate {
                    guard_signal_id: 9,
                    compare_op: xform::GateOp::GreaterEqual,
                    compare_value: 3,
                    fail_value: 0,
                },
            },
        ],
    };

    let gen_info = generator::GeneratorInfo {
        generator_id: 4,
        frame_def_id: 0x0102,
        interface_index: 1,
        period_ms: 250,
        trigger_type: generator::TRIGGER_ON_CHANGE,
        enabled: true,
        mappings: mappings(),
    };

    let counter_payload = [1, 0, 16, 0, 3, 0, 7, 0];
    let counter_info = counter::parse_counter_resp(&counter_payload).unwrap();

    let keys = [temp.key(), bitrate.key()];
    let mut slugs: Vec<String> = keys.iter().map(dsig::format_signal_key).collect();
    for bad in [
        "interface.0.config",
        "widget.0.config.datarate",
        "interface.x.config.datarate",
        "interface.0.boss.datarate",
        "interface.0.config.warp",
        "interface.0.config.datarate.chx",
        "interface.0.config.datarate.bogus",
    ] {
        slugs.push(dsig::parse_signal_key(bad).unwrap_err().to_string());
    }

    vec![
        ("signal_info_rate", json(&temp)),
        ("signal_info_bitrate", json(&bitrate)),
        ("capabilities", json(&caps)),
        ("capabilities_display", caps.to_string()),
        ("frame_def_can", json(&can_def)),
        ("frame_def_rs485", json(&rs_def)),
        (
            "frame_def_can_wire",
            hex(&frame_def::build_frame_def_add(&can_def).unwrap()),
        ),
        ("bridge", json(&bridge_info)),
        ("bridge_wire", hex(&bridge::build_bridge_add(&bridge_info))),
        ("transformer", json(&xform_info)),
        (
            "transformer_wire",
            hex(&xform::build_xform_add(&xform_info)),
        ),
        ("generator", json(&gen_info)),
        ("generator_wire", hex(&generator::build_gen_add(&gen_info))),
        ("counter", json(&counter_info)),
        (
            "frame_wire",
            hex(&p::frame::build_frame(
                MSG_DSIG_WRITE,
                FLAG_ACK_REQ,
                200,
                &[0, 1, 0, 0xFF],
            )),
        ),
        ("signal_key_slugs", slugs.join("\n")),
        (
            "semantic_names",
            [
                temp.semantic_name(None),
                bitrate.semantic_name(Some(IFACE_CAN)),
            ]
            .join("\n"),
        ),
    ]
}
