//! The protocol's constants and golden vectors, pinned: the firmware's
//! `framelink.h`, `capabilities.h`, `device_signal.h` and `frame_def.h` carry
//! the same values, and changing one here is a wire change.

use wslib_framelink_protocol::types::*;
use wslib_framelink_protocol::{
    Error, PROTOCOL_VERSION, RULE_FORMAT, SCHEMA_VERSION_MAX, can_id, frame, frame_def,
};

#[test]
fn format_versions_are_pinned() {
    assert_eq!(PROTOCOL_VERSION, 4);
    assert_eq!(RULE_FORMAT, 2);
    assert_eq!(SCHEMA_VERSION_MAX, 1);
}

#[test]
fn a_frame_matches_its_golden_vector() {
    let wire = frame::build_frame(MSG_PING, FLAG_ACK_REQ, 42, b"hi");
    assert_eq!(
        wire,
        [0x00, 0x05, 0x41, 0x01, 0x2A, 0x02, 0x03, b'h', b'i', 0x00]
    );
    let parsed = frame::parse_frame(&wire[1..wire.len() - 1]).unwrap();
    assert_eq!(
        (parsed.msg_type, parsed.flags, parsed.seq),
        (MSG_PING, FLAG_ACK_REQ, 42)
    );
    assert_eq!(parsed.payload, b"hi");
}

#[test]
fn a_corrupt_block_fails_cobs_before_the_version_is_read() {
    assert_eq!(
        frame::parse_frame(&[0x05, 0x31]).unwrap_err(),
        Error::CobsDecode
    );
    let v3 = wslib_framing::cobs::stuff(&[0x30, MSG_PING, 0, 0, 0]);
    assert_eq!(
        frame::parse_frame(&v3).unwrap_err(),
        Error::UnsupportedVersion(3)
    );
}

#[test]
fn error_codes_are_pinned() {
    assert_eq!(ERR_NONE, 0x00);
    assert_eq!(ERR_UNKNOWN_TYPE, 0x01);
    assert_eq!(ERR_INVALID_PAYLOAD, 0x02);
    assert_eq!(ERR_RESOURCE_FULL, 0x03);
    assert_eq!(ERR_NOT_FOUND, 0x04);
    assert_eq!(ERR_INVALID_INTERFACE, 0x05);
    assert_eq!(ERR_INVALID_STATE, 0x06);
    assert_eq!(ERR_PERSIST_FAIL, 0x07);
    assert_eq!(ERR_CRC_FAIL, 0x08);
    assert_eq!(ERR_WRITE_LOCKED, 0x09);
    assert_eq!(ERR_READ_ONLY, 0x0A);
    assert_eq!(ERR_OUT_OF_RANGE, 0x0B);
    assert_eq!(ERR_VERSION, 0x0C);
}

#[test]
fn signal_target_types_are_pinned() {
    assert_eq!(SIGNAL_TARGET_INTERFACE, 0);
    assert_eq!(SIGNAL_TARGET_PERIPHERAL, 1);
    assert_eq!(SIGNAL_TARGET_DEVICE, 2);
}

#[test]
fn interface_types_are_pinned() {
    assert_eq!(IFACE_CAN, 0x01);
    assert_eq!(IFACE_CANFD, 0x02);
    assert_eq!(IFACE_RS485, 0x03);
    assert_eq!(IFACE_RS232, 0x04);
    assert_eq!(IFACE_LIN, 0x05);
}

#[test]
fn peripheral_kinds_are_pinned() {
    assert_eq!(PERIPH_KIND_SENSOR, 0x01);
    assert_eq!(PERIPH_KIND_ACTUATOR, 0x02);
    assert_eq!(PERIPH_KIND_CONTROLLER, 0x03);
    assert_eq!(PERIPH_KIND_LINK, 0x04);
}

#[test]
fn signal_roles_are_pinned() {
    assert_eq!(ROLE_MEASUREMENT, 0x01);
    assert_eq!(ROLE_STATUS, 0x02);
    assert_eq!(ROLE_SETPOINT, 0x03);
    assert_eq!(ROLE_OUTPUT, 0x04);
    assert_eq!(ROLE_CONFIG, 0x05);
    assert_eq!(ROLE_COMMAND, 0x06);
    assert_eq!(ROLE_DIAGNOSTIC, 0x07);
}

#[test]
fn quantities_are_pinned() {
    assert_eq!(QTY_RAW, 0x00);
    assert_eq!(QTY_BOOL, 0x01);
    assert_eq!(QTY_ENUM, 0x02);
    assert_eq!(QTY_BITMASK, 0x03);
    assert_eq!(QTY_COUNT, 0x04);
    assert_eq!(QTY_RATIO, 0x05);
    assert_eq!(QTY_TEMPERATURE, 0x06);
    assert_eq!(QTY_CURRENT, 0x07);
    assert_eq!(QTY_VOLTAGE, 0x08);
    assert_eq!(QTY_POWER, 0x09);
    assert_eq!(QTY_ENERGY, 0x0A);
    assert_eq!(QTY_CHARGE, 0x0B);
    assert_eq!(QTY_PRESSURE, 0x0C);
    assert_eq!(QTY_FREQUENCY, 0x0D);
    assert_eq!(QTY_DATARATE, 0x0E);
    assert_eq!(QTY_DURATION, 0x0F);
    assert_eq!(QTY_COLOUR_RGB, 0x10);
    assert_eq!(QTY_STRING, 0x11);
    assert_eq!(QTY_RESISTANCE, 0x12);
    assert_eq!(QTY_CAPACITANCE, 0x13);
    assert_eq!(QTY_APPARENT_POWER, 0x14);
    assert_eq!(QTY_POWER_LEVEL, 0x15);
    assert_eq!(QTY_PER_SECOND, 0x80);
    assert_eq!(QTY_BASE_MASK, 0x7F);
}

#[test]
fn aspects_are_pinned() {
    assert_eq!(ASPECT_DEFAULT, 0);
    assert_eq!(ASPECT_TERMINATION, 1);
    assert_eq!(ASPECT_STANDBY, 2);
    assert_eq!(ASPECT_PARITY, 3);
    assert_eq!(ASPECT_STOP_BITS, 4);
    assert_eq!(ASPECT_DATA_BITS, 5);
    assert_eq!(ASPECT_CLIENT, 6);
    assert_eq!(ASPECT_FORWARD, 7);
    assert_eq!(ASPECT_INGRESS, 8);
    assert_eq!(ASPECT_INTEGRITY, 9);
    assert_eq!(ASPECT_TIMING, 10);
    assert_eq!(ASPECT_REFERENCE, 11);
    assert_eq!(ASPECT_RAMPED, 12);
    assert_eq!(ASPECT_ELAPSED, 13);
    assert_eq!(ASPECT_START, 14);
    assert_eq!(ASPECT_HIGH, 15);
    assert_eq!(ASPECT_LOW, 16);
    assert_eq!(ASPECT_PROPORTIONAL, 17);
    assert_eq!(ASPECT_INTEGRAL, 18);
    assert_eq!(ASPECT_DERIVATIVE, 19);
    assert_eq!(ASPECT_DC, 20);
    assert_eq!(ASPECT_AC, 21);
}

#[test]
fn meta_ids_are_pinned() {
    assert_eq!(META_BOARD_NAME, 0x01);
    assert_eq!(META_BOARD_REVISION, 0x02);
    assert_eq!(META_DEVICE_ID, 0x03);
    assert_eq!(META_MAX_FRAME_DEFS, 0x04);
    assert_eq!(META_MAX_SIGNALS_PER_FRAME, 0x05);
    assert_eq!(META_MAX_SIGNAL_STORE, 0x06);
    assert_eq!(META_MAX_TRANSFORMERS, 0x07);
    assert_eq!(META_MAX_GENERATORS, 0x08);
    assert_eq!(META_MAX_BRIDGES, 0x09);
    assert_eq!(META_MAX_FILTERS_PER_BRIDGE, 0x0A);
    assert_eq!(META_MAX_MAPPINGS_PER_XFORM, 0x0B);
    assert_eq!(META_TX_QUEUE_DEPTH, 0x0C);
    assert_eq!(META_SUPPORTED_FUNCTIONS, 0x0D);
    assert_eq!(META_CAN_MAX_DLC, 0x0E);
}

#[test]
fn value_types_are_pinned() {
    assert_eq!(frame_def::VALUE_TYPE_UNSIGNED, 0);
    assert_eq!(frame_def::VALUE_TYPE_SIGNED, 1);
    assert_eq!(frame_def::VALUE_TYPE_FLOAT, 2);
    assert_eq!(frame_def::VALUE_TYPE_BOOL, 3);
    assert_eq!(frame_def::VALUE_TYPE_ARRAY, 4);
}

#[test]
fn can_frame_def_flags_are_pinned() {
    assert_eq!(frame_def::CAN_FLAG_EXTENDED, 0x01);
    assert_eq!(frame_def::CAN_FLAG_FD, 0x02);
    assert_eq!(frame_def::CAN_FLAG_BRS, 0x04);
    assert_eq!(frame_def::CAN_FLAG_RTR, 0x08);
    assert_eq!(frame_def::CAN_FLAG_MATCH_ANY, 0x80);
}

#[test]
fn can_id_layout_is_pinned() {
    assert_eq!(can_id::CAN_HOST_BIT, 0x1000_0000);
    assert_eq!(can_id::CAN_DEVICE_ID_MASK, 0x0FFF_FF00);
    assert_eq!(can_id::CAN_SLOT_MASK, 0xFF);
    assert_eq!(can_id::SLOT_ISOTP_H2D, 0x40);
    assert_eq!(can_id::SLOT_ISOTP_D2H, 0x41);
    assert_eq!(
        can_id::can_id(0x00AB_CD00, can_id::SLOT_ISOTP_H2D, true),
        0x10AB_CD40
    );
    assert_eq!(
        can_id::can_id(0x00AB_CD00, can_id::SLOT_ISOTP_D2H, false),
        0x00AB_CD41
    );
}

#[test]
fn dsig_flags_are_pinned() {
    assert_eq!(DSIG_FLAG_WRITABLE, 0x01);
    assert_eq!(DSIG_FLAG_PERSISTABLE, 0x02);
    assert_eq!(DSIG_FLAG_RULE_DEST, 0x04);
    assert_eq!(DSIG_FLAG_FRAME_DEST, 0x08);
}

#[test]
fn file_transfer_messages_are_pinned() {
    assert_eq!(MSG_FILE_BEGIN, 0x57);
    assert_eq!(MSG_FILE_DATA, 0x58);
    assert_eq!(MSG_FILE_END, 0x59);
    assert_eq!(META_MAX_FILE_CHUNK, 0x20);
}

#[test]
fn file_begin_matches_its_golden_vector() {
    use wslib_framelink_protocol::file_xfer::{FileBegin, pack_begin};

    let packed = pack_begin(&FileBegin {
        target: 3,
        size: 600,
        crc32: 0x1234_5678,
    });

    assert_eq!(
        packed,
        [0x03, 0x58, 0x02, 0x00, 0x00, 0x78, 0x56, 0x34, 0x12]
    );
}

#[test]
fn device_signal_constants_are_pinned() {
    assert_eq!(DEVICE_SIGNAL_ID_BASE, 0xFF00);
    assert_eq!(DEVICE_SIGNAL_ID_MAX, 0xFFFE);
    assert_eq!(SIGNAL_CHANNEL_NONE, 0xFF);
    assert_eq!(FRAME_DEF_ID_DEVICE, 0xFFFF);
    assert_eq!(FRAME_DEF_ID_USER, 0xFFFE);
    assert_eq!(DSIG_FLAG_WRITABLE, 1 << 0);
    assert_eq!(DSIG_FLAG_PERSISTABLE, 1 << 1);
}

#[test]
fn rule_format_2_message_ids_are_pinned() {
    assert_eq!(MSG_COUNTER_ADD, 0x78);
    assert_eq!(MSG_COUNTER_REMOVE, 0x79);
    assert_eq!(MSG_COUNTER_LIST, 0x7A);
    assert_eq!(MSG_COUNTER_RESP, 0x7B);
    assert_eq!(MSG_EVENT_RULE_ADD, 0x7C);
    assert_eq!(MSG_EVENT_RULE_REMOVE, 0x7D);
    assert_eq!(MSG_EVENT_RULE_LIST, 0x7E);
    assert_eq!(MSG_EVENT_RULE_RESP, 0x7F);
    assert_eq!(MSG_FSM_ADD, 0x80);
    assert_eq!(MSG_FSM_REMOVE, 0x81);
    assert_eq!(MSG_FSM_LIST, 0x82);
    assert_eq!(MSG_FSM_RESP, 0x83);
    assert_eq!(MSG_FSM_ENABLE, 0x84);
    assert_eq!(MSG_TX_GROUP_ADD, 0x90);
    assert_eq!(MSG_TX_GROUP_REMOVE, 0x91);
    assert_eq!(MSG_TX_GROUP_LIST, 0x92);
    assert_eq!(MSG_TX_GROUP_RESP, 0x93);
    assert_eq!(MSG_TEMPLATE_SET, 0x94);
    for id in [
        MSG_COUNTER_ADD,
        MSG_COUNTER_REMOVE,
        MSG_COUNTER_LIST,
        MSG_COUNTER_RESP,
        MSG_EVENT_RULE_ADD,
        MSG_EVENT_RULE_REMOVE,
        MSG_EVENT_RULE_LIST,
        MSG_EVENT_RULE_RESP,
        MSG_FSM_ADD,
        MSG_FSM_REMOVE,
        MSG_FSM_LIST,
        MSG_FSM_RESP,
        MSG_FSM_ENABLE,
        MSG_TX_GROUP_ADD,
        MSG_TX_GROUP_REMOVE,
        MSG_TX_GROUP_LIST,
        MSG_TX_GROUP_RESP,
        MSG_TEMPLATE_SET,
    ] {
        assert_ne!(msg_type_name(id), "UNKNOWN", "0x{id:02X} has no name");
    }
}

#[test]
fn sequence_id_block_is_reserved() {
    assert_eq!(MSG_SEQ_RESERVED_FIRST, 0x8A);
    const { assert!(MSG_TX_GROUP_ADD > MSG_SEQ_RESERVED_LAST) };
}

#[test]
fn retired_responder_ids_are_not_allocatable() {
    for id in 0x85u8..=0x89 {
        assert_eq!(
            msg_type_name(id),
            "UNKNOWN",
            "0x{id:02X} is retired, not allocatable"
        );
    }
}

#[test]
fn rule_format_2_capability_ids_are_pinned() {
    assert_eq!(META_MAX_COUNTERS, 0x0F);
    assert_eq!(META_MAX_EVENT_RULES, 0x10);
    assert_eq!(META_MAX_FSMS, 0x11);
    assert_eq!(META_RETIRED_RESPONDERS, 0x12);
    assert_eq!(META_MAX_FIELD_OPS_PER_GEN, 0x13);
    assert_eq!(META_SUPPORTED_CHECKSUMS, 0x14);
    assert_eq!(META_MAX_SEQUENCES, 0x15);
    assert_eq!(META_RULE_FORMAT, 0x16);
    assert_eq!(META_MAX_FSM_ROWS, 0x17);
    assert_eq!(META_TEMPLATE_POOL_SIZE, 0x18);
    assert_eq!(META_MAX_TX_GROUPS, 0x19);
    assert_eq!(META_MAX_ENTRIES_PER_GROUP, 0x1A);
    assert_eq!(META_MAX_MAPPING_POOL, 0x1B);
    assert_eq!(META_MAX_SIGNAL_DEF_POOL, 0x1C);
    assert_eq!(META_DRAIN_MAX_PASSES, 0x1D);
    assert_eq!(META_LONG_TEMPLATE_POOL_SIZE, 0x1E);
    assert_eq!(META_MAX_MULTIFRAME_BYTES, 0x1F);
    assert_eq!(RULE_FORMAT, 2);
}
