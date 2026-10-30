//! Message types, flags, error codes, and the closed signal vocabularies:
//! interface types, peripheral kinds, roles, quantities, aspects and static
//! metadata ids. A new product adds capability rows on the device, never
//! values here.

pub const FRAMELINK_DEFAULT_PORT: u16 = 120;

// -- Message types -----------------------------------------------------------

// System (0x01 - 0x0F)
pub const MSG_PING: u8 = 0x01;
pub const MSG_PONG: u8 = 0x02;
pub const MSG_CAPABILITIES_REQ: u8 = 0x03;
pub const MSG_CAPABILITIES_RESP: u8 = 0x04;
pub const MSG_ACK: u8 = 0x05;
pub const MSG_NACK: u8 = 0x06;
pub const MSG_RESET: u8 = 0x07;

// Frame data (0x10 - 0x1F)
pub const MSG_FRAME_RX: u8 = 0x10;
pub const MSG_FRAME_TX: u8 = 0x11;
pub const MSG_STREAM_START: u8 = 0x12;
pub const MSG_STREAM_STOP: u8 = 0x13;
pub const MSG_FRAME_TX_BATCH: u8 = 0x14;

// Interface configuration (0x20 - 0x2F)
pub const MSG_IFACE_CONFIG_SET: u8 = 0x20;
pub const MSG_IFACE_CONFIG_GET: u8 = 0x21;
pub const MSG_IFACE_CONFIG_RESP: u8 = 0x22;

// Frame definitions (0x30 - 0x3F)
pub const MSG_FRAME_DEF_ADD: u8 = 0x30;
pub const MSG_FRAME_DEF_REMOVE: u8 = 0x31;
pub const MSG_FRAME_DEF_LIST: u8 = 0x32;
pub const MSG_FRAME_DEF_RESP: u8 = 0x33;

// Transformers (0x40 - 0x47)
pub const MSG_XFORM_ADD: u8 = 0x40;
pub const MSG_XFORM_REMOVE: u8 = 0x41;
pub const MSG_XFORM_LIST: u8 = 0x42;
pub const MSG_XFORM_RESP: u8 = 0x43;
pub const MSG_XFORM_ENABLE: u8 = 0x44;

// Generators (0x48 - 0x4F)
pub const MSG_GEN_ADD: u8 = 0x48;
pub const MSG_GEN_REMOVE: u8 = 0x49;
pub const MSG_GEN_LIST: u8 = 0x4A;
pub const MSG_GEN_RESP: u8 = 0x4B;
pub const MSG_GEN_ENABLE: u8 = 0x4C;

// Bridges (0x70 - 0x77)
pub const MSG_BRIDGE_ADD: u8 = 0x70;
pub const MSG_BRIDGE_REMOVE: u8 = 0x71;
pub const MSG_BRIDGE_LIST: u8 = 0x72;
pub const MSG_BRIDGE_RESP: u8 = 0x73;
pub const MSG_BRIDGE_ENABLE: u8 = 0x74;

pub const MSG_COUNTER_ADD: u8 = 0x78;
pub const MSG_COUNTER_REMOVE: u8 = 0x79;
pub const MSG_COUNTER_LIST: u8 = 0x7A;
pub const MSG_COUNTER_RESP: u8 = 0x7B;
pub const MSG_EVENT_RULE_ADD: u8 = 0x7C;
pub const MSG_EVENT_RULE_REMOVE: u8 = 0x7D;
pub const MSG_EVENT_RULE_LIST: u8 = 0x7E;
pub const MSG_EVENT_RULE_RESP: u8 = 0x7F;
pub const MSG_FSM_ADD: u8 = 0x80;
pub const MSG_FSM_REMOVE: u8 = 0x81;
pub const MSG_FSM_LIST: u8 = 0x82;
pub const MSG_FSM_RESP: u8 = 0x83;
pub const MSG_FSM_ENABLE: u8 = 0x84;
pub const MSG_SEQ_RESERVED_FIRST: u8 = 0x8A;
pub const MSG_SEQ_RESERVED_LAST: u8 = 0x8E;
pub const MSG_TX_GROUP_ADD: u8 = 0x90;
pub const MSG_TX_GROUP_REMOVE: u8 = 0x91;
pub const MSG_TX_GROUP_LIST: u8 = 0x92;
pub const MSG_TX_GROUP_RESP: u8 = 0x93;
pub const MSG_TEMPLATE_SET: u8 = 0x94;

// User signals (0x5A - 0x5B)
pub const MSG_USER_SIGNAL_ADD: u8 = 0x5A;
pub const MSG_USER_SIGNAL_REMOVE: u8 = 0x5B;

// Persistence (0x50 - 0x5F)
pub const MSG_PERSIST_SAVE: u8 = 0x50;
pub const MSG_PERSIST_LOAD: u8 = 0x51;
pub const MSG_PERSIST_CLEAR: u8 = 0x52;

// Board definition storage (0x54 - 0x56)
pub const MSG_BOARD_DEF_UPLOAD: u8 = 0x54;
pub const MSG_BOARD_DEF_DOWNLOAD: u8 = 0x55;
pub const MSG_BOARD_DEF_CLEAR: u8 = 0x56;

pub const MSG_FILE_BEGIN: u8 = 0x57;
pub const MSG_FILE_DATA: u8 = 0x58;
pub const MSG_FILE_END: u8 = 0x59;

// Device signals (0x60 - 0x6F)
pub const MSG_DSIG_LIST: u8 = 0x60;
pub const MSG_DSIG_LIST_RESP: u8 = 0x61;
pub const MSG_DSIG_READ: u8 = 0x62;
pub const MSG_DSIG_READ_RESP: u8 = 0x63;
pub const MSG_DSIG_WRITE: u8 = 0x64;
pub const MSG_DSIG_SET_INTERVAL: u8 = 0x5C;

// Write interlock (0x68 - 0x6B)
pub const MSG_WRITE_CHALLENGE: u8 = 0x68;
pub const MSG_WRITE_CHALLENGE_RESP: u8 = 0x69;
pub const MSG_WRITE_UNLOCK: u8 = 0x6A;
pub const MSG_WRITE_LOCK: u8 = 0x6B;

// -- Header flags ------------------------------------------------------------

pub const FLAG_NONE: u8 = 0x00;
pub const FLAG_ACK_REQ: u8 = 0x01;
pub const FLAG_RESPONSE: u8 = 0x02;
pub const FLAG_ERROR: u8 = 0x04;

// -- Error codes (NACK payload) ----------------------------------------------

pub const ERR_NONE: u8 = 0x00;
pub const ERR_UNKNOWN_TYPE: u8 = 0x01;
pub const ERR_INVALID_PAYLOAD: u8 = 0x02;
pub const ERR_RESOURCE_FULL: u8 = 0x03;
pub const ERR_NOT_FOUND: u8 = 0x04;
pub const ERR_INVALID_INTERFACE: u8 = 0x05;
pub const ERR_INVALID_STATE: u8 = 0x06;
pub const ERR_PERSIST_FAIL: u8 = 0x07;
pub const ERR_CRC_FAIL: u8 = 0x08;
pub const ERR_WRITE_LOCKED: u8 = 0x09;
pub const ERR_READ_ONLY: u8 = 0x0A;
pub const ERR_OUT_OF_RANGE: u8 = 0x0B;
pub const ERR_VERSION: u8 = 0x0C;

pub fn nack_code(payload: &[u8]) -> u8 {
    payload.first().copied().unwrap_or(ERR_NONE)
}

pub fn error_name(code: u8) -> &'static str {
    match code {
        ERR_NONE => "None",
        ERR_UNKNOWN_TYPE => "Unknown message type",
        ERR_INVALID_PAYLOAD => "Invalid payload",
        ERR_RESOURCE_FULL => "Resource full",
        ERR_NOT_FOUND => "Not found",
        ERR_INVALID_INTERFACE => "Invalid interface",
        ERR_INVALID_STATE => "Invalid state",
        ERR_PERSIST_FAIL => "Persistence failure",
        ERR_CRC_FAIL => "CRC failure",
        ERR_WRITE_LOCKED => "Write locked",
        ERR_READ_ONLY => "Read-only",
        ERR_OUT_OF_RANGE => "Out of range",
        ERR_VERSION => "Protocol version mismatch",
        _ => "Unknown error",
    }
}

// -- Interface types ---------------------------------------------------------

pub const IFACE_CAN: u8 = 0x01;
pub const IFACE_CANFD: u8 = 0x02;
pub const IFACE_RS485: u8 = 0x03;
pub const IFACE_RS232: u8 = 0x04;
pub const IFACE_LIN: u8 = 0x05;

/// Every interface type with its display name, for a consumer to enumerate.
pub const INTERFACE_NAMES: &[(u8, &str)] = &[
    (IFACE_CAN, "CAN"),
    (IFACE_CANFD, "CAN FD"),
    (IFACE_RS485, "RS-485"),
    (IFACE_RS232, "RS-232"),
    (IFACE_LIN, "LIN"),
];

/// `"Unknown"` for a type not in [`INTERFACE_NAMES`].
pub fn interface_name(iface_type: u8) -> &'static str {
    table_name(INTERFACE_NAMES, iface_type, "Unknown")
}

pub(crate) fn table_name(
    table: &'static [(u8, &'static str)],
    id: u8,
    unknown: &'static str,
) -> &'static str {
    table
        .iter()
        .find(|(known, _)| *known == id)
        .map_or(unknown, |(_, name)| name)
}

/// Board-TOML slug for an interface type.
pub fn interface_slug(iface_type: u8) -> &'static str {
    match iface_type {
        IFACE_CAN => "can",
        IFACE_CANFD => "canfd",
        IFACE_RS485 => "rs485",
        IFACE_RS232 => "rs232",
        IFACE_LIN => "lin",
        _ => "unknown",
    }
}

// -- Peripheral kinds --------------------------------------------------------

// Dataflow topology only: what a peripheral is, its signals imply and the
// board TOML names.

/// Produces measurements (N channels, mixed quantities allowed).
pub const PERIPH_KIND_SENSOR: u8 = 0x01;
/// Accepts commanded values that affect the world.
pub const PERIPH_KIND_ACTUATOR: u8 = 0x02;
/// Closes a loop: owns the measurement/setpoint/output triad.
pub const PERIPH_KIND_CONTROLLER: u8 = 0x03;
/// Comms channel that is not a frame-streaming interface.
pub const PERIPH_KIND_LINK: u8 = 0x04;

pub fn peripheral_kind_name(kind: u8) -> &'static str {
    match kind {
        PERIPH_KIND_SENSOR => "Sensor",
        PERIPH_KIND_ACTUATOR => "Actuator",
        PERIPH_KIND_CONTROLLER => "Controller",
        PERIPH_KIND_LINK => "Link",
        _ => "Unknown",
    }
}

/// Board-TOML slug for a peripheral kind.
pub fn peripheral_kind_slug(kind: u8) -> &'static str {
    match kind {
        PERIPH_KIND_SENSOR => "sensor",
        PERIPH_KIND_ACTUATOR => "actuator",
        PERIPH_KIND_CONTROLLER => "controller",
        PERIPH_KIND_LINK => "link",
        _ => "unknown",
    }
}

// -- Signal roles --------------------------------------------------------------

/// Sensed physical value.
pub const ROLE_MEASUREMENT: u8 = 0x01;
/// Device-reported operational state a UI shows.
pub const ROLE_STATUS: u8 = 0x02;
/// Desired value of an actuated or controlled quantity.
pub const ROLE_SETPOINT: u8 = 0x03;
/// Actuation level currently applied.
pub const ROLE_OUTPUT: u8 = 0x04;
/// Behavioural/tuning parameter (hysteresis, poll interval, bitrate).
pub const ROLE_CONFIG: u8 = 0x05;
/// Momentary stimulus — a write causes an effect, not persistent state.
pub const ROLE_COMMAND: u8 = 0x06;
/// Health/error accounting a UI hides by default.
pub const ROLE_DIAGNOSTIC: u8 = 0x07;

pub fn role_name(role: u8) -> &'static str {
    match role {
        ROLE_MEASUREMENT => "Measurement",
        ROLE_STATUS => "Status",
        ROLE_SETPOINT => "Setpoint",
        ROLE_OUTPUT => "Output",
        ROLE_CONFIG => "Config",
        ROLE_COMMAND => "Command",
        ROLE_DIAGNOSTIC => "Diagnostic",
        _ => "Unknown",
    }
}

/// Board-TOML slug for a signal role.
pub fn role_slug(role: u8) -> &'static str {
    match role {
        ROLE_MEASUREMENT => "measurement",
        ROLE_STATUS => "status",
        ROLE_SETPOINT => "setpoint",
        ROLE_OUTPUT => "output",
        ROLE_CONFIG => "config",
        ROLE_COMMAND => "command",
        ROLE_DIAGNOSTIC => "diagnostic",
        _ => "unknown",
    }
}

/// Parse a board-TOML role slug.
pub fn role_from_slug(slug: &str) -> Option<u8> {
    Some(match slug {
        "measurement" => ROLE_MEASUREMENT,
        "status" => ROLE_STATUS,
        "setpoint" => ROLE_SETPOINT,
        "output" => ROLE_OUTPUT,
        "config" => ROLE_CONFIG,
        "command" => ROLE_COMMAND,
        "diagnostic" => ROLE_DIAGNOSTIC,
        _ => return None,
    })
}

// -- Physical quantities -------------------------------------------------------

// Each quantity has exactly one canonical unit; magnitude/resolution live in
// the descriptor's scale/offset, never here.

pub const QTY_RAW: u8 = 0x00;
pub const QTY_BOOL: u8 = 0x01;
pub const QTY_ENUM: u8 = 0x02;
pub const QTY_BITMASK: u8 = 0x03;
pub const QTY_COUNT: u8 = 0x04;
/// 0..1; percent = scale 0.01.
pub const QTY_RATIO: u8 = 0x05;
/// °C.
pub const QTY_TEMPERATURE: u8 = 0x06;
/// A.
pub const QTY_CURRENT: u8 = 0x07;
/// V.
pub const QTY_VOLTAGE: u8 = 0x08;
/// W.
pub const QTY_POWER: u8 = 0x09;
/// J; Wh = scale 3600.
pub const QTY_ENERGY: u8 = 0x0A;
/// C; Ah = scale 3600.
pub const QTY_CHARGE: u8 = 0x0B;
/// Pa.
pub const QTY_PRESSURE: u8 = 0x0C;
/// Hz (cyclic rate).
pub const QTY_FREQUENCY: u8 = 0x0D;
/// bit/s.
pub const QTY_DATARATE: u8 = 0x0E;
/// s; also offsets from a target-defined epoch.
pub const QTY_DURATION: u8 = 0x0F;
/// u32 0x00RRGGBB composite.
pub const QTY_COLOUR_RGB: u8 = 0x10;
/// UTF-8 — metadata only, never in the signal store.
pub const QTY_STRING: u8 = 0x11;
pub const QTY_RESISTANCE: u8 = 0x12;
pub const QTY_CAPACITANCE: u8 = 0x13;
pub const QTY_APPARENT_POWER: u8 = 0x14;
pub const QTY_POWER_LEVEL: u8 = 0x15;

/// Time-derivative modifier bit (TEMPERATURE | PER_SECOND = °C/s).
pub const QTY_PER_SECOND: u8 = 0x80;
pub const QTY_BASE_MASK: u8 = 0x7F;

pub fn quantity_name(quantity: u8) -> &'static str {
    match quantity & QTY_BASE_MASK {
        QTY_RAW => "Raw",
        QTY_BOOL => "Bool",
        QTY_ENUM => "Enum",
        QTY_BITMASK => "Bitmask",
        QTY_COUNT => "Count",
        QTY_RATIO => "Ratio",
        QTY_TEMPERATURE => "Temperature",
        QTY_CURRENT => "Current",
        QTY_VOLTAGE => "Voltage",
        QTY_POWER => "Power",
        QTY_ENERGY => "Energy",
        QTY_CHARGE => "Charge",
        QTY_PRESSURE => "Pressure",
        QTY_FREQUENCY => "Frequency",
        QTY_DATARATE => "Bitrate",
        QTY_DURATION => "Duration",
        QTY_COLOUR_RGB => "Colour",
        QTY_STRING => "String",
        QTY_RESISTANCE => "Resistance",
        QTY_CAPACITANCE => "Capacitance",
        QTY_APPARENT_POWER => "Apparent Power",
        QTY_POWER_LEVEL => "Power Level",
        _ => "Unknown",
    }
}

/// Display name for a quantity, including the per-second modifier.
pub fn quantity_display(quantity: u8) -> String {
    if quantity & QTY_PER_SECOND != 0 {
        format!("{}/s", quantity_name(quantity))
    } else {
        quantity_name(quantity).to_string()
    }
}

/// Canonical unit for a base quantity ("" for dimensionless quantities).
pub fn quantity_unit(quantity: u8) -> &'static str {
    match quantity & QTY_BASE_MASK {
        QTY_TEMPERATURE => "°C",
        QTY_CURRENT => "A",
        QTY_VOLTAGE => "V",
        QTY_POWER => "W",
        QTY_ENERGY => "J",
        QTY_CHARGE => "C",
        QTY_PRESSURE => "Pa",
        QTY_FREQUENCY => "Hz",
        QTY_DATARATE => "bit/s",
        QTY_DURATION => "s",
        QTY_RESISTANCE => "Ω",
        QTY_CAPACITANCE => "F",
        QTY_APPARENT_POWER => "VA",
        QTY_POWER_LEVEL => "dBm",
        _ => "",
    }
}

/// Board-TOML slug for a base quantity (modifier bit ignored).
pub fn quantity_slug(quantity: u8) -> &'static str {
    match quantity & QTY_BASE_MASK {
        QTY_RAW => "raw",
        QTY_BOOL => "bool",
        QTY_ENUM => "enum",
        QTY_BITMASK => "bitmask",
        QTY_COUNT => "count",
        QTY_RATIO => "ratio",
        QTY_TEMPERATURE => "temperature",
        QTY_CURRENT => "current",
        QTY_VOLTAGE => "voltage",
        QTY_POWER => "power",
        QTY_ENERGY => "energy",
        QTY_CHARGE => "charge",
        QTY_PRESSURE => "pressure",
        QTY_FREQUENCY => "frequency",
        QTY_DATARATE => "datarate",
        QTY_DURATION => "duration",
        QTY_COLOUR_RGB => "colour_rgb",
        QTY_STRING => "string",
        QTY_RESISTANCE => "resistance",
        QTY_CAPACITANCE => "capacitance",
        QTY_APPARENT_POWER => "apparent_power",
        QTY_POWER_LEVEL => "power_level",
        _ => "unknown",
    }
}

/// Parse a board-TOML quantity slug, honouring an optional `_per_s` suffix.
pub fn quantity_from_slug(slug: &str) -> Option<u8> {
    let (base, per_second) = match slug.strip_suffix("_per_s") {
        Some(base) => (base, QTY_PER_SECOND),
        None => (slug, 0),
    };
    let q = match base {
        "raw" => QTY_RAW,
        "bool" => QTY_BOOL,
        "enum" => QTY_ENUM,
        "bitmask" => QTY_BITMASK,
        "count" => QTY_COUNT,
        "ratio" => QTY_RATIO,
        "temperature" => QTY_TEMPERATURE,
        "current" => QTY_CURRENT,
        "voltage" => QTY_VOLTAGE,
        "power" => QTY_POWER,
        "energy" => QTY_ENERGY,
        "charge" => QTY_CHARGE,
        "pressure" => QTY_PRESSURE,
        "frequency" => QTY_FREQUENCY,
        "datarate" => QTY_DATARATE,
        "duration" => QTY_DURATION,
        "colour_rgb" => QTY_COLOUR_RGB,
        "string" => QTY_STRING,
        "resistance" => QTY_RESISTANCE,
        "capacitance" => QTY_CAPACITANCE,
        "apparent_power" => QTY_APPARENT_POWER,
        "power_level" => QTY_POWER_LEVEL,
        _ => return None,
    };
    Some(q | per_second)
}

// -- Aspects -------------------------------------------------------------------

// Distinguishes signals that otherwise share (target, role, quantity, channel).
// DEFAULT is reserved for the self-evident primary.

pub const ASPECT_DEFAULT: u8 = 0;
pub const ASPECT_TERMINATION: u8 = 1;
pub const ASPECT_STANDBY: u8 = 2;
pub const ASPECT_PARITY: u8 = 3;
pub const ASPECT_STOP_BITS: u8 = 4;
pub const ASPECT_DATA_BITS: u8 = 5;
/// Client-delivery drop counter.
pub const ASPECT_CLIENT: u8 = 6;
/// Forward direction: bridge-forward drops, diode forward voltage.
pub const ASPECT_FORWARD: u8 = 7;
/// RX/ingress queue drop counter.
pub const ASPECT_INGRESS: u8 = 8;
pub const ASPECT_INTEGRITY: u8 = 9;
pub const ASPECT_TIMING: u8 = 10;
pub const ASPECT_REFERENCE: u8 = 11;
pub const ASPECT_RAMPED: u8 = 12;
pub const ASPECT_ELAPSED: u8 = 13;
pub const ASPECT_START: u8 = 14;
pub const ASPECT_HIGH: u8 = 15;
pub const ASPECT_LOW: u8 = 16;
pub const ASPECT_PROPORTIONAL: u8 = 17;
pub const ASPECT_INTEGRAL: u8 = 18;
pub const ASPECT_DERIVATIVE: u8 = 19;
pub const ASPECT_DC: u8 = 20;
/// RMS.
pub const ASPECT_AC: u8 = 21;

pub fn aspect_name(aspect: u8) -> &'static str {
    match aspect {
        ASPECT_DEFAULT => "Default",
        ASPECT_TERMINATION => "Termination",
        ASPECT_STANDBY => "Standby",
        ASPECT_PARITY => "Parity",
        ASPECT_STOP_BITS => "Stop Bits",
        ASPECT_DATA_BITS => "Data Bits",
        ASPECT_CLIENT => "Client",
        ASPECT_FORWARD => "Forward",
        ASPECT_INGRESS => "Ingress",
        ASPECT_INTEGRITY => "Integrity",
        ASPECT_TIMING => "Timing",
        ASPECT_REFERENCE => "Reference",
        ASPECT_RAMPED => "Ramped",
        ASPECT_ELAPSED => "Elapsed",
        ASPECT_START => "Start",
        ASPECT_HIGH => "High",
        ASPECT_LOW => "Low",
        ASPECT_PROPORTIONAL => "Proportional",
        ASPECT_INTEGRAL => "Integral",
        ASPECT_DERIVATIVE => "Derivative",
        ASPECT_DC => "DC",
        ASPECT_AC => "AC",
        _ => "Unknown",
    }
}

/// Board-TOML slug for an aspect.
pub fn aspect_slug(aspect: u8) -> &'static str {
    match aspect {
        ASPECT_DEFAULT => "default",
        ASPECT_TERMINATION => "termination",
        ASPECT_STANDBY => "standby",
        ASPECT_PARITY => "parity",
        ASPECT_STOP_BITS => "stop_bits",
        ASPECT_DATA_BITS => "data_bits",
        ASPECT_CLIENT => "client",
        ASPECT_FORWARD => "forward",
        ASPECT_INGRESS => "ingress",
        ASPECT_INTEGRITY => "integrity",
        ASPECT_TIMING => "timing",
        ASPECT_REFERENCE => "reference",
        ASPECT_RAMPED => "ramped",
        ASPECT_ELAPSED => "elapsed",
        ASPECT_START => "start",
        ASPECT_HIGH => "high",
        ASPECT_LOW => "low",
        ASPECT_PROPORTIONAL => "proportional",
        ASPECT_INTEGRAL => "integral",
        ASPECT_DERIVATIVE => "derivative",
        ASPECT_DC => "dc",
        ASPECT_AC => "ac",
        _ => "unknown",
    }
}

/// Parse a board-TOML aspect slug.
pub fn aspect_from_slug(slug: &str) -> Option<u8> {
    Some(match slug {
        "default" => ASPECT_DEFAULT,
        "termination" => ASPECT_TERMINATION,
        "standby" => ASPECT_STANDBY,
        "parity" => ASPECT_PARITY,
        "stop_bits" => ASPECT_STOP_BITS,
        "data_bits" => ASPECT_DATA_BITS,
        "client" => ASPECT_CLIENT,
        "forward" => ASPECT_FORWARD,
        "ingress" => ASPECT_INGRESS,
        "integrity" => ASPECT_INTEGRITY,
        "timing" => ASPECT_TIMING,
        "reference" => ASPECT_REFERENCE,
        "ramped" => ASPECT_RAMPED,
        "elapsed" => ASPECT_ELAPSED,
        "start" => ASPECT_START,
        "high" => ASPECT_HIGH,
        "low" => ASPECT_LOW,
        "proportional" => ASPECT_PROPORTIONAL,
        "integral" => ASPECT_INTEGRAL,
        "derivative" => ASPECT_DERIVATIVE,
        "dc" => ASPECT_DC,
        "ac" => ASPECT_AC,
        _ => return None,
    })
}

// -- Static metadata IDs -------------------------------------------------------

// Engine and board facts in the capabilities TLVs; anything that varies at
// runtime or describes a peripheral is a signal instead.

pub const META_BOARD_NAME: u8 = 0x01;
pub const META_BOARD_REVISION: u8 = 0x02;
pub const META_DEVICE_ID: u8 = 0x03;
pub const META_MAX_FRAME_DEFS: u8 = 0x04;
pub const META_MAX_SIGNALS_PER_FRAME: u8 = 0x05;
pub const META_MAX_SIGNAL_STORE: u8 = 0x06;
pub const META_MAX_TRANSFORMERS: u8 = 0x07;
pub const META_MAX_GENERATORS: u8 = 0x08;
pub const META_MAX_BRIDGES: u8 = 0x09;
pub const META_MAX_FILTERS_PER_BRIDGE: u8 = 0x0A;
pub const META_MAX_MAPPINGS_PER_XFORM: u8 = 0x0B;
pub const META_TX_QUEUE_DEPTH: u8 = 0x0C;
pub const META_SUPPORTED_FUNCTIONS: u8 = 0x0D;
pub const META_CAN_MAX_DLC: u8 = 0x0E;
pub const META_MAX_COUNTERS: u8 = 0x0F;
pub const META_MAX_EVENT_RULES: u8 = 0x10;
pub const META_MAX_FSMS: u8 = 0x11;
pub const META_RETIRED_RESPONDERS: u8 = 0x12;
pub const META_MAX_FIELD_OPS_PER_GEN: u8 = 0x13;
pub const META_SUPPORTED_CHECKSUMS: u8 = 0x14;
pub const META_MAX_SEQUENCES: u8 = 0x15;
pub const META_RULE_FORMAT: u8 = 0x16;
pub const META_MAX_FSM_ROWS: u8 = 0x17;
pub const META_TEMPLATE_POOL_SIZE: u8 = 0x18;
pub const META_MAX_TX_GROUPS: u8 = 0x19;
pub const META_MAX_ENTRIES_PER_GROUP: u8 = 0x1A;
pub const META_MAX_MAPPING_POOL: u8 = 0x1B;
pub const META_MAX_SIGNAL_DEF_POOL: u8 = 0x1C;
pub const META_DRAIN_MAX_PASSES: u8 = 0x1D;
pub const META_LONG_TEMPLATE_POOL_SIZE: u8 = 0x1E;
pub const META_MAX_MULTIFRAME_BYTES: u8 = 0x1F;
pub const META_MAX_FILE_CHUNK: u8 = 0x20;

pub const RULE_FORMAT: u8 = 2;

pub fn meta_name(id: u8) -> &'static str {
    match id {
        META_BOARD_NAME => "Board Name",
        META_BOARD_REVISION => "Board Revision",
        META_DEVICE_ID => "Device ID",
        META_MAX_FRAME_DEFS => "Max Frame Defs",
        META_MAX_SIGNALS_PER_FRAME => "Max Signals/Frame",
        META_MAX_SIGNAL_STORE => "Max Signal Store",
        META_MAX_TRANSFORMERS => "Max Transformers",
        META_MAX_GENERATORS => "Max Generators",
        META_MAX_BRIDGES => "Max Bridges",
        META_MAX_FILTERS_PER_BRIDGE => "Max Filters/Bridge",
        META_MAX_MAPPINGS_PER_XFORM => "Max Mappings/Xform",
        META_TX_QUEUE_DEPTH => "TX Queue Depth",
        META_SUPPORTED_FUNCTIONS => "Supported Functions",
        META_CAN_MAX_DLC => "CAN Max DLC",
        META_MAX_COUNTERS => "Max Counters",
        META_MAX_EVENT_RULES => "Max Event Rules",
        META_MAX_FSMS => "Max FSMs",
        META_MAX_FIELD_OPS_PER_GEN => "Max Field Ops/Gen",
        META_SUPPORTED_CHECKSUMS => "Supported Checksums",
        META_MAX_SEQUENCES => "Max Sequences",
        META_RULE_FORMAT => "Rule Format",
        META_MAX_FSM_ROWS => "Max FSM Rows",
        META_TEMPLATE_POOL_SIZE => "Template Pool Size",
        META_MAX_TX_GROUPS => "Max TX Groups",
        META_MAX_ENTRIES_PER_GROUP => "Max Entries/Group",
        META_MAX_MAPPING_POOL => "Max Mapping Pool",
        META_MAX_SIGNAL_DEF_POOL => "Max Signal Def Pool",
        META_DRAIN_MAX_PASSES => "Drain Max Passes",
        META_LONG_TEMPLATE_POOL_SIZE => "Long Template Pool Size",
        META_MAX_MULTIFRAME_BYTES => "Max Multiframe Bytes",
        META_MAX_FILE_CHUNK => "Max File Chunk",
        _ => "Unknown",
    }
}

// -- serde field adapters: a type id serialises as its name -------------------

pub(crate) fn ser_interface_name<S: serde::Serializer>(
    iface_type: &u8,
    s: S,
) -> Result<S::Ok, S::Error> {
    s.serialize_str(interface_name(*iface_type))
}

pub(crate) fn ser_peripheral_kind_name<S: serde::Serializer>(
    kind: &u8,
    s: S,
) -> Result<S::Ok, S::Error> {
    s.serialize_str(peripheral_kind_name(*kind))
}

// -- Signal target types -----------------------------------------------------

pub const SIGNAL_TARGET_INTERFACE: u8 = 0;
pub const SIGNAL_TARGET_PERIPHERAL: u8 = 1;
pub const SIGNAL_TARGET_DEVICE: u8 = 2;

pub fn signal_target_name(target: u8) -> &'static str {
    match target {
        SIGNAL_TARGET_INTERFACE => "Interface",
        SIGNAL_TARGET_PERIPHERAL => "Peripheral",
        SIGNAL_TARGET_DEVICE => "Device",
        _ => "Unknown",
    }
}

/// Board-TOML slug for a signal target type.
pub fn signal_target_slug(target: u8) -> &'static str {
    match target {
        SIGNAL_TARGET_INTERFACE => "interface",
        SIGNAL_TARGET_PERIPHERAL => "peripheral",
        SIGNAL_TARGET_DEVICE => "device",
        _ => "unknown",
    }
}

/// Parse a board-TOML signal target slug.
pub fn signal_target_from_slug(slug: &str) -> Option<u8> {
    Some(match slug {
        "interface" => SIGNAL_TARGET_INTERFACE,
        "peripheral" => SIGNAL_TARGET_PERIPHERAL,
        "device" => SIGNAL_TARGET_DEVICE,
        _ => return None,
    })
}

// -- Frame def ID sentinels --------------------------------------------------

pub const FRAME_DEF_ID_DEVICE: u16 = 0xFFFF;

pub const FRAME_DEF_ID_USER: u16 = 0xFFFE;

// -- Device signal constants ---------------------------------------------------

/// The device's reserved signal ids run from here to [`DEVICE_SIGNAL_ID_MAX`].
pub const DEVICE_SIGNAL_ID_BASE: u16 = 0xFF00;
pub const DEVICE_SIGNAL_ID_MAX: u16 = 0xFFFE;

/// The channel of a signal on the whole target.
pub const SIGNAL_CHANNEL_NONE: u8 = 0xFF;

// -- Device signal flags -----------------------------------------------------

pub const DSIG_FLAG_WRITABLE: u8 = 0x01;
pub const DSIG_FLAG_PERSISTABLE: u8 = 0x02;
pub const DSIG_FLAG_RULE_DEST: u8 = 0x04;
pub const DSIG_FLAG_FRAME_DEST: u8 = 0x08;

pub fn msg_type_name(msg_type: u8) -> &'static str {
    match msg_type {
        MSG_PING => "PING",
        MSG_PONG => "PONG",
        MSG_CAPABILITIES_REQ => "CAPABILITIES_REQ",
        MSG_CAPABILITIES_RESP => "CAPABILITIES_RESP",
        MSG_ACK => "ACK",
        MSG_NACK => "NACK",
        MSG_RESET => "RESET",
        MSG_FRAME_RX => "FRAME_RX",
        MSG_FRAME_TX => "FRAME_TX",
        MSG_STREAM_START => "STREAM_START",
        MSG_STREAM_STOP => "STREAM_STOP",
        MSG_FRAME_TX_BATCH => "FRAME_TX_BATCH",
        MSG_DSIG_LIST => "DSIG_LIST",
        MSG_DSIG_LIST_RESP => "DSIG_LIST_RESP",
        MSG_DSIG_READ => "DSIG_READ",
        MSG_DSIG_READ_RESP => "DSIG_READ_RESP",
        MSG_DSIG_WRITE => "DSIG_WRITE",
        MSG_DSIG_SET_INTERVAL => "DSIG_SET_INTERVAL",
        MSG_WRITE_CHALLENGE => "WRITE_CHALLENGE",
        MSG_WRITE_CHALLENGE_RESP => "WRITE_CHALLENGE_RESP",
        MSG_WRITE_UNLOCK => "WRITE_UNLOCK",
        MSG_WRITE_LOCK => "WRITE_LOCK",
        MSG_IFACE_CONFIG_SET => "IFACE_CONFIG_SET",
        MSG_IFACE_CONFIG_GET => "IFACE_CONFIG_GET",
        MSG_IFACE_CONFIG_RESP => "IFACE_CONFIG_RESP",
        MSG_FRAME_DEF_ADD => "FRAME_DEF_ADD",
        MSG_FRAME_DEF_REMOVE => "FRAME_DEF_REMOVE",
        MSG_FRAME_DEF_LIST => "FRAME_DEF_LIST",
        MSG_FRAME_DEF_RESP => "FRAME_DEF_RESP",
        MSG_XFORM_ADD => "XFORM_ADD",
        MSG_XFORM_REMOVE => "XFORM_REMOVE",
        MSG_XFORM_LIST => "XFORM_LIST",
        MSG_XFORM_RESP => "XFORM_RESP",
        MSG_XFORM_ENABLE => "XFORM_ENABLE",
        MSG_GEN_ADD => "GEN_ADD",
        MSG_GEN_REMOVE => "GEN_REMOVE",
        MSG_GEN_LIST => "GEN_LIST",
        MSG_GEN_RESP => "GEN_RESP",
        MSG_GEN_ENABLE => "GEN_ENABLE",
        MSG_PERSIST_SAVE => "PERSIST_SAVE",
        MSG_PERSIST_LOAD => "PERSIST_LOAD",
        MSG_PERSIST_CLEAR => "PERSIST_CLEAR",
        MSG_BRIDGE_ADD => "BRIDGE_ADD",
        MSG_BRIDGE_REMOVE => "BRIDGE_REMOVE",
        MSG_BRIDGE_LIST => "BRIDGE_LIST",
        MSG_BRIDGE_RESP => "BRIDGE_RESP",
        MSG_BRIDGE_ENABLE => "BRIDGE_ENABLE",
        MSG_FILE_BEGIN => "FILE_BEGIN",
        MSG_FILE_DATA => "FILE_DATA",
        MSG_FILE_END => "FILE_END",
        MSG_BOARD_DEF_UPLOAD => "BOARD_DEF_UPLOAD",
        MSG_BOARD_DEF_DOWNLOAD => "BOARD_DEF_DOWNLOAD",
        MSG_BOARD_DEF_CLEAR => "BOARD_DEF_CLEAR",
        MSG_USER_SIGNAL_ADD => "USER_SIGNAL_ADD",
        MSG_USER_SIGNAL_REMOVE => "USER_SIGNAL_REMOVE",
        MSG_COUNTER_ADD => "COUNTER_ADD",
        MSG_COUNTER_REMOVE => "COUNTER_REMOVE",
        MSG_COUNTER_LIST => "COUNTER_LIST",
        MSG_COUNTER_RESP => "COUNTER_RESP",
        MSG_EVENT_RULE_ADD => "EVENT_RULE_ADD",
        MSG_EVENT_RULE_REMOVE => "EVENT_RULE_REMOVE",
        MSG_EVENT_RULE_LIST => "EVENT_RULE_LIST",
        MSG_EVENT_RULE_RESP => "EVENT_RULE_RESP",
        MSG_FSM_ADD => "FSM_ADD",
        MSG_FSM_REMOVE => "FSM_REMOVE",
        MSG_FSM_LIST => "FSM_LIST",
        MSG_FSM_RESP => "FSM_RESP",
        MSG_FSM_ENABLE => "FSM_ENABLE",
        MSG_TX_GROUP_ADD => "TX_GROUP_ADD",
        MSG_TX_GROUP_REMOVE => "TX_GROUP_REMOVE",
        MSG_TX_GROUP_LIST => "TX_GROUP_LIST",
        MSG_TX_GROUP_RESP => "TX_GROUP_RESP",
        MSG_TEMPLATE_SET => "TEMPLATE_SET",
        _ => "UNKNOWN",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn per_second_modifier_round_trips_through_slugs() {
        let q = QTY_TEMPERATURE | QTY_PER_SECOND;
        assert_eq!(quantity_name(q), "Temperature");
        assert_eq!(quantity_display(q), "Temperature/s");
        assert_eq!(quantity_from_slug("temperature_per_s"), Some(q));
        assert_eq!(quantity_from_slug(quantity_slug(q)), Some(QTY_TEMPERATURE));
    }

    #[test]
    fn electrical_quantities_carry_their_canonical_units() {
        assert_eq!(quantity_unit(QTY_RESISTANCE), "Ω");
        assert_eq!(quantity_unit(QTY_CAPACITANCE), "F");
        assert_eq!(quantity_unit(QTY_APPARENT_POWER), "VA");
        assert_eq!(quantity_unit(QTY_POWER_LEVEL), "dBm");
    }

    #[test]
    fn every_vocabulary_slug_round_trips() {
        for role in ROLE_MEASUREMENT..=ROLE_DIAGNOSTIC {
            assert_eq!(
                role_from_slug(role_slug(role)),
                Some(role),
                "role {role:#04x}"
            );
        }
        for q in QTY_RAW..=QTY_POWER_LEVEL {
            assert_eq!(
                quantity_from_slug(quantity_slug(q)),
                Some(q),
                "quantity {q:#04x}"
            );
        }
        for aspect in ASPECT_DEFAULT..=ASPECT_AC {
            assert_eq!(
                aspect_from_slug(aspect_slug(aspect)),
                Some(aspect),
                "aspect {aspect:#04x}"
            );
        }
        for target in SIGNAL_TARGET_INTERFACE..=SIGNAL_TARGET_DEVICE {
            assert_eq!(
                signal_target_from_slug(signal_target_slug(target)),
                Some(target)
            );
        }
    }

    #[test]
    fn vocabulary_names_never_fall_through_to_unknown() {
        for role in ROLE_MEASUREMENT..=ROLE_DIAGNOSTIC {
            assert_ne!(role_name(role), "Unknown");
        }
        for q in QTY_RAW..=QTY_POWER_LEVEL {
            assert_ne!(quantity_name(q), "Unknown");
        }
        for aspect in ASPECT_DEFAULT..=ASPECT_AC {
            assert_ne!(aspect_name(aspect), "Unknown");
        }
        for kind in PERIPH_KIND_SENSOR..=PERIPH_KIND_LINK {
            assert_ne!(peripheral_kind_name(kind), "Unknown");
        }
        for id in META_BOARD_NAME..=META_MAX_FILE_CHUNK {
            if id == META_RETIRED_RESPONDERS {
                continue;
            }
            assert_ne!(meta_name(id), "Unknown");
        }
    }
}
