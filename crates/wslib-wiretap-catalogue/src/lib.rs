//! WireTAP-format device catalogues (TOML) across CAN, Serial and Modbus: the
//! parser, validator, decoder and editor, and the DBC bridge.
//!
//! It takes bytes and returns values: no I/O, no transport, no polling loop. A
//! consumer drives the device, owns the clock, and brings the bytes back here.
//! The Modbus register map, poll schedules and RTU framing are
//! [`wslib_modbus`]'s; this crate reads a catalogue's Modbus section through
//! them.

mod byte_name;
pub mod dbc;
pub mod decode;
pub mod edit;
pub mod framing_detect;
pub mod layout;
pub mod migrate;
pub mod mirror;
pub mod model;
pub mod mux_case;
pub mod parse;
pub mod rtu;
pub mod rtu_decode;
pub mod serial_framing;
pub mod summary;
pub mod text;
pub mod validate;

pub use byte_name::{byte_name, parse_byte_name};
pub use layout::{FrameLayout, LayoutRange, RangeKind, frame_layout};
pub use mirror::{MirrorTracker, MirrorVerdict};
pub use model::{
    CanConfig, Catalogue, Confidence, DisplayHint, EffectiveDefaults, Endianness, Frame,
    FrameTunnel, FunctionCode, HeaderField, Meta, ModbusConfig, Mux, MuxCase, NAME_KEYED_FRAME_ID,
    Protocol, RegisterType, SerialConfig, Signal, SignalFormat, TunnelProtocol,
    UnknownRegisterType, ValidationError, WriteBank,
};
pub use mux_case::{CaseRange, compare_mux_case_keys, is_mux_case_key, mux_case_values};
pub use parse::{CatalogueError, RtuRules, RtuRulesError, rtu_rules};
pub use rtu::RtuSettings;
pub use rtu_decode::{RtuDecode, decode_rtu_message, exception_label, function_label};
pub use serial_framing::{
    DegenerateFraming, DelimiterOptions, FrameIdConfig, FramingEncoding, FramingMode, SerialFrame,
    SerialFramer, UnknownFramingMode, degenerate_framing_field,
};
pub use summary::CatalogueSummary;
pub use text::{DiffKind, DiffRow, UnsafeFilename};
