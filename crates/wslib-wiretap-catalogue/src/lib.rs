//! WireTAP-format device catalogues (TOML) across CAN, Serial and Modbus: the
//! parser, validator, decoder and editor, and the DBC bridge.
//!
//! It takes bytes and returns values: no I/O, no transport, no polling loop. A
//! consumer drives the device, owns the clock, and brings the bytes back here.
//! The Modbus register map, poll schedules and RTU framing are
//! [`wslib_modbus`]'s; this crate reads a catalogue's Modbus section through
//! them.
//!
//! - [`parse`]: `Catalogue::parse` resolves all three frame sections into the
//!   unified [`model`] (`Catalogue`/`Frame`/`Signal`/`Mux`).
//! - [`validate`]: field-path and message findings for the editor.
//! - [`decode`]: raw bytes to signal values.
//! - [`mirror`]: does a mirrored frame still agree with its source, over the
//!   bytes it inherited?
//! - [`rtu`]: a catalogue's function codes and tunnels as RTU stream options.
//! - [`rtu_decode`]: a recovered RTU message as signals.
//! - [`framing_detect`]: which framing a raw serial byte stream uses (SLIP,
//!   Modbus RTU or a delimiter), and what RTU couldn't frame.
//! - [`serial_framing`]: a serial byte stream cut into frames by SLIP, a
//!   delimiter or Modbus RTU, behind one `SerialFramer`, and where a frame's id
//!   sits in it.
//! - [`summary`]: a catalogue's counts and resolved per-frame rows, across
//!   protocols, for a consumer's report.
//! - [`dbc`]: Vector DBC to and from catalogue TOML.
//! - [`text`]: a catalogue's source as text: the editor's line diff,
//!   `[meta].name` from a file that may not parse, and the filename rules.

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
    CanConfig, Catalogue, ChecksumConfig, Confidence, DisplayHint, EffectiveDefaults, Endianness,
    Frame, FrameTunnel, FunctionCode, HeaderField, Meta, ModbusConfig, Mux, MuxCase,
    NAME_KEYED_FRAME_ID, Protocol, RegisterType, SerialConfig, Signal, SignalFormat,
    TunnelProtocol, UnknownRegisterType, ValidationError, WriteBank,
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
