//! Modbus: the wire facts, a TOML register map decoded and encoded, poll
//! schedules on the caller's clock, a register sweep's plan, Modbus RTU framed
//! off a byte stream and stamped off a serial line, and with `tcp` a client and
//! a poller over it.

mod bank;
mod item_schedule;
mod manifest;
pub mod protocol;
mod ranges;
mod rtu_stream;
mod rtu_tap;
mod scan;
mod schedule;
mod validate;

#[cfg(feature = "tcp")]
mod error;
#[cfg(feature = "tcp")]
mod poller;
#[cfg(feature = "tcp")]
mod request;
#[cfg(feature = "task")]
mod task;
#[cfg(feature = "tcp")]
mod tcp;
#[cfg(feature = "testing")]
pub mod testing;
#[cfg(feature = "write")]
mod write;
#[cfg(all(feature = "task", feature = "write"))]
mod writer;

pub use bank::{RegisterType, UnknownRegisterType, WriteBank};
pub use item_schedule::{ItemSchedule, PollItem};
pub use manifest::*;
pub use protocol::*;
pub use ranges::{RangeError, RangeSpec, RegisterRange, chunk_ranges};
pub use rtu_stream::{
    CrcPolicy, Direction, DirectionBasis, LengthRule, ModbusRtuMessage, ModbusRtuOptions,
    ModbusRtuStream, Payload, Selector, VendorLen, VendorLength, is_modelled_function,
};
pub use rtu_tap::{RtuTap, TappedMessage};
pub use scan::{
    AddressBlock, DEFAULT_BUSY_RETRIES, ReadOutcome, ReadSpan, RegisterSweep, SweepEnd,
    SweepLimits, SweepProgress, SweepStep,
};
pub use schedule::{FrameBackoff, PollSchedule};
pub use validate::{Finding, validate};
pub use wslib_bits::{DisplayHint, Endianness, SignalFormat};

#[cfg(feature = "tcp")]
pub use error::RequestError;
#[cfg(feature = "tcp")]
pub use poller::{Banks, ItemId, PollEvent, Poller, Step, StepEnd, UnitSource};
#[cfg(feature = "tcp")]
pub use request::{DeviceIdCode, DeviceIdentification, ReadData, ReadRequest, Reading};
#[cfg(feature = "task")]
pub use task::{PollTask, TaskEvent, TaskOptions, spawn};
#[cfg(feature = "tcp")]
pub use tcp::{ModbusTcp, TcpOptions};
#[cfg(feature = "write")]
pub use write::{Readback, ReadbackKind, WriteOutcome, WriteReport};
#[cfg(all(feature = "task", feature = "write"))]
pub use writer::{PollWriter, WriteRefused};
#[cfg(feature = "tcp")]
pub use wslib_tcp::{ResolveError, TransportError, tcp_endpoint};

/// With `tcp` and without `write`, `ModbusTcp` has no write path: none of these
/// builds.
///
/// ```compile_fail
/// let _ = wslib_modbus::ModbusTcp::write_registers;
/// ```
/// ```compile_fail
/// let _ = wslib_modbus::ModbusTcp::write_coils;
/// ```
/// ```compile_fail
/// let _ = wslib_modbus::ModbusTcp::write_verified;
/// ```
/// ```compile_fail
/// use wslib_modbus::WriteReport;
/// ```
#[cfg(all(doctest, feature = "tcp", not(feature = "write")))]
pub struct NoWritePath;

/// With `task` and without `write`, `PollTask` has no writer: none of these
/// builds.
///
/// ```compile_fail
/// let _ = wslib_modbus::PollTask::<()>::writer;
/// ```
/// ```compile_fail
/// use wslib_modbus::PollWriter;
/// ```
#[cfg(all(doctest, feature = "task", not(feature = "write")))]
pub struct NoTaskWritePath;
