//! A serial line: its settings and wire time, the SLIP and delimiter framers,
//! and with `task` a port read by a task that reopens it.

mod framing;
mod line;
#[cfg(feature = "ports")]
mod listing;
pub mod slip;
#[cfg(feature = "task")]
mod task;

pub use framing::{DelimiterFramer, DelimiterOptions, Framed};
pub use line::{InvalidLineSettings, LineSettings, LineSettingsError, Parity, UnknownParity};
#[cfg(feature = "ports")]
pub use listing::{PortInfo, PortKind, UsbPort, ports};
pub use slip::SlipDecoder;
#[cfg(feature = "task")]
pub use task::{Access, SerialError, SerialEvent, SerialOptions, SerialTask, open};
#[cfg(feature = "write")]
pub use task::{SerialPort, SerialWriter, WriteRefused};
