//! GVRET, both ends: the codec, and with `transport` a CAN task on a GVRET
//! device over TCP or, with `serial`, a serial port.

mod codec;
#[cfg(feature = "serial")]
mod serial;
#[cfg(feature = "transport")]
mod transport;

pub use codec::*;
#[cfg(feature = "transport")]
pub use transport::{GvretOptions, Link, open, probe};
#[cfg(feature = "transport")]
pub use wslib_tcp::{TransportError, tcp_endpoint};
