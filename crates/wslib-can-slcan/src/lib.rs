//! SLCAN, the ASCII serial line CAN protocol: the codec, and with `transport` a
//! CAN task on an SLCAN adapter over a serial port.

mod codec;
#[cfg(all(feature = "transport", not(target_os = "ios")))]
mod serial;
#[cfg(all(feature = "transport", not(target_os = "ios")))]
mod transport;

pub use codec::*;
#[cfg(all(feature = "transport", not(target_os = "ios")))]
pub use transport::{SlcanOptions, check_rates, open, probe};
