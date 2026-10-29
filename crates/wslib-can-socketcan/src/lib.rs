//! SocketCAN's frame layouts, and with `transport` on Linux a CAN task over a
//! raw socket.

mod codec;
#[cfg(all(feature = "transport", target_os = "linux"))]
mod transport;

pub use codec::*;
#[cfg(all(feature = "transport", target_os = "linux"))]
pub use transport::{Bitrates, SocketCanOptions, bitrates, open};
