//! gs_usb, the candleLight protocol: the codec, and with `transport` a CAN task
//! on a gs_usb adapter over nusb on macOS and Windows, or on Linux the
//! SocketCAN interface each of its channels became.

mod codec;
#[cfg(all(
    feature = "transport",
    any(test, target_os = "macos", target_os = "windows", target_os = "linux")
))]
mod transport;
#[cfg(all(
    feature = "transport",
    any(test, target_os = "macos", target_os = "windows", target_os = "linux")
))]
mod usb;

pub use codec::*;
#[cfg(all(
    feature = "transport",
    any(test, target_os = "macos", target_os = "windows", target_os = "linux")
))]
pub use transport::{GsUsbDevice, GsUsbOptions};
#[cfg(all(feature = "transport", target_os = "linux"))]
pub use transport::{LinuxGsUsbDevice, devices};
#[cfg(all(feature = "transport", any(target_os = "macos", target_os = "windows")))]
pub use transport::{devices, open, probe};
