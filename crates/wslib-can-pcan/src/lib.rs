//! PEAK-System's USB CAN adapters: the classic PCAN-USB's codec and the CAN FD
//! family's, and with `transport` a CAN task on either over nusb, or on
//! Windows through PEAK's own driver.

pub mod pcan_usb;
pub mod pcan_usb_fd;
#[cfg(all(
    feature = "transport",
    any(test, target_os = "macos", target_os = "windows")
))]
mod transport;
#[cfg(all(
    feature = "transport",
    any(test, target_os = "macos", target_os = "windows")
))]
mod usb;

#[cfg(all(
    feature = "transport",
    any(test, target_os = "macos", target_os = "windows")
))]
pub use transport::{PcanDevice, PcanModel, PcanOptions};
#[cfg(all(feature = "transport", any(target_os = "macos", target_os = "windows")))]
pub use transport::{devices, open, probe};
