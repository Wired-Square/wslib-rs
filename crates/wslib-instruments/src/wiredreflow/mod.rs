pub use wslib_framelink_protocol::can_id::{DEVICE_ID_DIGITS, device_id_text};

pub mod bus;
pub mod frame;
pub mod link;
#[cfg(any(
    feature = "can-slcan",
    all(feature = "can-socketcan", target_os = "linux"),
    all(
        any(feature = "can-gsusb", feature = "can-pcan"),
        any(target_os = "macos", target_os = "windows")
    ),
    feature = "can-gvret"
))]
mod task;

#[cfg(not(any(
    feature = "can-slcan",
    all(feature = "can-socketcan", target_os = "linux"),
    all(
        any(feature = "can-gsusb", feature = "can-pcan"),
        any(target_os = "macos", target_os = "windows")
    ),
    feature = "can-gvret"
)))]
mod task {
    use super::bus::{Bus, CanBus, refused};
    use crate::probe::StartError;

    pub(crate) fn open_bus(bus: &CanBus) -> Result<Box<dyn Bus>, StartError> {
        Err(refused(bus))
    }
}
