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
    use std::io;

    use super::bus::{Bus, CanBus, refusal};

    pub(crate) fn open_bus(bus: &CanBus) -> io::Result<Box<dyn Bus>> {
        Err(refusal(bus))
    }
}
