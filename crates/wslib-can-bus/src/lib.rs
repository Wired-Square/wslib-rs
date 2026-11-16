//! A CAN adapter's address, [`CanBus`], such as `can0`, `slcan=<name>`,
//! `gsusb[=<serial>]`, `pcan[=<serial>]` or `gvret=<host>[:<port>]`. With
//! `task`, `open` opens a wslib-can task on it through each adapter feature
//! that is on.

#![cfg_attr(
    not(test),
    forbid(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::unreachable
    )
)]

mod bus;
mod error;
#[cfg(feature = "task")]
mod open;
#[cfg(any(
    test,
    all(
        any(feature = "gsusb", feature = "pcan"),
        any(target_os = "macos", target_os = "windows")
    )
))]
mod usb;

pub use bus::{
    BUS_FORMS, BusKind, BusParseError, CanBus, DEVICE_SEPARATOR, GVRET_PORT, GVRET_PREFIX,
    PATH_SEPARATOR, PortDirectory, SLCAN_PREFIX, SerialPort, form_count, forms_of, name_the_bus,
    port_forms,
};
pub use error::{OpenError, refusal};
#[cfg(feature = "task")]
pub use open::open;
