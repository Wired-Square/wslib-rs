use std::{io, time::Duration};

#[cfg(test)]
pub(crate) use wslib_can_bus::PortDirectory;
use wslib_can_bus::{BusKind, OpenError};
pub use wslib_can_bus::{CanBus, SerialPort};
pub(crate) use wslib_can_bus::{DEVICE_SEPARATOR, PATH_SEPARATOR, SLCAN_PREFIX, port_forms};

use super::frame::RawFrame;
pub(crate) use super::task::open_bus;
use crate::{probe::ProbeError, uri::BUS_FORMS};

pub(crate) const fn feature(kind: BusKind) -> (&'static str, bool) {
    match kind {
        BusKind::SocketCan => ("can-socketcan", cfg!(feature = "can-socketcan")),
        BusKind::Slcan => ("can-slcan", cfg!(feature = "can-slcan")),
        BusKind::GsUsb => ("can-gsusb", cfg!(feature = "can-gsusb")),
        BusKind::Pcan => ("can-pcan", cfg!(feature = "can-pcan")),
        BusKind::Gvret => ("can-gvret", cfg!(feature = "can-gvret")),
    }
}

pub(crate) fn name_the_bus(what: &str) -> String {
    wslib_can_bus::name_the_bus(what, BUS_FORMS)
}

pub(crate) fn refused(bus: &CanBus) -> io::Error {
    match feature(bus.kind()) {
        (feature, false) => io::Error::new(
            io::ErrorKind::Unsupported,
            ProbeError::FeatureDisabled(feature),
        ),
        (_, true) => failed(OpenError::Unreachable(bus.clone())),
    }
}

pub(crate) fn failed(error: OpenError) -> io::Error {
    io::Error::new(error.kind(), error.explain(BUS_FORMS))
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code, reason = "only a CAN backend's bus raises it")]
pub(crate) enum BusError {
    Lost(String),
    Ended(String),
}

pub(crate) trait Bus: Send {
    fn read(&mut self, timeout: Duration) -> Result<Option<RawFrame>, BusError>;
}

#[cfg(test)]
mod tests;
