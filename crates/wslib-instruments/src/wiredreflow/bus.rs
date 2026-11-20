use std::{error::Error, sync::Arc, time::Duration};

#[cfg(test)]
pub(crate) use wslib_can_bus::PortDirectory;
use wslib_can_bus::{BusKind, OpenError};
pub use wslib_can_bus::{CanBus, SerialPort};
pub(crate) use wslib_can_bus::{DEVICE_SEPARATOR, PATH_SEPARATOR, SLCAN_PREFIX, port_forms};

use super::frame::RawFrame;
pub(crate) use super::task::open_bus;
use crate::{probe::StartError, uri::BUS_FORMS};

pub(crate) fn out_of_reach(bus: &CanBus) -> String {
    OpenError::Unreachable(bus.clone()).explain(BUS_FORMS)
}

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

pub(crate) fn refused(bus: &CanBus) -> StartError {
    match feature(bus.kind()) {
        (feature, false) => StartError::FeatureDisabled(feature),
        (_, true) => StartError::Unreachable(bus.clone()),
    }
}

pub(crate) type Cause = Arc<dyn Error + Send + Sync>;

#[derive(Debug)]
#[allow(dead_code, reason = "only a CAN backend's bus raises it")]
pub(crate) enum BusError {
    Lost(Cause),
    Ended(Option<Cause>),
}

pub(crate) trait Bus: Send {
    fn read(&mut self, timeout: Duration) -> Result<Option<RawFrame>, BusError>;
}

#[cfg(test)]
mod tests;
