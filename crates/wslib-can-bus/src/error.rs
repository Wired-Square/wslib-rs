use std::{error::Error, fmt, io};

use crate::bus::{BUS_FORMS, CanBus, name_the_bus};

/// Why a bus didn't open.
#[derive(Debug)]
#[non_exhaustive]
pub enum OpenError {
    /// This build leaves out the bus's [`feature`](crate::BusKind::feature).
    FeatureOff(CanBus),
    /// This platform doesn't reach the bus's adapter this way. On Linux gs_usb
    /// and PEAK adapters are SocketCAN interfaces, and SocketCAN is only on
    /// Linux.
    Unreachable(CanBus),
    /// The bus's adapter sets the bus's rate, and no bitrate was given.
    NoBitrate(CanBus),
    /// CAN FD was asked of an adapter that sets the bus's rates, and no data
    /// rate was given.
    NoDataBitrate(CanBus),
    /// CAN FD was asked of a GVRET device, which has none.
    NoFd(CanBus),
    /// Finding the adapter, or opening it, failed.
    Open { bus: CanBus, source: io::Error },
}

impl OpenError {
    /// `Unsupported` for a bus this build doesn't open and for CAN FD on GVRET,
    /// `InvalidInput` for a missing rate, otherwise the failure's own kind.
    pub fn kind(&self) -> io::ErrorKind {
        match self {
            OpenError::FeatureOff(_) | OpenError::Unreachable(_) | OpenError::NoFd(_) => {
                io::ErrorKind::Unsupported
            }
            OpenError::NoBitrate(_) | OpenError::NoDataBitrate(_) => io::ErrorKind::InvalidInput,
            OpenError::Open { source, .. } => source.kind(),
        }
    }

    /// The message, with `forms` as the buses a build opens. `Display` uses
    /// [`BUS_FORMS`].
    pub fn explain(&self, forms: &[&str]) -> String {
        match self {
            OpenError::FeatureOff(bus) => format!(
                "{bus}: this build leaves it out; enable wslib-can-bus' `{}` feature",
                bus.kind().feature()
            ),
            OpenError::Unreachable(bus @ (CanBus::GsUsb { .. } | CanBus::Pcan { .. })) => format!(
                "{bus}: on Linux a gs_usb or PEAK adapter is a SocketCAN interface; name that interface, \
                 e.g. can0"
            ),
            OpenError::Unreachable(bus) => format!(
                "{bus}: SocketCAN needs Linux; {}",
                name_the_bus("the adapter", forms)
            ),
            OpenError::NoBitrate(bus) => {
                format!("{bus}: this adapter sets the bus's rate; give the bus's bitrate")
            }
            OpenError::NoDataBitrate(bus) => {
                format!("{bus}: this adapter sets the bus's rates; give CAN FD's data bitrate")
            }
            OpenError::NoFd(bus) => format!("{bus}: a GVRET device has no CAN FD"),
            OpenError::Open { bus, source } => format!("{bus}: {source}"),
        }
    }
}

impl fmt::Display for OpenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.explain(BUS_FORMS))
    }
}

impl Error for OpenError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            OpenError::Open { source, .. } => Some(source),
            OpenError::FeatureOff(_)
            | OpenError::Unreachable(_)
            | OpenError::NoBitrate(_)
            | OpenError::NoDataBitrate(_)
            | OpenError::NoFd(_) => None,
        }
    }
}

/// Why this build doesn't open `bus`, or `None` if it does.
pub fn refusal(bus: &CanBus) -> Option<OpenError> {
    let kind = bus.kind();
    (!(kind.built() && kind.reachable())).then(|| refused(bus))
}

pub(crate) fn refused(bus: &CanBus) -> OpenError {
    if bus.kind().built() {
        OpenError::Unreachable(bus.clone())
    } else {
        OpenError::FeatureOff(bus.clone())
    }
}

#[cfg(test)]
mod tests;
