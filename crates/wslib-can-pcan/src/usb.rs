//! Helpers for the nusb host.

#![cfg_attr(
    not(any(target_os = "macos", target_os = "windows")),
    allow(
        dead_code,
        reason = "only the tests and the Linux listing build it here"
    )
)]

use std::{error::Error, fmt, io};

use wslib_can::CanError;

/// A request the device didn't take: its going away is `Closed`, anything else
/// names the request.
pub(crate) fn refused(request: &'static str) -> impl Fn(io::Error) -> CanError {
    move |e| match e.kind() {
        io::ErrorKind::ConnectionAborted => CanError::Closed,
        _ => CanError::Request { request, source: e },
    }
}

/// Read as a number, so a bus already stored still matches.
#[cfg(any(target_os = "macos", target_os = "windows"))]
pub(crate) fn bus(found: &nusb::DeviceInfo) -> u8 {
    found.bus_id().parse().unwrap_or(0)
}

/// The service Windows has bound to the device; elsewhere `None`.
#[cfg(any(target_os = "macos", target_os = "windows"))]
pub(crate) fn bound_driver(found: &nusb::DeviceInfo) -> Option<&str> {
    #[cfg(target_os = "windows")]
    return found.driver();
    #[cfg(not(target_os = "windows"))]
    {
        let _ = found;
        None
    }
}

/// nusb's refusal of a device bound to a driver other than WinUSB, which names
/// neither the driver nor what would work.
pub(crate) fn foreign_driver(
    error: io::Error,
    driver: Option<&str>,
    remedy: &'static str,
) -> io::Error {
    match driver {
        Some(driver) if error.kind() == io::ErrorKind::Unsupported => io::Error::new(
            io::ErrorKind::Unsupported,
            ForeignDriver {
                driver: driver.to_owned(),
                remedy,
                source: error,
            },
        ),
        _ => error,
    }
}

#[derive(Debug)]
struct ForeignDriver {
    driver: String,
    remedy: &'static str,
    source: io::Error,
}

impl fmt::Display for ForeignDriver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self { driver, remedy, .. } = self;
        write!(
            f,
            "the adapter is bound to the {driver} driver, not WinUSB: {remedy}"
        )
    }
}

impl Error for ForeignDriver {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.source)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_refusal_names_the_bound_driver_and_the_remedy_and_nothing_else_changes() {
        let unsupported = || io::Error::new(io::ErrorKind::Unsupported, "incompatible driver");
        let named = foreign_driver(unsupported(), Some("libusbK"), "bind WinUSB to it");
        assert_eq!(named.kind(), io::ErrorKind::Unsupported);
        assert_eq!(
            named.to_string(),
            "the adapter is bound to the libusbK driver, not WinUSB: bind WinUSB to it"
        );
        let refused = named
            .source()
            .and_then(|cause| cause.downcast_ref::<io::Error>())
            .unwrap();
        assert_eq!(
            (refused.kind(), refused.to_string()),
            (
                io::ErrorKind::Unsupported,
                "incompatible driver".to_string()
            )
        );
        let unbound = foreign_driver(unsupported(), None, "bind WinUSB to it");
        assert_eq!(unbound.to_string(), "incompatible driver");
        let other = foreign_driver(io::ErrorKind::NotFound.into(), Some("WinUSB"), "");
        assert_eq!(other.kind(), io::ErrorKind::NotFound);
    }
}
