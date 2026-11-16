use std::io;

use wslib_can::{CanError, CanOptions, CanTask};

use crate::{
    bus::CanBus,
    error::{OpenError, refusal, refused},
};

/// Opens a wslib-can task on `bus`.
///
/// An SLCAN, gs_usb or PEAK adapter runs at `bitrate`, and fails with
/// [`OpenError::NoBitrate`] without one. A SocketCAN interface or a GVRET
/// device keeps its own bitrate and ignores `bitrate`. A gs_usb or PEAK bus
/// without a serial takes the one adapter attached. A bus this build doesn't
/// open fails at once with its [`refusal`](crate::refusal).
#[cfg_attr(
    not(any(
        feature = "slcan",
        all(
            any(feature = "gsusb", feature = "pcan"),
            any(target_os = "macos", target_os = "windows")
        )
    )),
    allow(
        unused_variables,
        reason = "only SLCAN, gs_usb and PEAK adapters take a bitrate"
    )
)]
pub async fn open(
    bus: &CanBus,
    bitrate: Option<u32>,
    options: CanOptions,
) -> Result<CanTask, OpenError> {
    if let Some(why) = refusal(bus) {
        return Err(why);
    }
    match bus {
        #[cfg(feature = "slcan")]
        CanBus::Slcan { port } => {
            use wslib_serial::{LineSettings, Parity};
            let bitrate = bitrate_for(bus, bitrate)?;
            const LINE: LineSettings = LineSettings {
                baud: 115_200,
                data_bits: 8,
                parity: Parity::None,
                stop_bits: 1,
            };
            let slcan = wslib_can_slcan::SlcanOptions {
                path: port.path(),
                line: LINE,
                bitrate,
                data_bitrate: None,
            };
            named(bus, wslib_can_slcan::open(slcan, options).await)
        }
        #[cfg(all(feature = "socketcan", target_os = "linux"))]
        CanBus::SocketCan { interface } => {
            let socketcan = wslib_can_socketcan::SocketCanOptions {
                interface: interface.clone(),
                fd: false,
            };
            named(bus, wslib_can_socketcan::open(socketcan, options).await)
        }
        #[cfg(all(feature = "gsusb", any(target_os = "macos", target_os = "windows")))]
        CanBus::GsUsb { serial } => {
            let bitrate = bitrate_for(bus, bitrate)?;
            let device = crate::usb::only_adapter(
                bus,
                wslib_can_gsusb::devices(),
                serial.as_deref(),
                |device| device.serial.as_deref(),
            )?;
            named(
                bus,
                wslib_can_gsusb::open(wslib_can_gsusb::GsUsbOptions::new(device, bitrate), options)
                    .await,
            )
        }
        #[cfg(all(feature = "pcan", any(target_os = "macos", target_os = "windows")))]
        CanBus::Pcan { serial } => {
            let bitrate = bitrate_for(bus, bitrate)?;
            let device = crate::usb::only_adapter(
                bus,
                wslib_can_pcan::devices(),
                serial.as_deref(),
                |device| device.serial.as_deref(),
            )?;
            named(
                bus,
                wslib_can_pcan::open(wslib_can_pcan::PcanOptions::new(device, bitrate), options)
                    .await,
            )
        }
        #[cfg(feature = "gvret")]
        CanBus::Gvret { host, port } => {
            const CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
            let link = wslib_can_gvret::Link::Tcp {
                endpoint: wslib_can_gvret::tcp_endpoint(host, *port),
                connect_timeout: CONNECT_TIMEOUT,
            };
            named(
                bus,
                wslib_can_gvret::open(link, wslib_can_gvret::GvretOptions::default(), options)
                    .await,
            )
        }
        _ => Err(refused(bus)),
    }
}

#[cfg_attr(
    not(any(
        feature = "slcan",
        all(
            any(feature = "gsusb", feature = "pcan"),
            any(target_os = "macos", target_os = "windows")
        )
    )),
    allow(
        dead_code,
        reason = "only SLCAN, gs_usb and PEAK adapters take a bitrate"
    )
)]
fn bitrate_for(bus: &CanBus, bitrate: Option<u32>) -> Result<u32, OpenError> {
    bitrate.ok_or_else(|| OpenError::NoBitrate(bus.clone()))
}

#[cfg_attr(
    not(any(
        feature = "slcan",
        all(feature = "socketcan", target_os = "linux"),
        all(
            any(feature = "gsusb", feature = "pcan"),
            any(target_os = "macos", target_os = "windows")
        ),
        feature = "gvret"
    )),
    allow(dead_code, reason = "only an adapter this platform reaches opens")
)]
fn named(bus: &CanBus, opened: Result<CanTask, CanError>) -> Result<CanTask, OpenError> {
    opened.map_err(|e| OpenError::Open {
        bus: bus.clone(),
        source: io::Error::other(e),
    })
}

#[cfg(test)]
mod tests;
