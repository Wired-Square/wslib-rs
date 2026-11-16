use std::io;

use wslib_can::{CanError, CanOptions, CanTask};

use crate::{
    bus::CanBus,
    config::{BusConfig, CanMode},
    error::{OpenError, refusal, refused},
};

/// Opens a wslib-can task on `bus`.
///
/// An SLCAN, gs_usb or PEAK adapter runs at `config`'s rates. It fails with
/// [`OpenError::NoBitrate`] without a nominal rate, and in CAN FD with
/// [`OpenError::NoDataBitrate`] without a data rate. A SocketCAN interface
/// keeps its own rates and opens for CAN FD when `config` asks. A GVRET device
/// keeps its own rate and fails CAN FD with [`OpenError::NoFd`].
///
/// An adapter that can't run CAN FD refuses it as [`OpenError::Open`]: a
/// classic PCAN-USB, a PEAK adapter held by PEAK's Windows driver, a gs_usb
/// device without FD or that reports no clock, and SLCAN without the Elmue
/// firmware. A gs_usb or PEAK bus without a serial takes the one adapter
/// attached. A bus this build doesn't open fails at once with its
/// [`refusal`](crate::refusal).
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
    allow(
        unused_variables,
        reason = "only an adapter this platform reaches reads the config"
    )
)]
pub async fn open(
    bus: &CanBus,
    config: BusConfig,
    options: CanOptions,
) -> Result<CanTask, OpenError> {
    if let Some(why) = refusal(bus) {
        return Err(why);
    }
    match bus {
        #[cfg(feature = "slcan")]
        CanBus::Slcan { port } => {
            use wslib_serial::{LineSettings, Parity};
            let (bitrate, data_bitrate) = rates(bus, config)?;
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
                data_bitrate,
            };
            named(bus, wslib_can_slcan::open(slcan, options).await)
        }
        #[cfg(all(feature = "socketcan", target_os = "linux"))]
        CanBus::SocketCan { interface } => {
            let socketcan = wslib_can_socketcan::SocketCanOptions {
                interface: interface.clone(),
                fd: config.mode.is_fd(),
            };
            named(bus, wslib_can_socketcan::open(socketcan, options).await)
        }
        #[cfg(all(feature = "gsusb", any(target_os = "macos", target_os = "windows")))]
        CanBus::GsUsb { serial } => {
            let (bitrate, data_bitrate) = rates(bus, config)?;
            let device = crate::usb::only_adapter(
                bus,
                wslib_can_gsusb::devices(),
                serial.as_deref(),
                |device| device.serial.as_deref(),
            )?;
            let mut gsusb = wslib_can_gsusb::GsUsbOptions::new(device, bitrate);
            gsusb.data = data_bitrate.map(|rate| (rate, None));
            named(bus, wslib_can_gsusb::open(gsusb, options).await)
        }
        #[cfg(all(feature = "pcan", any(target_os = "macos", target_os = "windows")))]
        CanBus::Pcan { serial } => {
            let (bitrate, data_bitrate) = rates(bus, config)?;
            let device = crate::usb::only_adapter(
                bus,
                wslib_can_pcan::devices(),
                serial.as_deref(),
                |device| device.serial.as_deref(),
            )?;
            let mut pcan = wslib_can_pcan::PcanOptions::new(device, bitrate);
            pcan.data = data_bitrate.map(|rate| (rate, None));
            named(bus, wslib_can_pcan::open(pcan, options).await)
        }
        #[cfg(feature = "gvret")]
        CanBus::Gvret { host, port } => {
            if config.mode.is_fd() {
                return Err(OpenError::NoFd(bus.clone()));
            }
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
fn rates(bus: &CanBus, config: BusConfig) -> Result<(u32, Option<u32>), OpenError> {
    let bitrate = config
        .bitrate
        .ok_or_else(|| OpenError::NoBitrate(bus.clone()))?;
    match config.mode {
        CanMode::Fd { data_bitrate: None } => Err(OpenError::NoDataBitrate(bus.clone())),
        mode => Ok((bitrate, mode.data_bitrate())),
    }
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
