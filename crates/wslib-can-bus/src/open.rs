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
            let slcan = slcan_options(port, rates(bus, config)?);
            named(bus, wslib_can_slcan::open(slcan, options).await)
        }
        #[cfg(all(feature = "socketcan", target_os = "linux"))]
        CanBus::SocketCan { interface } => {
            let socketcan = socketcan_options(interface, config.mode);
            named(bus, wslib_can_socketcan::open(socketcan, options).await)
        }
        #[cfg(all(feature = "gsusb", any(target_os = "macos", target_os = "windows")))]
        CanBus::GsUsb { serial } => {
            let rates = rates(bus, config)?;
            let device = crate::usb::only_adapter(
                bus,
                wslib_can_gsusb::devices(),
                serial.as_deref(),
                |device| device.serial.as_deref(),
            )?;
            named(
                bus,
                wslib_can_gsusb::open(gsusb_options(device, rates), options).await,
            )
        }
        #[cfg(all(feature = "pcan", any(target_os = "macos", target_os = "windows")))]
        CanBus::Pcan { serial } => {
            let rates = rates(bus, config)?;
            let device = crate::usb::only_adapter(
                bus,
                wslib_can_pcan::devices(),
                serial.as_deref(),
                |device| device.serial.as_deref(),
            )?;
            named(
                bus,
                wslib_can_pcan::open(pcan_options(device, rates), options).await,
            )
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
fn rates(bus: &CanBus, config: BusConfig) -> Result<Rates, OpenError> {
    let bitrate = config
        .bitrate
        .ok_or_else(|| OpenError::NoBitrate(bus.clone()))?;
    match config.mode {
        CanMode::Fd { data_bitrate: None } => Err(OpenError::NoDataBitrate(bus.clone())),
        mode => Ok(Rates {
            bitrate,
            data_bitrate: mode.data_bitrate(),
        }),
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Rates {
    bitrate: u32,
    data_bitrate: Option<u32>,
}

#[cfg(feature = "slcan")]
const SLCAN_LINE: wslib_serial::LineSettings = wslib_serial::LineSettings {
    baud: 115_200,
    data_bits: 8,
    parity: wslib_serial::Parity::None,
    stop_bits: 1,
};

#[cfg(feature = "slcan")]
fn slcan_options(port: &crate::bus::SerialPort, rates: Rates) -> wslib_can_slcan::SlcanOptions {
    wslib_can_slcan::SlcanOptions {
        path: port.path(),
        line: SLCAN_LINE,
        bitrate: rates.bitrate,
        data_bitrate: rates.data_bitrate,
    }
}

#[cfg(all(feature = "socketcan", target_os = "linux"))]
fn socketcan_options(interface: &str, mode: CanMode) -> wslib_can_socketcan::SocketCanOptions {
    wslib_can_socketcan::SocketCanOptions {
        interface: interface.to_owned(),
        fd: mode.is_fd(),
    }
}

#[cfg(all(feature = "gsusb", any(target_os = "macos", target_os = "windows")))]
fn gsusb_options(
    device: wslib_can_gsusb::GsUsbDevice,
    rates: Rates,
) -> wslib_can_gsusb::GsUsbOptions {
    let mut gsusb = wslib_can_gsusb::GsUsbOptions::new(device, rates.bitrate);
    gsusb.data = rates.data_bitrate.map(|rate| (rate, None));
    gsusb
}

#[cfg(all(feature = "pcan", any(target_os = "macos", target_os = "windows")))]
fn pcan_options(device: wslib_can_pcan::PcanDevice, rates: Rates) -> wslib_can_pcan::PcanOptions {
    let mut pcan = wslib_can_pcan::PcanOptions::new(device, rates.bitrate);
    pcan.data = rates.data_bitrate.map(|rate| (rate, None));
    pcan
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
