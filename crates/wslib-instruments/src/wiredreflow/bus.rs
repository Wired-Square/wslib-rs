use std::{fmt, io, net::Ipv6Addr, str::FromStr, time::Duration};

use super::frame::RawFrame;
pub(crate) use super::task::open_bus;
use crate::{probe::ProbeError, uri::without_controls};

pub(crate) const SLCAN_PREFIX: &str = "slcan=";
pub(crate) const GVRET_PREFIX: &str = "gvret=";
pub(crate) const GVRET_PORT: u16 = 23;
pub(crate) const PATH_SEPARATOR: char = '/';
pub(crate) const DEVICE_SEPARATOR: char = '@';
const GSUSB: &str = "gsusb";
const PCAN: &str = "pcan";
const SERIAL_SEPARATOR: char = '=';
const PORT_SEPARATOR: char = ':';
#[cfg(not(windows))]
const DEVICES_PATH: &str = "/dev/";
// serialport opens a bare name on Windows, under `\\.\`.
#[cfg(windows)]
const DEVICES_PATH: &str = "";
const BY_ID_PATH: &str = "/dev/serial/by-id/";
const BY_ID_TAG: &str = "by-id:";
#[cfg(target_os = "linux")]
const EXAMPLE_PORT: &str = "ttyACM0";
#[cfg(windows)]
const EXAMPLE_PORT: &str = "COM3";
#[cfg(not(any(target_os = "linux", windows)))]
const EXAMPLE_PORT: &str = "cu.usbmodem2101";
const NAME_PLACEHOLDER: &str = "<name>";
const FORM_SEPARATOR: &str = ", or ";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PortDirectory {
    Devices,
    ById,
}

const DIRECTORIES: [PortDirectory; 2] = [PortDirectory::ById, PortDirectory::Devices];

impl PortDirectory {
    pub(crate) fn path(self) -> &'static str {
        match self {
            PortDirectory::Devices => DEVICES_PATH,
            PortDirectory::ById => BY_ID_PATH,
        }
    }

    fn tag(self) -> Option<&'static str> {
        match self {
            PortDirectory::Devices => None,
            PortDirectory::ById => Some(BY_ID_TAG),
        }
    }
}

/// A serial port named as a `slcan=` bus names it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SerialPort {
    pub(crate) directory: PortDirectory,
    pub(crate) name: String,
}

impl SerialPort {
    /// The path the port opens at.
    pub fn path(&self) -> String {
        format!("{}{}", self.directory.path(), self.name)
    }

    pub(crate) fn at(path: &str) -> Option<SerialPort> {
        DIRECTORIES.into_iter().find_map(|directory| {
            path.strip_prefix(directory.path())
                .filter(|name| {
                    !name.is_empty() && !name.contains([PATH_SEPARATOR, DEVICE_SEPARATOR])
                })
                .map(|name| SerialPort {
                    directory,
                    name: name.to_owned(),
                })
                .filter(|port| port.to_string().parse::<SerialPort>().as_ref() == Ok(port))
        })
    }
}

/// The serial-port forms that name a port on this platform; `/dev/serial/by-id`
/// is Linux's.
pub(crate) fn port_forms() -> String {
    let forms: Vec<String> = DIRECTORIES
        .into_iter()
        .filter(|directory| *directory != PortDirectory::ById || cfg!(target_os = "linux"))
        .map(|directory| {
            let tag = directory.tag().unwrap_or_default();
            match directory.path() {
                "" => format!("{SLCAN_PREFIX}{tag}{NAME_PLACEHOLDER}"),
                path => {
                    format!("{SLCAN_PREFIX}{tag}{NAME_PLACEHOLDER} for {path}{NAME_PLACEHOLDER}")
                }
            }
        })
        .collect();
    forms.join(FORM_SEPARATOR)
}

/// The bus forms that name an adapter on this platform.
fn bus_hints() -> String {
    let mut hints = Vec::new();
    if cfg!(target_os = "linux") {
        hints.push("a SocketCAN interface such as can0".to_owned());
    }
    hints.push(port_forms());
    if cfg!(any(target_os = "macos", target_os = "windows")) {
        hints.push(usb_forms());
    }
    hints.push(gvret_form());
    hints.join(FORM_SEPARATOR)
}

pub(crate) fn example_bus() -> String {
    if cfg!(target_os = "linux") {
        "can0".into()
    } else {
        format!("{SLCAN_PREFIX}{EXAMPLE_PORT}")
    }
}

fn usb_forms() -> String {
    format!("{GSUSB}[{SERIAL_SEPARATOR}<serial>] or {PCAN}[{SERIAL_SEPARATOR}<serial>]")
}

fn gvret_form() -> String {
    format!("{GVRET_PREFIX}<host>[{PORT_SEPARATOR}<port>]")
}

fn usb_serial(s: &str, kind: &str) -> Option<Result<Option<String>, String>> {
    let rest = s.strip_prefix(kind)?;
    let serial = match rest.strip_prefix(SERIAL_SEPARATOR) {
        None if rest.is_empty() => Ok(None),
        None => return None,
        Some("") => Err(format!(
            "{s}: name the adapter's serial after '{SERIAL_SEPARATOR}', or write {kind} alone"
        )),
        Some(serial) if serial.contains([PATH_SEPARATOR, DEVICE_SEPARATOR]) => Err(format!(
            "{s}: a serial can't contain '{PATH_SEPARATOR}' or '{DEVICE_SEPARATOR}'"
        )),
        Some(serial) => Ok(Some(serial.to_owned())),
    };
    Some(serial)
}

fn write_usb(f: &mut fmt::Formatter<'_>, kind: &str, serial: Option<&str>) -> fmt::Result {
    f.write_str(kind)?;
    serial.map_or(Ok(()), |serial| write!(f, "{SERIAL_SEPARATOR}{serial}"))
}

fn gvret_endpoint(s: &str, endpoint: &str) -> Result<(String, u16), String> {
    let refused = || {
        format!(
            "{s}: name the GVRET device as {}, e.g. {GVRET_PREFIX}192.168.4.1",
            gvret_form()
        )
    };
    if endpoint.is_empty() || endpoint.contains([PATH_SEPARATOR, DEVICE_SEPARATOR]) {
        return Err(refused());
    }
    if let Some(bracketed) = endpoint.strip_prefix('[') {
        let (address, port) = bracketed.split_once(']').ok_or_else(refused)?;
        let port = match port.strip_prefix(PORT_SEPARATOR) {
            None if port.is_empty() => GVRET_PORT,
            Some(port) => port.parse().map_err(|_| refused())?,
            None => return Err(refused()),
        };
        return address
            .parse::<Ipv6Addr>()
            .map(|_| (address.to_owned(), port))
            .map_err(|_| refused());
    }
    if endpoint.parse::<Ipv6Addr>().is_ok() {
        return Ok((endpoint.to_owned(), GVRET_PORT));
    }
    match endpoint.split_once(PORT_SEPARATOR) {
        None => Ok((endpoint.to_owned(), GVRET_PORT)),
        Some((host, port)) if !host.is_empty() => {
            Ok((host.to_owned(), port.parse().map_err(|_| refused())?))
        }
        Some(_) => Err(refused()),
    }
}

fn port_path_refusal(path: &str) -> String {
    match SerialPort::at(path) {
        Some(port) => {
            format!(
                "write {SLCAN_PREFIX}{port}, the port's name under {}",
                port.directory.path()
            )
        }
        None => format!("name the serial port as {}", port_forms()),
    }
}

impl FromStr for SerialPort {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (directory, name) = DIRECTORIES
            .into_iter()
            .find_map(|directory| {
                directory
                    .tag()
                    .and_then(|tag| s.strip_prefix(tag))
                    .map(|name| (directory, name))
            })
            .unwrap_or((PortDirectory::Devices, s));
        if name.contains(PATH_SEPARATOR) {
            return Err(port_path_refusal(name));
        }
        if name.contains(DEVICE_SEPARATOR) {
            return Err(format!(
                "{name}: a port name can't contain '{DEVICE_SEPARATOR}', which starts the device id; \
                 name the port by a udev alias without one"
            ));
        }
        if name.is_empty() {
            return Err(format!(
                "name the serial port as {}, e.g. {SLCAN_PREFIX}{EXAMPLE_PORT}",
                port_forms()
            ));
        }
        Ok(SerialPort {
            directory,
            name: name.to_owned(),
        })
    }
}

impl fmt::Display for SerialPort {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}{}",
            self.directory.tag().unwrap_or_default(),
            self.name
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CanBus {
    SocketCan {
        interface: String,
    },
    Slcan {
        port: SerialPort,
    },
    GsUsb {
        serial: Option<String>,
    },
    Pcan {
        serial: Option<String>,
    },
    /// A GVRET device over TCP; `host` is a name or an IP address, unbracketed.
    Gvret {
        host: String,
        port: u16,
    },
}

impl CanBus {
    fn backend(&self) -> (&'static str, bool) {
        match self {
            CanBus::SocketCan { .. } => ("can-socketcan", cfg!(feature = "can-socketcan")),
            CanBus::Slcan { .. } => ("can-slcan", cfg!(feature = "can-slcan")),
            CanBus::GsUsb { .. } => ("can-gsusb", cfg!(feature = "can-gsusb")),
            CanBus::Pcan { .. } => ("can-pcan", cfg!(feature = "can-pcan")),
            CanBus::Gvret { .. } => ("can-gvret", cfg!(feature = "can-gvret")),
        }
    }
}

/// Why a bus this build can't open isn't opened: its feature is off, or its
/// adapter isn't reachable this way on this platform.
pub(crate) fn refusal(bus: &CanBus) -> io::Error {
    if let (feature, false) = bus.backend() {
        return io::Error::new(
            io::ErrorKind::Unsupported,
            ProbeError::FeatureDisabled(feature),
        );
    }
    let why = match bus {
        CanBus::GsUsb { .. } | CanBus::Pcan { .. } => format!(
            "{bus}: gs_usb and PEAK adapters open over USB on macOS and Windows; on Linux, their kernel \
             driver makes each a SocketCAN interface, so name that, e.g. can0"
        ),
        _ => format!(
            "{bus}: SocketCAN needs Linux; here, name the adapter as {}",
            bus_hints()
        ),
    };
    io::Error::new(io::ErrorKind::Unsupported, why)
}

impl FromStr for CanBus {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = without_controls(s)?;
        if let Some(serial) = usb_serial(s, GSUSB) {
            return serial.map(|serial| CanBus::GsUsb { serial });
        }
        if let Some(serial) = usb_serial(s, PCAN) {
            return serial.map(|serial| CanBus::Pcan { serial });
        }
        if let Some(endpoint) = s.strip_prefix(GVRET_PREFIX) {
            return gvret_endpoint(s, endpoint).map(|(host, port)| CanBus::Gvret { host, port });
        }
        match s.strip_prefix(SLCAN_PREFIX) {
            Some(port) => port
                .parse()
                .map(|port| CanBus::Slcan { port })
                .map_err(|why| format!("{s}: {why}")),
            None if s.is_empty() => Err(format!("name the CAN bus as {}", bus_hints())),
            None => Ok(CanBus::SocketCan {
                interface: s.to_owned(),
            }),
        }
    }
}

impl fmt::Display for CanBus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CanBus::SocketCan { interface } => f.write_str(interface),
            CanBus::Slcan { port } => write!(f, "{SLCAN_PREFIX}{port}"),
            CanBus::GsUsb { serial } => write_usb(f, GSUSB, serial.as_deref()),
            CanBus::Pcan { serial } => write_usb(f, PCAN, serial.as_deref()),
            CanBus::Gvret { host, port } if host.parse::<Ipv6Addr>().is_ok() => {
                write!(f, "{GVRET_PREFIX}[{host}]{PORT_SEPARATOR}{port}")
            }
            CanBus::Gvret { host, port } => write!(f, "{GVRET_PREFIX}{host}{PORT_SEPARATOR}{port}"),
        }
    }
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
