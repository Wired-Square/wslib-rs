use std::{error::Error, fmt, net::Ipv6Addr, str::FromStr};

/// A kind of CAN adapter, as a bus names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BusKind {
    SocketCan,
    Slcan,
    GsUsb,
    Pcan,
    Gvret,
}

const SOCKETCAN_FORMS: &[&str] = &["a SocketCAN interface such as can0"];
const SLCAN_FORMS: &[&str] = &[
    "slcan=<name>",
    #[cfg(target_os = "linux")]
    "slcan=by-id:<name>",
];
const GSUSB_FORMS: &[&str] = &["gsusb[=<serial>]"];
const PCAN_FORMS: &[&str] = &["pcan[=<serial>]"];
const GVRET_FORMS: &[&str] = &["gvret=<host>[:<port>]"];

impl BusKind {
    /// Every kind, in the order their forms are listed.
    pub const ALL: [BusKind; 5] = [
        BusKind::SocketCan,
        BusKind::Slcan,
        BusKind::GsUsb,
        BusKind::Pcan,
        BusKind::Gvret,
    ];

    /// The forms that name a bus of this kind; `slcan=by-id:<name>` is Linux's.
    pub const fn forms(self) -> &'static [&'static str] {
        match self {
            BusKind::SocketCan => SOCKETCAN_FORMS,
            BusKind::Slcan => SLCAN_FORMS,
            BusKind::GsUsb => GSUSB_FORMS,
            BusKind::Pcan => PCAN_FORMS,
            BusKind::Gvret => GVRET_FORMS,
        }
    }

    /// The feature that opens this kind.
    pub const fn feature(self) -> &'static str {
        self.backend().0
    }

    /// Whether this platform reaches this kind's adapter: SocketCAN only on
    /// Linux, gs_usb and PEAK only on macOS and Windows.
    pub const fn reachable(self) -> bool {
        match self {
            BusKind::SocketCan => cfg!(target_os = "linux"),
            BusKind::GsUsb | BusKind::Pcan => cfg!(any(target_os = "macos", target_os = "windows")),
            BusKind::Slcan | BusKind::Gvret => true,
        }
    }

    /// Whether this kind's adapter sets the bus's rate, so opening it takes a
    /// bitrate: SLCAN, gs_usb and PEAK do. A SocketCAN interface and a GVRET
    /// device keep their own.
    pub const fn sets_bitrate(self) -> bool {
        match self {
            BusKind::Slcan | BusKind::GsUsb | BusKind::Pcan => true,
            BusKind::SocketCan | BusKind::Gvret => false,
        }
    }

    pub(crate) const fn built(self) -> bool {
        self.backend().1
    }

    const fn backend(self) -> (&'static str, bool) {
        match self {
            BusKind::SocketCan => ("socketcan", cfg!(feature = "socketcan")),
            BusKind::Slcan => ("slcan", cfg!(feature = "slcan")),
            BusKind::GsUsb => ("gsusb", cfg!(feature = "gsusb")),
            BusKind::Pcan => ("pcan", cfg!(feature = "pcan")),
            BusKind::Gvret => ("gvret", cfg!(feature = "gvret")),
        }
    }
}

/// The number of forms [`forms_of`] returns for `kinds`.
pub const fn form_count(kinds: &[BusKind]) -> usize {
    let mut count = 0;
    let mut rest = kinds;
    while let Some((kind, others)) = rest.split_first() {
        if (*kind).reachable() {
            count += (*kind).forms().len();
        }
        rest = others;
    }
    count
}

/// The forms of the `kinds` this platform reaches, in order. `N` must be
/// their [`form_count`].
pub const fn forms_of<const N: usize>(kinds: &[BusKind]) -> [&'static str; N] {
    assert!(N == form_count(kinds), "N is not the kinds' form_count");
    let mut forms = [""; N];
    let mut slots: &mut [&'static str] = &mut forms;
    let mut rest = kinds;
    while let Some((kind, others)) = rest.split_first() {
        if (*kind).reachable() {
            let mut offered = (*kind).forms();
            while let Some((form, more)) = offered.split_first() {
                let unfilled = slots;
                slots = match unfilled.split_first_mut() {
                    Some((slot, free)) => {
                        *slot = *form;
                        free
                    }
                    None => &mut [],
                };
                offered = more;
            }
        }
        rest = others;
    }
    forms
}

const BUILT: &[BusKind] = &[
    #[cfg(feature = "socketcan")]
    BusKind::SocketCan,
    #[cfg(feature = "slcan")]
    BusKind::Slcan,
    #[cfg(feature = "gsusb")]
    BusKind::GsUsb,
    #[cfg(feature = "pcan")]
    BusKind::Pcan,
    #[cfg(feature = "gvret")]
    BusKind::Gvret,
];
const OPENED: [&str; form_count(BUILT)] = forms_of(BUILT);

/// The `<bus>` forms this build opens.
pub const BUS_FORMS: &[&str] = &OPENED;

/// The text before an SLCAN bus's port name.
pub const SLCAN_PREFIX: &str = "slcan=";
/// The text before a GVRET bus's host.
pub const GVRET_PREFIX: &str = "gvret=";
/// A GVRET bus's port when it names none.
pub const GVRET_PORT: u16 = 23;
/// A path's separator, which no port name or serial contains.
pub const PATH_SEPARATOR: char = '/';
/// The character after a bus that starts a device id. No bus contains it.
pub const DEVICE_SEPARATOR: char = '@';
const GSUSB: &str = "gsusb";
const PCAN: &str = "pcan";
const SERIAL_SEPARATOR: char = '=';
const PORT_SEPARATOR: char = ':';
#[cfg(not(windows))]
const DEVICES_PATH: &str = "/dev/";
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
const NO_BUS: &str =
    "this build opens no CAN bus on this platform; build it with an adapter this platform reaches";

/// The directory a serial port's name is under.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum PortDirectory {
    /// `/dev/`, or a bare name on Windows.
    Devices,
    /// `/dev/serial/by-id/`, written `by-id:`.
    ById,
}

const DIRECTORIES: [PortDirectory; 2] = [PortDirectory::ById, PortDirectory::Devices];

impl PortDirectory {
    /// The directory's path, which a port's name follows.
    pub fn path(self) -> &'static str {
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
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SerialPort {
    directory: PortDirectory,
    name: String,
}

impl SerialPort {
    /// The path the port opens at.
    pub fn path(&self) -> String {
        format!("{}{}", self.directory.path(), self.name)
    }

    /// The port a path opens, if its name parses back to it.
    pub fn at(path: &str) -> Option<SerialPort> {
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

/// The forms that name a serial port on this platform.
pub fn port_forms() -> String {
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

/// A message asking for `what` as one of `forms`, or saying the build opens
/// no bus if `forms` is empty.
pub fn name_the_bus(what: &str, forms: &[&str]) -> String {
    if forms.is_empty() {
        return NO_BUS.into();
    }
    format!("name {what} as {}", forms.join(FORM_SEPARATOR))
}

fn without_controls(text: &str) -> Result<&str, String> {
    if text.contains(char::is_control) {
        return Err(format!("{text:?} contains a control character"));
    }
    Ok(text)
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

/// Why text is not a [`SerialPort`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum PortParseError {
    /// A path, not a name; `Some` holds the port the path opens.
    Path(Option<SerialPort>),
    /// A name containing [`DEVICE_SEPARATOR`].
    DeviceSeparator(String),
    Empty,
}

impl fmt::Display for PortParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PortParseError::Path(Some(port)) => write!(
                f,
                "write {SLCAN_PREFIX}{port}, the port's name under {}",
                port.directory.path()
            ),
            PortParseError::Path(None) => write!(f, "name the serial port as {}", port_forms()),
            PortParseError::DeviceSeparator(name) => write!(
                f,
                "{name}: a port name can't contain '{DEVICE_SEPARATOR}', which starts the device id; \
                 name the port by a udev alias without one"
            ),
            PortParseError::Empty => write!(
                f,
                "name the serial port as {}, e.g. {SLCAN_PREFIX}{EXAMPLE_PORT}",
                port_forms()
            ),
        }
    }
}

impl Error for PortParseError {}

impl FromStr for SerialPort {
    type Err = PortParseError;

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
            return Err(PortParseError::Path(SerialPort::at(name)));
        }
        if name.contains(DEVICE_SEPARATOR) {
            return Err(PortParseError::DeviceSeparator(name.to_owned()));
        }
        if name.is_empty() {
            return Err(PortParseError::Empty);
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

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
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
    /// A GVRET device over TCP. `host` is a name or an IP address, without
    /// brackets.
    Gvret {
        host: String,
        port: u16,
    },
}

impl CanBus {
    /// The kind of adapter this bus is on.
    pub fn kind(&self) -> BusKind {
        match self {
            CanBus::SocketCan { .. } => BusKind::SocketCan,
            CanBus::Slcan { .. } => BusKind::Slcan,
            CanBus::GsUsb { .. } => BusKind::GsUsb,
            CanBus::Pcan { .. } => BusKind::Pcan,
            CanBus::Gvret { .. } => BusKind::Gvret,
        }
    }
}

/// Why text is not a [`CanBus`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum BusParseError {
    /// No text. `Display` asks for one of [`BUS_FORMS`]. A caller that opens
    /// other forms can name them with [`name_the_bus`].
    Empty,
    /// Text that names no bus, and why.
    Invalid(String),
    /// An SLCAN bus whose port is no [`SerialPort`].
    Port { bus: String, source: PortParseError },
}

impl fmt::Display for BusParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BusParseError::Empty => f.write_str(&name_the_bus("the CAN bus", BUS_FORMS)),
            BusParseError::Invalid(why) => f.write_str(why),
            BusParseError::Port { bus, .. } => write!(f, "{bus} names no serial port"),
        }
    }
}

impl Error for BusParseError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            BusParseError::Port { source, .. } => Some(source),
            BusParseError::Empty | BusParseError::Invalid(_) => None,
        }
    }
}

impl FromStr for CanBus {
    type Err = BusParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.is_empty() {
            return Err(BusParseError::Empty);
        }
        parse_bus(s)
    }
}

fn parse_bus(s: &str) -> Result<CanBus, BusParseError> {
    let s = without_controls(s).map_err(BusParseError::Invalid)?;
    if let Some(serial) = usb_serial(s, GSUSB) {
        return serial
            .map(|serial| CanBus::GsUsb { serial })
            .map_err(BusParseError::Invalid);
    }
    if let Some(serial) = usb_serial(s, PCAN) {
        return serial
            .map(|serial| CanBus::Pcan { serial })
            .map_err(BusParseError::Invalid);
    }
    if let Some(endpoint) = s.strip_prefix(GVRET_PREFIX) {
        return gvret_endpoint(s, endpoint)
            .map(|(host, port)| CanBus::Gvret { host, port })
            .map_err(BusParseError::Invalid);
    }
    match s.strip_prefix(SLCAN_PREFIX) {
        Some(port) => port
            .parse()
            .map(|port| CanBus::Slcan { port })
            .map_err(|source| BusParseError::Port {
                bus: s.to_owned(),
                source,
            }),
        None if s.contains(PATH_SEPARATOR) => Err(BusParseError::Invalid(format!(
            "{s}: an interface name can't contain '{PATH_SEPARATOR}'"
        ))),
        None if s.contains(DEVICE_SEPARATOR) => Err(BusParseError::Invalid(format!(
            "{s}: an interface name can't contain '{DEVICE_SEPARATOR}', which starts the device id"
        ))),
        None => Ok(CanBus::SocketCan {
            interface: s.to_owned(),
        }),
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

#[cfg(test)]
mod tests;
