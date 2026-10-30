use std::{convert::Infallible, error::Error, fmt, io, str::FromStr};

#[cfg(not(feature = "ble"))]
use crate::probe::ProbeError;
use crate::{
    gw121::{
        METER_NAME, Target,
        decode::{self, STATUS, TABLE},
    },
    probe::Probe,
    sample::Sample,
    selected::Selected,
    signal::{self, SignalKey},
    wiredreflow::{
        self,
        bus::{
            CanBus, DEVICE_SEPARATOR, PATH_SEPARATOR, SLCAN_PREFIX, SerialPort, example_bus,
            port_forms,
        },
        frame::{DEVICE_ID_MAX, device_text},
        link::WiredReflowProbe,
    },
};

/// The probe forms this build opens.
pub const URI_FORMS: &[&str] = &[
    #[cfg(feature = "ble")]
    "121gw",
    #[cfg(feature = "ble")]
    "121gw:<address-or-name>[/<signal>…]",
    #[cfg(any(
        feature = "can-slcan",
        all(feature = "can-socketcan", target_os = "linux"),
        all(
            any(feature = "can-gsusb", feature = "can-pcan"),
            any(target_os = "macos", target_os = "windows")
        ),
        feature = "can-gvret"
    ))]
    "wiredreflow:<bus>[@<device-id>][/<signal>…]",
];

/// The `<bus>` forms this build opens.
pub const BUS_FORMS: &[&str] = &[
    #[cfg(all(feature = "can-socketcan", target_os = "linux"))]
    "a SocketCAN interface such as can0",
    #[cfg(feature = "can-slcan")]
    "slcan=<name>",
    #[cfg(all(feature = "can-slcan", target_os = "linux"))]
    "slcan=by-id:<name>",
    #[cfg(all(feature = "can-gsusb", any(target_os = "macos", target_os = "windows")))]
    "gsusb[=<serial>]",
    #[cfg(all(feature = "can-pcan", any(target_os = "macos", target_os = "windows")))]
    "pcan[=<serial>]",
    #[cfg(feature = "can-gvret")]
    "gvret=<host>[:<port>]",
];

const GW121: &str = "121gw";
const WIREDREFLOW: &str = "wiredreflow";
const HEX_PREFIX: &str = "0x";
const HEX: u32 = 16;
const SCHEME_SEPARATOR: char = ':';
const SELECTOR_SEPARATOR: char = '/';
const STATUS_OK: &str = "ok";
const LIST_SEPARATOR: &str = ", ";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProbeUri {
    Gw121 {
        target: Target,
        selected: Vec<SignalKey>,
    },
    WiredReflow {
        bus: CanBus,
        device: Option<u32>,
        selected: Vec<SignalKey>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProbeUriError {
    Unrecognised(String),
    Target(String),
    Signal(String),
}

impl fmt::Display for ProbeUriError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProbeUriError::Unrecognised(text) => {
                write!(f, "unrecognised probe {text:?}; {}", expected())
            }
            ProbeUriError::Target(why) | ProbeUriError::Signal(why) => f.write_str(why),
        }
    }
}

impl Error for ProbeUriError {}

fn expected() -> String {
    if URI_FORMS.is_empty() {
        return "this build opens no probe; enable `ble` or a `can-*` feature".into();
    }
    let mut forms = format!("expected {}", URI_FORMS.join(LIST_SEPARATOR));
    if !BUS_FORMS.is_empty() {
        forms.push_str(&format!(" (bus: {})", BUS_FORMS.join(LIST_SEPARATOR)));
    }
    forms
}

struct Scheme {
    signals: fn() -> Vec<SignalKey>,
    key_named: fn(&str) -> Option<SignalKey>,
    display_name: fn(&SignalKey) -> Option<&'static str>,
}

fn gw121_signals() -> Vec<SignalKey> {
    decode::signals(&TABLE)
}

const GW121_SCHEME: Scheme = Scheme {
    signals: gw121_signals,
    key_named: decode::key_named,
    display_name: decode::display_name,
};

const WIREDREFLOW_SCHEME: Scheme = Scheme {
    signals: wiredreflow::frame::signals,
    key_named: wiredreflow::frame::key_named,
    display_name: wiredreflow::frame::display_name,
};

fn selector(scheme: &Scheme, probe: &str, text: &str) -> Result<SignalKey, ProbeUriError> {
    if text.is_empty() {
        return Err(ProbeUriError::Signal(format!(
            "{probe}: empty signal after '{SELECTOR_SEPARATOR}'"
        )));
    }
    let key = match (scheme.key_named)(text) {
        Some(key) => key,
        None => signal::parse(text).map_err(|why| {
            let names: Vec<&str> = (scheme.signals)()
                .iter()
                .filter_map(|key| (scheme.display_name)(key))
                .collect();
            ProbeUriError::Signal(format!(
                "{text} is not one of {} and not a signal key: {why}",
                names.join(LIST_SEPARATOR)
            ))
        })?,
    };
    if !(scheme.signals)().contains(&key) {
        return Err(ProbeUriError::Signal(format!(
            "{probe} can't produce {}",
            signal::slug(&key)
        )));
    }
    Ok(key)
}

fn selectors<'a>(
    scheme: &Scheme,
    probe: &str,
    parts: impl Iterator<Item = &'a str>,
) -> Result<Vec<SignalKey>, ProbeUriError> {
    let mut keys = Vec::new();
    for text in parts {
        let key = selector(scheme, probe, text)?;
        if !keys.contains(&key) {
            keys.push(key);
        }
    }
    Ok(keys)
}

fn target(text: &str) -> Target {
    text.parse()
        .unwrap_or_else(|never: Infallible| match never {})
}

fn device_id(text: &str) -> Result<u32, ProbeUriError> {
    let digits = text
        .split_at_checked(HEX_PREFIX.len())
        .filter(|(prefix, _)| prefix.eq_ignore_ascii_case(HEX_PREFIX))
        .map_or(text, |(_, digits)| digits);
    u32::from_str_radix(digits, HEX)
        .ok()
        .filter(|id| digits.chars().all(|digit| digit.is_ascii_hexdigit()) && *id <= DEVICE_ID_MAX)
        .ok_or_else(|| {
            ProbeUriError::Target(format!(
                "{text:?} is not a WiredReflow device id (hex, up to {DEVICE_ID_MAX:X}); \
                 the device id is everything after the first '{DEVICE_SEPARATOR}'"
            ))
        })
}

fn corrected_slcan(parts: &[&str]) -> Option<String> {
    (1..=parts.len()).rev().find_map(|at| {
        let (path, signals) = parts.split_at_checked(at)?;
        let written: String = path
            .iter()
            .map(|part| format!("{PATH_SEPARATOR}{part}"))
            .collect();
        let (path_text, device) = match written.split_once(DEVICE_SEPARATOR) {
            Some((path_text, id)) => (path_text, Some(device_id(id).ok()?)),
            None => (written.as_str(), None),
        };
        let port = SerialPort::at(path_text)?;
        if !signals
            .iter()
            .all(|text| selector(&WIREDREFLOW_SCHEME, WIREDREFLOW, text).is_ok())
        {
            return None;
        }
        let mut uri = format!("{WIREDREFLOW}{SCHEME_SEPARATOR}{SLCAN_PREFIX}{port}");
        if let Some(id) = device {
            uri.push(DEVICE_SEPARATOR);
            uri.push_str(&device_text(id));
        }
        for text in signals {
            uri.push(SELECTOR_SEPARATOR);
            uri.push_str(text);
        }
        Some(uri)
    })
}

fn slcan_path_refusal(s: &str, parts: &[&str]) -> ProbeUriError {
    let why = match corrected_slcan(parts) {
        Some(uri) => format!("write {uri}"),
        None => format!("name the serial port as {}", port_forms()),
    };
    ProbeUriError::Target(format!("{s}: {why}"))
}

impl FromStr for ProbeUri {
    type Err = ProbeUriError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s == GW121 {
            return Ok(ProbeUri::Gw121 {
                target: Target::Name(METER_NAME.to_owned()),
                selected: vec![],
            });
        }
        if let Some(rest) = s
            .strip_prefix(GW121)
            .and_then(|rest| rest.strip_prefix(SCHEME_SEPARATOR))
        {
            let mut parts = rest.split(SELECTOR_SEPARATOR);
            let target_text = parts.next().unwrap_or_default();
            if target_text.is_empty() {
                return Err(ProbeUriError::Target(format!(
                    "{GW121}{SCHEME_SEPARATOR}<address-or-name> needs an address or name after the colon"
                )));
            }
            let target = target(target_text);
            let probe = format!("{GW121}{SCHEME_SEPARATOR}{target}");
            return Ok(ProbeUri::Gw121 {
                selected: selectors(&GW121_SCHEME, &probe, parts)?,
                target,
            });
        }
        if s == WIREDREFLOW {
            return Err(ProbeUriError::Target(format!(
                "{WIREDREFLOW} needs a bus after a colon, e.g. {WIREDREFLOW}{SCHEME_SEPARATOR}{}",
                example_bus()
            )));
        }
        if let Some(rest) = s
            .strip_prefix(WIREDREFLOW)
            .and_then(|rest| rest.strip_prefix(SCHEME_SEPARATOR))
        {
            let mut parts = rest.split(SELECTOR_SEPARATOR).peekable();
            let target = parts.next().unwrap_or_default();
            if target == SLCAN_PREFIX && parts.peek().is_some() {
                let path: Vec<&str> = parts.collect();
                return Err(slcan_path_refusal(s, &path));
            }
            let (bus_text, device) = match target.split_once(DEVICE_SEPARATOR) {
                Some((bus, id)) => (bus, Some(device_id(id)?)),
                None => (target, None),
            };
            let bus: CanBus = bus_text.parse().map_err(ProbeUriError::Target)?;
            let probe = format!("{WIREDREFLOW}{SCHEME_SEPARATOR}{target}");
            return Ok(ProbeUri::WiredReflow {
                bus,
                device,
                selected: selectors(&WIREDREFLOW_SCHEME, &probe, parts)?,
            });
        }
        Err(ProbeUriError::Unrecognised(s.to_owned()))
    }
}

impl fmt::Display for ProbeUri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProbeUri::Gw121 { target, .. } => write!(f, "{GW121}{SCHEME_SEPARATOR}{target}")?,
            ProbeUri::WiredReflow { bus, device, .. } => {
                write!(f, "{WIREDREFLOW}{SCHEME_SEPARATOR}{bus}")?;
                if let Some(id) = device {
                    write!(f, "{DEVICE_SEPARATOR}{}", device_text(*id))?;
                }
            }
        }
        for key in self.selected() {
            write!(f, "{SELECTOR_SEPARATOR}{}", signal::slug(key))?;
        }
        Ok(())
    }
}

impl ProbeUri {
    pub fn selected(&self) -> &[SignalKey] {
        match self {
            ProbeUri::Gw121 { selected, .. } | ProbeUri::WiredReflow { selected, .. } => selected,
        }
    }
}

/// Serialises as its text, which parses back to it.
#[cfg(feature = "serde")]
impl serde::Serialize for ProbeUri {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for ProbeUri {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = <std::borrow::Cow<'de, str>>::deserialize(deserializer)?;
        text.parse().map_err(serde::de::Error::custom)
    }
}

pub fn narrowed(probe: Box<dyn Probe>, keys: &[SignalKey]) -> Box<dyn Probe> {
    if keys.is_empty() {
        probe
    } else {
        Box::new(Selected::new(probe, keys.to_vec()))
    }
}

/// A backend this build leaves out fails with `ErrorKind::Unsupported` around
/// [`ProbeError::FeatureDisabled`](crate::probe::ProbeError::FeatureDisabled).
pub fn open(uri: &ProbeUri) -> io::Result<Box<dyn Probe>> {
    let probe: Box<dyn Probe> = match uri {
        #[cfg(feature = "ble")]
        ProbeUri::Gw121 { target, .. } => {
            Box::new(crate::gw121::ble::Gw121Probe::start(target.clone())?)
        }
        #[cfg(not(feature = "ble"))]
        ProbeUri::Gw121 { .. } => {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                ProbeError::FeatureDisabled("ble"),
            ));
        }
        ProbeUri::WiredReflow { bus, device, .. } => {
            Box::new(WiredReflowProbe::start(bus, *device)?)
        }
    };
    Ok(narrowed(probe, uri.selected()))
}

fn status_text(bits: i64) -> String {
    let flags = decode::status_flags(bits);
    if flags.is_empty() {
        STATUS_OK.into()
    } else {
        flags.join(LIST_SEPARATOR)
    }
}

pub fn value_text(uri: &ProbeUri, sample: &Sample) -> String {
    match uri {
        ProbeUri::Gw121 { .. } if sample.key == STATUS => status_text(sample.value.mantissa),
        ProbeUri::Gw121 { .. } | ProbeUri::WiredReflow { .. } => sample.value.to_string(),
    }
}
