use std::fmt;
use std::str::FromStr;

pub const USB_SERIAL_PREFIX: &str = "usb:";
pub const USB_PATH_PREFIX: &str = "usb-path:";

const MAC_HEX_DIGITS: usize = 12;

fn normalise_mac(mac: &str) -> Option<String> {
    let digits: String = mac
        .chars()
        .filter(|c| !matches!(c, ':' | '-'))
        .map(|c| c.to_ascii_lowercase())
        .collect();
    let valid = digits.len() == MAC_HEX_DIGITS && digits.chars().all(|c| c.is_ascii_hexdigit());
    valid.then_some(digits)
}

pub fn mac_matches(expected: &str, actual: &str) -> bool {
    match (normalise_mac(expected), normalise_mac(actual)) {
        (Some(expected), Some(actual)) => expected == actual,
        _ => false,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(try_from = "String", into = "String"))]
pub enum PortIdentity {
    UsbSerial(String),
    UsbPath(String),
    Tty(String),
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct IdentityParseError(pub String);

impl FromStr for PortIdentity {
    type Err = IdentityParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (value, build): (&str, fn(String) -> Self) =
            if let Some(serial) = s.strip_prefix(USB_SERIAL_PREFIX) {
                (serial, Self::UsbSerial)
            } else if let Some(path) = s.strip_prefix(USB_PATH_PREFIX) {
                (path, Self::UsbPath)
            } else {
                (s, Self::Tty)
            };
        if value.is_empty() {
            return Err(IdentityParseError(format!(
                "port identity {s:?} names no port"
            )));
        }
        Ok(build(value.to_string()))
    }
}

impl fmt::Display for PortIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UsbSerial(serial) => write!(f, "{USB_SERIAL_PREFIX}{serial}"),
            Self::UsbPath(path) => write!(f, "{USB_PATH_PREFIX}{path}"),
            Self::Tty(path) => f.write_str(path),
        }
    }
}

impl TryFrom<String> for PortIdentity {
    type Error = IdentityParseError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        s.parse()
    }
}

impl From<PortIdentity> for String {
    fn from(id: PortIdentity) -> Self {
        id.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BY_PATH: &str = "platform-xhci-hcd.0-usb-0:1.4:1.0-port0";

    fn parse(s: &str) -> Result<PortIdentity, IdentityParseError> {
        s.parse()
    }

    fn by_path_identity() -> String {
        format!("{USB_PATH_PREFIX}{BY_PATH}")
    }

    #[test]
    fn prefixes_select_the_kind() {
        let serial = PortIdentity::UsbSerial("58:8C".into());
        let path = PortIdentity::UsbPath(BY_PATH.into());
        let tty = PortIdentity::Tty("/dev/ttyUSB1".into());
        assert_eq!(parse("usb:58:8C"), Ok(serial));
        assert_eq!(parse(&by_path_identity()), Ok(path));
        assert_eq!(parse("/dev/ttyUSB1"), Ok(tty));
    }

    #[test]
    fn an_identity_naming_nothing_is_refused() {
        for s in ["", "usb:", "usb-path:"] {
            let expected = format!("port identity {s:?} names no port");
            assert_eq!(parse(s).unwrap_err().to_string(), expected);
        }
    }

    #[test]
    fn parsing_neither_trims_nor_folds_case() {
        assert_eq!(parse(" usb:X"), Ok(PortIdentity::Tty(" usb:X".into())));
        assert_eq!(parse("USB:X"), Ok(PortIdentity::Tty("USB:X".into())));
    }

    #[test]
    fn display_is_the_inverse_of_parse() {
        let by_path = by_path_identity();
        for s in ["usb:58:8C", &by_path, "/dev/ttyUSB1", "COM3"] {
            assert_eq!(parse(s).unwrap().to_string(), s);
        }
    }

    #[test]
    fn macs_match_across_separators_and_case() {
        const MAC: &str = "68:09:47:1d:2f:0c";
        assert!(mac_matches("68:09:47:1D:2F:0C", MAC));
        assert!(mac_matches("680947-1d2f0c", MAC));
        assert!(!mac_matches("68:09:47:1d:2f:0d", MAC));
        assert!(!mac_matches("abc", MAC));
        assert!(!mac_matches("68:09:47:1d:2f:0g", "68:09:47:1d:2f:0g"));
        assert!(!mac_matches(MAC, "(unknown)"));
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serde_uses_the_string_form() {
        #[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug)]
        struct Wrap {
            id: PortIdentity,
        }
        let wrap = Wrap {
            id: PortIdentity::UsbPath(BY_PATH.into()),
        };
        let mut bytes = Vec::new();
        ciborium::into_writer(&wrap, &mut bytes).unwrap();
        let back: Wrap = ciborium::from_reader(bytes.as_slice()).unwrap();
        assert_eq!(back, wrap);

        #[derive(serde::Serialize)]
        struct Raw {
            id: String,
        }
        let mut bad = Vec::new();
        ciborium::into_writer(&Raw { id: "usb:".into() }, &mut bad).unwrap();
        assert!(ciborium::from_reader::<Wrap, _>(bad.as_slice()).is_err());
    }
}
