use std::fmt;
use std::str::FromStr;

pub const USB_SERIAL_PREFIX: &str = "usb:";
pub const USB_PATH_PREFIX: &str = "usb-path:";

const MAC_OCTETS: usize = 6;
const HEX_DIGITS_PER_OCTET: usize = 2;
const HEX_RADIX: u32 = 16;
const MAC_SEPARATOR: &str = ":";
const UNREPORTED_MAC: &str = "(unknown)";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(try_from = "String", into = "String"))]
pub struct Mac([u8; MAC_OCTETS]);

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0:?} is not a MAC of six hex octets")]
pub struct MacParseError(pub String);

impl FromStr for Mac {
    type Err = MacParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let nibbles: Vec<u32> = s
            .chars()
            .filter(|c| !matches!(c, ':' | '-'))
            .map(|c| c.to_digit(HEX_RADIX))
            .collect::<Option<_>>()
            .filter(|n: &Vec<u32>| n.len() == MAC_OCTETS * HEX_DIGITS_PER_OCTET)
            .ok_or_else(|| MacParseError(s.to_string()))?;
        let mut octets = [0; MAC_OCTETS];
        let (pairs, _) = nibbles.as_chunks::<HEX_DIGITS_PER_OCTET>();
        for (octet, [high, low]) in octets.iter_mut().zip(pairs) {
            *octet = (high * HEX_RADIX + low) as u8;
        }
        Ok(Self(octets))
    }
}

impl fmt::Display for Mac {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, octet) in self.0.iter().enumerate() {
            if i > 0 {
                f.write_str(MAC_SEPARATOR)?;
            }
            write!(f, "{octet:02x}")?;
        }
        Ok(())
    }
}

pub(crate) fn reported_mac(mac: Option<&Mac>) -> String {
    mac.map_or_else(|| UNREPORTED_MAC.to_string(), Mac::to_string)
}

impl TryFrom<String> for Mac {
    type Error = MacParseError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        s.parse()
    }
}

impl From<Mac> for String {
    fn from(mac: Mac) -> Self {
        mac.to_string()
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

impl PortIdentity {
    /// The first of `usb_serial`, `usb_path` and `tty` that is present and
    /// non-empty, taken as that kind of identity without parsing it.
    pub fn from_parts(
        usb_serial: Option<&str>,
        usb_path: Option<&str>,
        tty: Option<&str>,
    ) -> Option<Self> {
        let named = |part: Option<&str>| part.filter(|p| !p.is_empty()).map(str::to_string);
        named(usb_serial)
            .map(Self::UsbSerial)
            .or_else(|| named(usb_path).map(Self::UsbPath))
            .or_else(|| named(tty).map(Self::Tty))
    }
}

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

    const MAC: &str = "68:09:47:1d:2f:0c";

    fn mac(s: &str) -> Result<Mac, MacParseError> {
        s.parse()
    }

    #[test]
    fn a_mac_parses_across_separators_and_case() {
        let expected = mac(MAC);
        assert!(expected.is_ok());
        for s in ["68:09:47:1D:2F:0C", "680947-1d2f0c", "6809471d2f0c"] {
            assert_eq!(mac(s), expected);
        }
        assert_ne!(mac("68:09:47:1d:2f:0d"), expected);
    }

    #[test]
    fn a_mac_that_is_not_six_hex_octets_is_refused() {
        for s in [
            "",
            "abc",
            "68:09:47:1d:2f:0g",
            "68:09:47:1d:2f",
            "68:09:47:1d:2f:0c:00",
            "+8:09:47:1d:2f:0c",
            "68:09:47:1d:2f:0c ",
            "(unknown)",
        ] {
            assert_eq!(mac(s), Err(MacParseError(s.into())));
        }
    }

    #[test]
    fn a_mac_displays_lower_case_with_colons() {
        assert_eq!(mac("680947-1D2F0C").unwrap().to_string(), MAC);
    }

    #[test]
    fn from_parts_takes_the_first_part_that_names_a_port() {
        let from = PortIdentity::from_parts;
        let serial = PortIdentity::UsbSerial("S".into());
        let path = PortIdentity::UsbPath("P".into());
        let tty = PortIdentity::Tty("T".into());
        assert_eq!(from(Some("S"), Some("P"), Some("T")), Some(serial));
        assert_eq!(from(None, Some("P"), Some("T")), Some(path));
        assert_eq!(from(Some(""), Some(""), Some("T")), Some(tty));
        assert_eq!(from(Some(""), None, Some("")), None);
        assert_eq!(from(None, None, None), None);
    }

    #[test]
    fn from_parts_does_not_parse_a_part() {
        let tty = PortIdentity::from_parts(None, None, Some("usb:X"));
        assert_eq!(tty, Some(PortIdentity::Tty("usb:X".into())));
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

        #[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug)]
        struct WrapMac {
            mac: Mac,
        }
        let wrap = WrapMac {
            mac: mac(MAC).unwrap(),
        };
        let mut bytes = Vec::new();
        ciborium::into_writer(&wrap, &mut bytes).unwrap();
        let back: WrapMac = ciborium::from_reader(bytes.as_slice()).unwrap();
        assert_eq!(back, wrap);

        #[derive(serde::Serialize)]
        struct RawMac {
            mac: String,
        }
        let mut bad = Vec::new();
        ciborium::into_writer(&RawMac { mac: "abc".into() }, &mut bad).unwrap();
        assert!(ciborium::from_reader::<WrapMac, _>(bad.as_slice()).is_err());
    }
}
