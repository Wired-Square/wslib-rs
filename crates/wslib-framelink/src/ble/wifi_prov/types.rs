use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;

/// The firmware's own security byte, not Zephyr's `wifi_security_type`. Only
/// bytes confirmed on hardware are named; any other round-trips unnamed.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct WifiSecurity(u8);

impl WifiSecurity {
    pub const OPEN: Self = Self(0);
    pub const WPA2_PSK: Self = Self(2);

    pub const fn from_byte(b: u8) -> Self {
        Self(b)
    }

    pub const fn byte(self) -> u8 {
        self.0
    }

    /// `"open"` or `"wpa2-psk"`; `None` for an unnamed byte.
    pub const fn name(self) -> Option<&'static str> {
        match self.0 {
            0 => Some("open"),
            2 => Some("wpa2-psk"),
            _ => None,
        }
    }
}

impl core::fmt::Debug for WifiSecurity {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self.name() {
            Some(n) => write!(f, "WifiSecurity({n})"),
            None => write!(f, "WifiSecurity(byte={})", self.0),
        }
    }
}

impl core::fmt::Display for WifiSecurity {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self.name() {
            Some(n) => f.write_str(n),
            None => write!(f, "byte-{}", self.0),
        }
    }
}

impl Serialize for WifiSecurity {
    fn serialize<S: serde::Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        ser.serialize_u8(self.0)
    }
}

impl<'de> Deserialize<'de> for WifiSecurity {
    fn deserialize<D: serde::Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        let byte = u8::deserialize(de)?;
        Ok(Self(byte))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[repr(u8)]
#[non_exhaustive]
pub enum WifiStatus {
    Disconnected = 0,
    Connecting = 1,
    Connected = 2,
    Error = 3,
}

impl WifiStatus {
    /// An unknown byte reads as `Disconnected`.
    pub const fn from_byte(b: u8) -> Self {
        match b {
            1 => Self::Connecting,
            2 => Self::Connected,
            3 => Self::Error,
            _ => Self::Disconnected,
        }
    }

    /// The byte the device reports, the inverse of [`from_byte`](Self::from_byte).
    pub const fn as_byte(self) -> u8 {
        match self {
            Self::Disconnected => 0,
            Self::Connecting => 1,
            Self::Connected => 2,
            Self::Error => 3,
        }
    }

    /// Whether a provisioning attempt has ended, connected or failed.
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Connected | Self::Error)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WifiCredentials {
    pub ssid: String,
    /// `None` for an open network.
    pub passphrase: Option<String>,
    pub security: WifiSecurity,
}

impl WifiCredentials {
    pub fn open(ssid: impl Into<String>) -> Self {
        Self {
            ssid: ssid.into(),
            passphrase: None,
            security: WifiSecurity::OPEN,
        }
    }

    /// WPA2-PSK; an empty passphrase is none.
    pub fn psk(ssid: impl Into<String>, passphrase: impl Into<String>) -> Self {
        let psk = passphrase.into();
        Self {
            ssid: ssid.into(),
            passphrase: if psk.is_empty() { None } else { Some(psk) },
            security: WifiSecurity::WPA2_PSK,
        }
    }
}

/// What the device holds; a field it could not read in time is `None`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProvisioningStatus {
    pub ssid: Option<String>,
    pub security: Option<WifiSecurity>,
    pub status: WifiStatus,
    pub ip_address: Option<Ipv4Addr>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
#[non_exhaustive]
pub enum ProvisioningEvent {
    Status {
        status: WifiStatus,
    },
    /// A DHCP lease, around the time `Connected` is reported.
    IpAddress {
        address: Ipv4Addr,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wifi_security_named_constants_round_trip() {
        for sec in [WifiSecurity::OPEN, WifiSecurity::WPA2_PSK] {
            assert_eq!(WifiSecurity::from_byte(sec.byte()), sec);
            assert!(
                sec.name().is_some(),
                "named constant {sec:?} should have a name"
            );
        }
    }

    #[test]
    fn wifi_status_bytes_round_trip() {
        for status in [
            WifiStatus::Disconnected,
            WifiStatus::Connecting,
            WifiStatus::Connected,
            WifiStatus::Error,
        ] {
            assert_eq!(WifiStatus::from_byte(status.as_byte()), status);
        }
    }

    #[test]
    fn wifi_security_unknown_byte_round_trips_as_raw() {
        let unknown = WifiSecurity::from_byte(0xFE);
        assert_eq!(unknown.byte(), 0xFE);
        assert_eq!(unknown.name(), None);
        assert_eq!(format!("{unknown}"), "byte-254");
    }

    #[test]
    fn wifi_security_known_constant_bytes() {
        assert_eq!(WifiSecurity::OPEN.byte(), 0);
        assert_eq!(WifiSecurity::WPA2_PSK.byte(), 2);
    }

    #[test]
    fn wifi_security_serde_is_raw_byte() {
        let json = serde_json::to_string(&WifiSecurity::WPA2_PSK).unwrap();
        assert_eq!(json, "2");
        let back: WifiSecurity = serde_json::from_str("2").unwrap();
        assert_eq!(back, WifiSecurity::WPA2_PSK);
        let exotic: WifiSecurity = serde_json::from_str("99").unwrap();
        assert_eq!(exotic.byte(), 99);
    }

    #[test]
    fn wifi_status_decoding() {
        assert_eq!(WifiStatus::from_byte(0), WifiStatus::Disconnected);
        assert_eq!(WifiStatus::from_byte(1), WifiStatus::Connecting);
        assert_eq!(WifiStatus::from_byte(2), WifiStatus::Connected);
        assert_eq!(WifiStatus::from_byte(3), WifiStatus::Error);
        assert_eq!(WifiStatus::from_byte(0xFF), WifiStatus::Disconnected);
    }

    #[test]
    fn wifi_status_is_terminal() {
        assert!(WifiStatus::Connected.is_terminal());
        assert!(WifiStatus::Error.is_terminal());
        assert!(!WifiStatus::Disconnected.is_terminal());
        assert!(!WifiStatus::Connecting.is_terminal());
    }

    #[test]
    fn credentials_open_helper() {
        let c = WifiCredentials::open("MyNetwork");
        assert_eq!(c.security, WifiSecurity::OPEN);
        assert_eq!(c.passphrase, None);
    }

    #[test]
    fn credentials_psk_helper_empty_passphrase_treated_as_none() {
        let c = WifiCredentials::psk("MyNetwork", "");
        assert_eq!(c.passphrase, None);
        assert_eq!(c.security, WifiSecurity::WPA2_PSK);
    }

    #[test]
    fn credentials_psk_helper_sends_byte_2() {
        let c = WifiCredentials::psk("MyNetwork", "secret");
        assert_eq!(c.security.byte(), 2);
    }

    #[test]
    fn provisioning_event_serde_tagged() {
        let ev = ProvisioningEvent::Status {
            status: WifiStatus::Connecting,
        };
        let json = serde_json::to_string(&ev).unwrap();
        assert!(json.contains(r#""kind":"status""#));
        let back: ProvisioningEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(back, ev);
    }

    #[test]
    fn ip_address_event_round_trips() {
        let ev = ProvisioningEvent::IpAddress {
            address: Ipv4Addr::new(192, 168, 1, 42),
        };
        let json = serde_json::to_string(&ev).unwrap();
        let back: ProvisioningEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(back, ev);
    }

    #[test]
    fn provisioning_status_round_trips() {
        let s = ProvisioningStatus {
            ssid: Some("MyNetwork".into()),
            security: Some(WifiSecurity::WPA2_PSK),
            status: WifiStatus::Connected,
            ip_address: Some(Ipv4Addr::new(192, 168, 1, 42)),
        };
        let json = serde_json::to_string(&s).unwrap();
        let back: ProvisioningStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(back, s);
    }
}
