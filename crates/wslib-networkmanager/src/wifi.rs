use std::fmt;

use zbus::zvariant::Value;

use crate::props::{group, owned};
use crate::{Device, Settings};

/// What an access point asks of a client, read off its three flag words.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Security {
    Open,
    Wep,
    /// Opportunistic Wireless Encryption: encrypted, with no passphrase.
    Owe,
    WpaPsk,
    /// WPA3-Personal alone; a network that also offers PSK reads as `WpaPsk`.
    Sae,
    /// 802.1X.
    Eap,
}

impl Security {
    /// `NM80211ApFlags.PRIVACY`.
    pub const PRIVACY: u32 = 0x1;
    /// `NM80211ApSecurityFlags.KEY_MGMT_PSK`.
    pub const KEY_MGMT_PSK: u32 = 0x100;
    pub const KEY_MGMT_802_1X: u32 = 0x200;
    pub const KEY_MGMT_SAE: u32 = 0x400;
    pub const KEY_MGMT_OWE: u32 = 0x800;

    /// From an access point's `Flags`, `WpaFlags` and `RsnFlags`.
    pub fn of(flags: u32, wpa: u32, rsn: u32) -> Self {
        let both = wpa | rsn;
        if both & Self::KEY_MGMT_802_1X != 0 {
            Self::Eap
        } else if both & Self::KEY_MGMT_PSK != 0 {
            Self::WpaPsk
        } else if both & Self::KEY_MGMT_SAE != 0 {
            Self::Sae
        } else if both & Self::KEY_MGMT_OWE != 0 {
            Self::Owe
        } else if flags & Self::PRIVACY != 0 {
            Self::Wep
        } else {
            Self::Open
        }
    }

    /// Why [`Device::wifi_profile`](crate::Device::wifi_profile) refuses this network, if it does.
    pub fn unsupported(self) -> Option<Unsupported> {
        match self {
            Self::Wep => Some(Unsupported::Wep),
            Self::Eap => Some(Unsupported::Enterprise),
            _ => None,
        }
    }

    pub fn needs_passphrase(self) -> bool {
        matches!(self, Self::Wep | Self::WpaPsk | Self::Sae)
    }

    /// `802-11-wireless-security.key-mgmt`, `None` for an open network and for
    /// the two this crate builds no profile for, WEP and 802.1X.
    pub fn key_mgmt(self) -> Option<&'static str> {
        match self {
            Self::Owe => Some("owe"),
            Self::WpaPsk => Some("wpa-psk"),
            Self::Sae => Some("sae"),
            Self::Open | Self::Wep | Self::Eap => None,
        }
    }
}

/// Why [`Device::wifi_profile`] built no profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JoinError {
    NeedsPassphrase,
    Unsupported(Unsupported),
}

impl fmt::Display for JoinError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NeedsPassphrase => f.write_str("the network needs a passphrase"),
            Self::Unsupported(Unsupported::Wep) => f.write_str("WEP networks are not supported"),
            Self::Unsupported(Unsupported::Enterprise) => {
                f.write_str("802.1X networks are not supported")
            }
        }
    }
}

impl std::error::Error for JoinError {}

/// The security this crate builds no profile for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unsupported {
    Wep,
    /// 802.1X.
    Enterprise,
}

impl Device {
    /// A profile joining `ssid`, secured as the strongest access point by that
    /// name asks, since a WPA3-only network refuses `wpa-psk`. A network not
    /// in range is taken at the passphrase's word: WPA-PSK with one, open
    /// without. A passphrase for a network that takes none is left out.
    pub fn wifi_profile(
        &self,
        ssid: &[u8],
        passphrase: Option<&str>,
    ) -> Result<Settings, JoinError> {
        let security = self.strongest(ssid).map_or(
            if passphrase.is_some() {
                Security::WpaPsk
            } else {
                Security::Open
            },
            |ap| ap.security,
        );
        wifi_profile(ssid, security, passphrase)
    }
}

fn wifi_profile(
    ssid: &[u8],
    security: Security,
    passphrase: Option<&str>,
) -> Result<Settings, JoinError> {
    if let Some(refused) = security.unsupported() {
        return Err(JoinError::Unsupported(refused));
    }
    let passphrase = match (security.needs_passphrase(), passphrase) {
        (true, None) => return Err(JoinError::NeedsPassphrase),
        (true, passphrase) => passphrase,
        (false, _) => None,
    };
    let mut settings = Settings::from([
        (
            "connection".to_string(),
            group([
                (
                    "id",
                    Value::from(String::from_utf8_lossy(ssid).into_owned()),
                ),
                ("type", Value::from("802-11-wireless")),
            ]),
        ),
        (
            "802-11-wireless".to_string(),
            group([
                ("ssid", Value::from(ssid.to_vec())),
                ("mode", Value::from("infrastructure")),
            ]),
        ),
        ("ipv4".to_string(), group([("method", Value::from("auto"))])),
    ]);
    if let Some(key_mgmt) = security.key_mgmt() {
        let mut secured = group([("key-mgmt", Value::from(key_mgmt))]);
        if let Some(passphrase) = passphrase {
            secured.insert("psk".to_string(), owned(Value::from(passphrase)));
        }
        settings.insert("802-11-wireless-security".to_string(), secured);
    }
    Ok(settings)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::props::{prop, text};

    #[test]
    fn security_is_read_off_the_flag_words() {
        use Security::*;
        assert_eq!(Security::of(0, 0, 0), Open);
        assert_eq!(Security::of(1, 0, 0), Wep);
        assert_eq!(Security::of(1, Security::KEY_MGMT_PSK, 0), WpaPsk);
        assert_eq!(Security::of(1, 0, Security::KEY_MGMT_SAE), Sae);
        assert_eq!(
            Security::of(1, 0, Security::KEY_MGMT_SAE | Security::KEY_MGMT_PSK),
            WpaPsk
        );
        assert_eq!(Security::of(0, 0, Security::KEY_MGMT_OWE), Owe);
        assert_eq!(Security::of(1, 0, Security::KEY_MGMT_802_1X), Eap);
        assert!(!Owe.needs_passphrase() && WpaPsk.needs_passphrase());
    }

    #[test]
    fn a_profile_carries_the_ssid_as_bytes_and_the_key_management_asked_for() {
        let key_mgmt = |s: &Settings| text(&s["802-11-wireless-security"], "key-mgmt");
        let open = wifi_profile(b"Ops", Security::Open, None).unwrap();
        assert_eq!(
            prop::<Vec<u8>>(&open["802-11-wireless"], "ssid").unwrap(),
            b"Ops"
        );
        assert_eq!(text(&open["connection"], "id").as_deref(), Some("Ops"));
        assert!(!open.contains_key("802-11-wireless-security"));

        let psk = wifi_profile(b"Ops", Security::WpaPsk, Some("hunter2hunter2")).unwrap();
        assert_eq!(key_mgmt(&psk).as_deref(), Some("wpa-psk"));
        assert_eq!(
            text(&psk["802-11-wireless-security"], "psk").as_deref(),
            Some("hunter2hunter2")
        );
        let sae = wifi_profile(b"Ops", Security::Sae, Some("hunter2hunter2")).unwrap();
        assert_eq!(key_mgmt(&sae).as_deref(), Some("sae"));

        let owe = wifi_profile(b"Ops", Security::Owe, Some("ignored")).unwrap();
        assert_eq!(key_mgmt(&owe).as_deref(), Some("owe"));
        assert!(!owe["802-11-wireless-security"].contains_key("psk"));
        assert!(
            !wifi_profile(b"Ops", Security::Open, Some("ignored"))
                .unwrap()
                .contains_key("802-11-wireless-security")
        );
    }

    #[test]
    fn wep_802_1x_and_a_missing_passphrase_build_nothing() {
        for (security, refused) in [
            (Security::Wep, Unsupported::Wep),
            (Security::Eap, Unsupported::Enterprise),
        ] {
            assert_eq!(security.unsupported(), Some(refused));
            assert_eq!(
                wifi_profile(b"Ops", security, Some("x")),
                Err(JoinError::Unsupported(refused))
            );
        }
        assert_eq!(
            wifi_profile(b"Ops", Security::WpaPsk, None),
            Err(JoinError::NeedsPassphrase)
        );
    }
}
