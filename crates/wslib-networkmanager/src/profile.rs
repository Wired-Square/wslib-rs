use std::collections::HashMap;
use std::net::Ipv4Addr;

use zbus::zvariant::{OwnedObjectPath, Value};

use crate::props::{addresses, owned, prop, text};
use crate::{Address, Group, Settings};

/// A profile's IPv4 addressing, as this crate writes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ipv4 {
    /// DHCP, with `dns` in place of the lease's resolvers unless it is empty.
    Auto { dns: Vec<Ipv4Addr> },
    Manual {
        address: Ipv4Addr,
        prefix: u8,
        gateway: Option<Ipv4Addr>,
        dns: Vec<Ipv4Addr>,
    },
}

impl Ipv4 {
    /// The whole `ipv4` group for this addressing.
    ///
    /// No gateway is an absent key, never `""`, which NetworkManager reads as
    /// a gateway that is set and refuses. `Auto` still writes an empty
    /// `address-data`, so the profile visibly carries no static address.
    pub fn group(&self) -> Group {
        let (Self::Auto { dns } | Self::Manual { dns, .. }) = self;
        let mut ipv4 = HashMap::new();
        if !dns.is_empty() {
            // `au` in host byte order: network order writes 1.1.168.192 for
            // 192.168.1.1, which applies and never resolves.
            let packed: Vec<u32> = dns.iter().map(|d| u32::from_ne_bytes(d.octets())).collect();
            ipv4.insert("dns".to_string(), owned(Value::from(packed)));
            ipv4.insert("ignore-auto-dns".to_string(), owned(Value::from(true)));
        }
        let (method, address_data) = match self {
            Self::Auto { .. } => ("auto", Vec::new()),
            Self::Manual {
                address,
                prefix,
                gateway,
                ..
            } => {
                if let Some(gateway) = gateway {
                    ipv4.insert(
                        "gateway".to_string(),
                        owned(Value::from(gateway.to_string())),
                    );
                }
                let entry = HashMap::from([
                    ("address".to_string(), Value::from(address.to_string())),
                    ("prefix".to_string(), Value::from(u32::from(*prefix))),
                ]);
                ("manual", vec![entry])
            }
        };
        ipv4.insert("method".to_string(), owned(Value::from(method)));
        ipv4.insert("address-data".to_string(), owned(Value::from(address_data)));
        ipv4
    }
}

/// Replaces `settings`' whole `ipv4` group, ready for
/// [`Client::update_profile`](crate::Client::update_profile). Drops the
/// `proxy` group `GetSettings` answers with, which NetworkManager fills in
/// itself.
pub fn set_ipv4(settings: &mut Settings, ipv4: &Ipv4) {
    settings.insert("ipv4".to_string(), ipv4.group());
    settings.remove("proxy");
}

/// A profile's `ipv4` group as it reads.
/// `ipv4.method`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ipv4Method {
    Auto,
    Manual,
    LinkLocal,
    Shared,
    Disabled,
    Other(String),
}

impl From<String> for Ipv4Method {
    fn from(method: String) -> Self {
        match method.as_str() {
            "auto" => Self::Auto,
            "manual" => Self::Manual,
            "link-local" => Self::LinkLocal,
            "shared" => Self::Shared,
            "disabled" => Self::Disabled,
            _ => Self::Other(method),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ProfileIpv4 {
    /// `None` when the group does not say, which NetworkManager takes as `Auto`.
    pub method: Option<Ipv4Method>,
    pub addresses: Vec<Address<Ipv4Addr>>,
    pub gateway: Option<Ipv4Addr>,
    pub dns: Vec<Ipv4Addr>,
}

impl ProfileIpv4 {
    /// `None` when the profile has no `ipv4` group.
    pub fn read(settings: &Settings) -> Option<Self> {
        let ipv4 = settings.get("ipv4")?;
        Some(Self {
            method: text(ipv4, "method").map(Ipv4Method::from),
            addresses: addresses(ipv4, "address-data"),
            gateway: text(ipv4, "gateway").and_then(|g| g.parse().ok()),
            dns: prop::<Vec<u32>>(ipv4, "dns")
                .unwrap_or_default()
                .into_iter()
                .map(|packed| Ipv4Addr::from(packed.to_ne_bytes()))
                .collect(),
        })
    }

    /// DHCP with nothing set beside it.
    pub fn is_plain_auto(&self) -> bool {
        matches!(self.method, None | Some(Ipv4Method::Auto))
            && self.addresses.is_empty()
            && self.dns.is_empty()
    }
}

/// `connection.type`: `802-3-ethernet`, `802-11-wireless`, …
pub fn connection_type(settings: &Settings) -> Option<String> {
    text(settings.get("connection")?, "type")
}

pub(crate) fn ssid(settings: &Settings) -> Option<Vec<u8>> {
    prop(settings.get("802-11-wireless")?, "ssid")
}

/// A profile NetworkManager holds, as [`Client::saved`](crate::Client::saved) lists it.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Profile {
    pub path: OwnedObjectPath,
    /// Kept when a checkpoint's rollback adds the profile back at a new path.
    pub uuid: String,
    pub id: String,
    /// `connection.type`.
    pub kind: String,
    /// Wi-Fi profiles only.
    pub ssid: Option<Vec<u8>>,
}

impl Profile {
    /// `None` without the `uuid`, `id` and `type` NetworkManager gives every profile.
    pub fn read(path: OwnedObjectPath, settings: &Settings) -> Option<Self> {
        let connection = settings.get("connection")?;
        Some(Self {
            path,
            uuid: text(connection, "uuid")?,
            id: text(connection, "id")?,
            kind: text(connection, "type")?,
            ssid: ssid(settings),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manual(gateway: Option<Ipv4Addr>) -> Ipv4 {
        Ipv4::Manual {
            address: Ipv4Addr::new(10, 0, 50, 12),
            prefix: 24,
            gateway,
            dns: Vec::new(),
        }
    }

    fn read(ipv4: &Ipv4) -> ProfileIpv4 {
        ProfileIpv4::read(&Settings::from([("ipv4".to_string(), ipv4.group())])).unwrap()
    }

    #[test]
    fn no_gateway_is_an_absent_key() {
        assert!(!Ipv4::Auto { dns: vec![] }.group().contains_key("gateway"));
        assert!(!manual(None).group().contains_key("gateway"));
        let gateway = Some(Ipv4Addr::new(10, 0, 50, 254));
        assert_eq!(
            text(&manual(gateway).group(), "gateway").as_deref(),
            Some("10.0.50.254")
        );
        assert_eq!(read(&manual(gateway)).gateway, gateway);
    }

    #[test]
    fn auto_writes_an_empty_address_list_and_reads_back_plain() {
        let auto = Ipv4::Auto { dns: vec![] };
        assert!(auto.group().contains_key("address-data"));
        let back = read(&auto);
        assert_eq!(back.method, Some(Ipv4Method::Auto));
        assert!(back.is_plain_auto());

        let back = read(&manual(None));
        assert_eq!(back.method, Some(Ipv4Method::Manual));
        assert_eq!(
            back.addresses
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
            ["10.0.50.12/24"]
        );
        assert!(!back.is_plain_auto());
        assert!(ProfileIpv4::read(&Settings::new()).is_none());
    }

    #[test]
    fn a_missing_method_reads_as_none_and_an_unknown_one_is_kept() {
        let with =
            |ipv4: Group| ProfileIpv4::read(&Settings::from([("ipv4".to_string(), ipv4)])).unwrap();
        let unsaid = with(Group::new());
        assert_eq!(unsaid.method, None);
        assert!(unsaid.is_plain_auto());
        for (word, method) in [
            ("link-local", Ipv4Method::LinkLocal),
            ("shared", Ipv4Method::Shared),
            ("disabled", Ipv4Method::Disabled),
            ("carrier-pigeon", Ipv4Method::Other("carrier-pigeon".into())),
        ] {
            let read = with(crate::props::group([("method", Value::from(word))]));
            assert_eq!(read.method, Some(method));
            assert!(!read.is_plain_auto());
        }
    }

    #[test]
    fn resolvers_are_host_byte_order_and_win_over_the_lease() {
        let resolver = Ipv4Addr::new(192, 168, 1, 1);
        let group = Ipv4::Auto {
            dns: vec![resolver],
        }
        .group();
        assert_eq!(
            prop::<Vec<u32>>(&group, "dns").unwrap(),
            [u32::from_ne_bytes([192, 168, 1, 1])]
        );
        assert_eq!(prop::<bool>(&group, "ignore-auto-dns"), Some(true));
        assert_eq!(
            read(&Ipv4::Auto {
                dns: vec![resolver]
            })
            .dns,
            [resolver]
        );
        assert!(
            !read(&Ipv4::Auto {
                dns: vec![resolver]
            })
            .is_plain_auto()
        );
        assert!(!Ipv4::Auto { dns: vec![] }.group().contains_key("dns"));
    }

    #[test]
    fn setting_ipv4_replaces_the_group_and_drops_proxy() {
        let mut settings = Settings::from([
            ("ipv4".to_string(), manual(None).group()),
            ("proxy".to_string(), Group::new()),
            (
                "connection".to_string(),
                crate::props::group([("type", Value::from("802-3-ethernet"))]),
            ),
        ]);
        set_ipv4(&mut settings, &Ipv4::Auto { dns: vec![] });
        assert!(!settings.contains_key("proxy"));
        assert!(read(&Ipv4::Auto { dns: vec![] }) == ProfileIpv4::read(&settings).unwrap());
        assert_eq!(
            connection_type(&settings).as_deref(),
            Some("802-3-ethernet")
        );
    }
}
