use std::collections::HashMap;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use zbus::zvariant::OwnedObjectPath;

use crate::props::{addresses, entries, number, prop, text};
use crate::{Group, Objects, Security};

pub(crate) const DEVICE: &str = "org.freedesktop.NetworkManager.Device";
pub(crate) const WIRED: &str = "org.freedesktop.NetworkManager.Device.Wired";
pub(crate) const WIRELESS: &str = "org.freedesktop.NetworkManager.Device.Wireless";
pub(crate) const ACCESS_POINT: &str = "org.freedesktop.NetworkManager.AccessPoint";
pub(crate) const ACTIVE: &str = "org.freedesktop.NetworkManager.Connection.Active";
pub(crate) const IP4_CONFIG: &str = "org.freedesktop.NetworkManager.IP4Config";
pub(crate) const IP6_CONFIG: &str = "org.freedesktop.NetworkManager.IP6Config";

/// One device as NetworkManager's object tree has it.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct Device {
    pub path: OwnedObjectPath,
    pub interface: String,
    pub kind: DeviceKind,
    pub state: DeviceState,
    /// An `NMDeviceStateReason`; [`reason`](crate::reason) names the ones worth acting on.
    pub reason: u32,
    pub managed: bool,
    pub hw_address: Option<String>,
    /// Wired devices only.
    pub carrier: Option<bool>,
    pub ip4: Option<IpConfig<Ipv4Addr>>,
    pub ip6: Option<IpConfig<Ipv6Addr>>,
    /// The profile behind the device's active connection.
    pub profile: Option<OwnedObjectPath>,
    /// Wi-Fi devices only, leaving out hidden networks' nameless ones.
    pub access_points: Vec<AccessPoint>,
    /// The one a Wi-Fi device is associated with.
    pub active_access_point: Option<AccessPoint>,
}

/// `NMDeviceType`, as far as this crate tells types apart.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceKind {
    Ethernet,
    Wifi,
    Other(u32),
}

/// `NMDeviceState`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceState {
    Unknown,
    Unmanaged,
    /// Where an unplugged wired device sits.
    Unavailable,
    Disconnected,
    Prepare,
    Config,
    NeedAuth,
    IpConfig,
    IpCheck,
    Secondaries,
    Activated,
    Deactivating,
    Failed,
}

impl From<u32> for DeviceState {
    fn from(state: u32) -> Self {
        match state {
            10 => Self::Unmanaged,
            20 => Self::Unavailable,
            30 => Self::Disconnected,
            40 => Self::Prepare,
            50 => Self::Config,
            60 => Self::NeedAuth,
            70 => Self::IpConfig,
            80 => Self::IpCheck,
            90 => Self::Secondaries,
            100 => Self::Activated,
            110 => Self::Deactivating,
            120 => Self::Failed,
            _ => Self::Unknown,
        }
    }
}

impl DeviceState {
    /// Between `Prepare` and `Secondaries`: on the way to `Activated`.
    pub fn is_activating(self) -> bool {
        matches!(
            self,
            Self::Prepare
                | Self::Config
                | Self::NeedAuth
                | Self::IpConfig
                | Self::IpCheck
                | Self::Secondaries
        )
    }
}

/// The `NMDeviceStateReason` values a caller is likely to act on; every other
/// one, including those each activation passes through, is left as a number.
pub mod reason {
    pub const IP_CONFIG_UNAVAILABLE: u32 = 5;
    /// On Wi-Fi, typically a wrong passphrase.
    pub const NO_SECRETS: u32 = 7;
    pub const SUPPLICANT_DISCONNECT: u32 = 8;
    pub const SUPPLICANT_FAILED: u32 = 10;
    pub const SUPPLICANT_TIMEOUT: u32 = 11;
    /// Not reliably left on an unplugged device; see [`Device::unplugged`](crate::Device::unplugged).
    pub const CARRIER: u32 = 40;
    pub const SSID_NOT_FOUND: u32 = 53;
    pub const IP_ADDRESS_DUPLICATE: u32 = 64;
}

/// What an interface has now, as distinct from how its profile configures it.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct IpConfig<A> {
    pub addresses: Vec<Address<A>>,
    pub gateway: Option<A>,
    pub dns: Vec<A>,
}

/// An address and its prefix length, shown as `10.0.50.12/24`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Address<A = IpAddr> {
    pub address: A,
    pub prefix: u8,
}

impl<A: Into<IpAddr>> Address<A> {
    pub fn widen(self) -> Address {
        Address {
            address: self.address.into(),
            prefix: self.prefix,
        }
    }
}

impl<A: fmt::Display> fmt::Display for Address<A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.address, self.prefix)
    }
}

/// One access point a Wi-Fi device sees.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct AccessPoint {
    pub path: OwnedObjectPath,
    /// Bytes, as an SSID has no declared encoding.
    pub ssid: Vec<u8>,
    /// Percent.
    pub strength: u8,
    pub security: Security,
}

impl Device {
    /// A wired device with no cable in, which NetworkManager says through
    /// `Carrier` rather than reliably as the state's reason.
    pub fn unplugged(&self) -> bool {
        self.kind == DeviceKind::Ethernet
            && self.state == DeviceState::Unavailable
            && self.carrier == Some(false)
    }

    /// Both families' addresses, IPv4 first.
    pub fn addresses(&self) -> impl Iterator<Item = Address> {
        let v4 = self
            .ip4
            .iter()
            .flat_map(|c| &c.addresses)
            .map(|a| a.widen());
        let v6 = self
            .ip6
            .iter()
            .flat_map(|c| &c.addresses)
            .map(|a| a.widen());
        v4.chain(v6)
    }

    /// One access point per SSID, the strongest, strongest first.
    pub fn networks(&self) -> Vec<&AccessPoint> {
        let mut best: HashMap<&[u8], &AccessPoint> = HashMap::new();
        for ap in &self.access_points {
            let seen = best.entry(&ap.ssid).or_insert(ap);
            if seen.strength < ap.strength {
                *seen = ap;
            }
        }
        let mut networks: Vec<_> = best.into_values().collect();
        networks.sort_by(|a, b| b.strength.cmp(&a.strength).then(a.ssid.cmp(&b.ssid)));
        networks
    }

    /// The strongest access point named `ssid`.
    pub fn strongest(&self, ssid: &[u8]) -> Option<&AccessPoint> {
        self.access_points
            .iter()
            .filter(|ap| ap.ssid == ssid)
            .max_by_key(|ap| ap.strength)
    }

    /// Every device in an object tree as `GetManagedObjects` answers it, by
    /// interface name; [`Client::devices`](crate::Client::devices) reads one off the bus.
    pub fn from_objects(objects: &Objects) -> Vec<Device> {
        let mut devices: Vec<Device> = objects
            .iter()
            .filter_map(|(path, interfaces)| {
                let props = interfaces.get(DEVICE)?;
                let linked = |key| linked(objects, props, key);
                let wireless = interfaces.get(WIRELESS);
                Some(Device {
                    path: path.clone(),
                    interface: text(props, "Interface").unwrap_or_default(),
                    kind: match number(props, "DeviceType").unwrap_or(0) {
                        1 => DeviceKind::Ethernet,
                        2 => DeviceKind::Wifi,
                        other => DeviceKind::Other(other),
                    },
                    state: number(props, "State").unwrap_or(0).into(),
                    reason: prop::<(u32, u32)>(props, "StateReason").map_or(0, |(_, why)| why),
                    managed: prop(props, "Managed").unwrap_or(false),
                    hw_address: text(props, "HwAddress").filter(|a| !a.is_empty()),
                    carrier: interfaces.get(WIRED).and_then(|w| prop(w, "Carrier")),
                    ip4: linked("Ip4Config")
                        .and_then(|o| o.get(IP4_CONFIG))
                        .map(|g| {
                            let dns = entries(g, "NameserverData")
                                .iter()
                                .filter_map(|entry| text(entry, "address")?.parse().ok())
                                .collect();
                            ip_config(g, dns)
                        }),
                    ip6: linked("Ip6Config")
                        .and_then(|o| o.get(IP6_CONFIG))
                        .map(|g| {
                            let dns = prop::<Vec<Vec<u8>>>(g, "Nameservers")
                                .unwrap_or_default()
                                .into_iter()
                                .filter_map(|bytes| Some(<[u8; 16]>::try_from(bytes).ok()?.into()))
                                .collect();
                            ip_config(g, dns)
                        }),
                    profile: linked("ActiveConnection")
                        .and_then(|o| prop(o.get(ACTIVE)?, "Connection")),
                    access_points: wireless
                        .and_then(|w| prop::<Vec<OwnedObjectPath>>(w, "AccessPoints"))
                        .unwrap_or_default()
                        .iter()
                        .filter_map(|ap| access_point(objects, ap))
                        .collect(),
                    active_access_point: wireless
                        .and_then(|w| prop::<OwnedObjectPath>(w, "ActiveAccessPoint"))
                        .and_then(|ap| access_point(objects, &ap)),
                })
            })
            .collect();
        devices.sort_by(|a, b| a.interface.cmp(&b.interface));
        devices
    }
}

/// The object a path-valued property names; NetworkManager says none with `/`.
fn linked<'a>(
    objects: &'a Objects,
    props: &Group,
    key: &str,
) -> Option<&'a HashMap<String, Group>> {
    objects.get(&prop::<OwnedObjectPath>(props, key)?)
}

fn ip_config<A: FromStr>(config: &Group, dns: Vec<A>) -> IpConfig<A> {
    IpConfig {
        addresses: addresses(config, "AddressData"),
        gateway: text(config, "Gateway").and_then(|g| g.parse().ok()),
        dns,
    }
}

fn access_point(objects: &Objects, path: &OwnedObjectPath) -> Option<AccessPoint> {
    let ap = objects.get(path)?.get(ACCESS_POINT)?;
    let flags = |key| number(ap, key).unwrap_or(0);
    Some(AccessPoint {
        path: path.clone(),
        ssid: prop::<Vec<u8>>(ap, "Ssid").filter(|s| !s.is_empty())?,
        strength: prop(ap, "Strength").unwrap_or(0),
        security: Security::of(flags("Flags"), flags("WpaFlags"), flags("RsnFlags")),
    })
}
