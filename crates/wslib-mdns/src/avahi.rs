//! avahi over D-Bus: adverts in entry groups, the server's host name and
//! state, and address records for an alias.

use std::net::IpAddr;

use futures_util::{Stream, StreamExt};
use tokio::sync::watch;
use tokio::task::AbortHandle;
use zbus::Connection;

use crate::service::Held;
use crate::{Advert, AdvertState, Error, HostName, Service};

pub(crate) const AVAHI: &str = "org.freedesktop.Avahi";

/// avahi's `AVAHI_PUBLISH_NO_REVERSE`: the address's reverse record is the
/// machine's own name's, and a second one is a local collision.
const NO_REVERSE: u32 = 16;

/// avahi on a bus, usually the system bus.
#[derive(Debug, Clone)]
pub struct Avahi {
    connection: Connection,
}

impl Avahi {
    pub fn new(connection: &Connection) -> Self {
        Self {
            connection: connection.clone(),
        }
    }

    /// Publishes `service` on every interface and both protocols, under
    /// avahi's host name.
    pub async fn advertise(&self, service: &Service) -> Result<Advert, Error> {
        let (name, kind) = (service.instance.to_string(), service.kind.to_string());
        let mut records = vec![Record::Service {
            name: name.clone(),
            kind: kind.clone(),
            port: service.port,
            txt: service
                .txt
                .iter()
                .map(|t| t.to_string().into_bytes())
                .collect(),
        }];
        for subtype in service.subtypes_of_its_kind()? {
            records.push(Record::Subtype {
                name: name.clone(),
                kind: kind.clone(),
                subtype: subtype.to_string(),
            });
        }
        let group = Group::publish(&self.connection, records).await?;
        Ok(Advert {
            state: group.state.clone(),
            held: Held::Avahi(group),
        })
    }
}

/// A and AAAA records for one name, published and withdrawn together, and
/// withdrawn when dropped.
#[derive(Debug)]
pub struct AddressGroup(Group);

impl AddressGroup {
    /// Publishes `name` on each `(interface index, address)` with no reverse
    /// record, an AAAA record on both protocols and an A record on IPv4 alone
    /// as avahi publishes its own host name.
    pub async fn publish(
        connection: &Connection,
        name: &HostName,
        addresses: impl IntoIterator<Item = (u32, IpAddr)>,
    ) -> Result<Self, Error> {
        let records = addresses
            .into_iter()
            .map(|(interface, ip)| {
                Ok(Record::Address {
                    interface: i32::try_from(interface)
                        .map_err(|_| Error::Unsupported("an interface index past i32"))?,
                    protocol: if ip.is_ipv4() { 0 } else { -1 },
                    name: name.fqdn(),
                    address: ip.to_string(),
                })
            })
            .collect::<Result<Vec<_>, Error>>()?;
        if records.is_empty() {
            return Err(Error::Unsupported("an address group with no addresses"));
        }
        Group::publish(connection, records).await.map(Self)
    }

    pub fn state(&self) -> watch::Receiver<AdvertState> {
        self.0.state.clone()
    }

    pub async fn withdraw(self) -> Result<(), Error> {
        self.0.withdraw().await
    }
}

/// Of `addresses` on each interface, the ones avahi publishes for its own
/// host name: per interface and family the global ones, or the link-local
/// ones where there is none. Sorted, without repeats.
pub fn own_addresses(addresses: impl IntoIterator<Item = (u32, IpAddr)>) -> Vec<(u32, IpAddr)> {
    let link_local = |ip: &IpAddr| match ip {
        IpAddr::V4(ip) => ip.is_link_local(),
        IpAddr::V6(ip) => ip.is_unicast_link_local(),
    };
    let all: Vec<_> = addresses.into_iter().collect();
    let has_global = |interface: u32, v4: bool| {
        all.iter()
            .any(|(i, ip)| *i == interface && ip.is_ipv4() == v4 && !link_local(ip))
    };
    let mut own: Vec<_> = all
        .iter()
        .filter(|(i, ip)| !link_local(ip) || !has_global(*i, ip.is_ipv4()))
        .copied()
        .collect();
    own.sort();
    own.dedup();
    own
}

/// One record of an entry group, as avahi's calls take it.
enum Record {
    Service {
        name: String,
        kind: String,
        port: u16,
        txt: Vec<Vec<u8>>,
    },
    Subtype {
        name: String,
        kind: String,
        subtype: String,
    },
    Address {
        interface: i32,
        protocol: i32,
        name: String,
        address: String,
    },
}

impl Record {
    async fn add(self, group: &entry_group::EntryGroupProxy<'_>) -> zbus::Result<()> {
        match self {
            Self::Service {
                name,
                kind,
                port,
                txt,
            } => {
                group
                    .add_service(-1, -1, 0, &name, &kind, "", "", port, txt)
                    .await
            }
            Self::Subtype {
                name,
                kind,
                subtype,
            } => {
                group
                    .add_service_subtype(-1, -1, 0, &name, &kind, "", &subtype)
                    .await
            }
            Self::Address {
                interface,
                protocol,
                name,
                address,
            } => {
                group
                    .add_address(interface, protocol, NO_REVERSE, &name, &address)
                    .await
            }
        }
    }
}

/// An entry group this connection holds, freed when dropped, and the watch
/// on its state.
#[derive(Debug)]
pub(crate) struct Group {
    proxy: Option<entry_group::EntryGroupProxy<'static>>,
    state: watch::Receiver<AdvertState>,
    watcher: Option<AbortHandle>,
}

impl Group {
    /// A new group holding `records`, watched before it is committed so no
    /// state is missed. The group is owned from the moment avahi answers, so
    /// a publish failed or cut short frees it.
    async fn publish(connection: &Connection, records: Vec<Record>) -> Result<Self, Error> {
        let proxy = async {
            let path = server::AvahiProxy::new(connection)
                .await?
                .entry_group_new()
                .await?;
            entry_group::EntryGroupProxy::builder(connection)
                .path(path)?
                .build()
                .await
        }
        .await
        .map_err(bus_error)?;
        let (states, state) = watch::channel(AdvertState::Registering);
        let mut group = Self {
            proxy: Some(proxy.clone()),
            state,
            watcher: None,
        };
        let filled = async {
            let changes = proxy.receive_state_changed().await?;
            for record in records {
                record.add(&proxy).await?;
            }
            proxy.commit().await?;
            zbus::Result::Ok(changes)
        };
        let mut changes = match filled.await {
            Ok(changes) => changes,
            Err(e) => {
                group.withdraw().await.ok();
                return Err(bus_error(e));
            }
        };
        let watcher = tokio::spawn(async move {
            while let Some(changed) = changes.next().await {
                if let Some(next) = changed.args().ok().and_then(|a| group_state(a.state)) {
                    states.send_replace(next);
                }
            }
        });
        group.watcher = Some(watcher.abort_handle());
        Ok(group)
    }

    pub(crate) async fn withdraw(mut self) -> Result<(), Error> {
        match self.proxy.take() {
            Some(group) => group.free().await.map_err(bus_error),
            None => Ok(()),
        }
    }
}

impl Drop for Group {
    fn drop(&mut self) {
        if let Some(watcher) = self.watcher.take() {
            watcher.abort();
        }
        if let (Some(group), Ok(runtime)) =
            (self.proxy.take(), tokio::runtime::Handle::try_current())
        {
            runtime.spawn(async move { group.free().await.ok() });
        }
    }
}

fn group_state(state: i32) -> Option<AdvertState> {
    Some(match state {
        1 => AdvertState::Registering,
        2 => AdvertState::Established,
        3 => AdvertState::Collided,
        4 => AdvertState::Failed,
        _ => return None,
    })
}

const NOBODY_OWNS_AVAHI: [&str; 2] = [
    "org.freedesktop.DBus.Error.ServiceUnknown",
    "org.freedesktop.DBus.Error.NameHasNoOwner",
];

fn error_name(e: &zbus::Error) -> Option<&str> {
    match e {
        zbus::Error::MethodError(name, ..) => Some(name.as_str()),
        _ => None,
    }
}

fn bus_error(e: zbus::Error) -> Error {
    match error_name(&e) {
        Some("org.freedesktop.Avahi.CollisionError") => Error::Collision(e),
        Some(name) if NOBODY_OWNS_AVAHI.contains(&name) => Error::NotRunning(e),
        _ => Error::Bus(e),
    }
}

/// avahi's server state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ServerState {
    Invalid,
    Registering,
    /// Running under its host name, which a collision may just have changed.
    Running,
    Collision,
    Failure,
}

impl From<i32> for ServerState {
    fn from(state: i32) -> Self {
        match state {
            1 => Self::Registering,
            2 => Self::Running,
            3 => Self::Collision,
            4 => Self::Failure,
            _ => Self::Invalid,
        }
    }
}

/// Whether anything owns avahi's name on the bus.
pub async fn is_running(connection: &Connection) -> Result<bool, Error> {
    async {
        let bus = zbus::fdo::DBusProxy::new(connection).await?;
        Ok(bus.name_has_owner(AVAHI.try_into()?).await?)
    }
    .await
    .map_err(bus_error)
}

/// The label `.local` answers to now, avahi's rename of it after a collision included.
pub async fn host_name(connection: &Connection) -> Result<String, Error> {
    async {
        server::AvahiProxy::new(connection)
            .await?
            .get_host_name()
            .await
    }
    .await
    .map_err(bus_error)
}

/// The label `.local` answers to from now on, until avahi restarts; avahi
/// keeps this for root and the `netdev` group. Its own name already is no change.
pub async fn set_host_name(connection: &Connection, name: &HostName) -> Result<(), Error> {
    let set = async {
        server::AvahiProxy::new(connection)
            .await?
            .set_host_name(name.as_str())
            .await
    };
    match set.await {
        Err(e) if error_name(&e) == Some("org.freedesktop.Avahi.NoChangeError") => Ok(()),
        set => set.map_err(bus_error),
    }
}

/// `true` each time an avahi takes the name, `false` each time one leaves
/// it; a new avahi holds none of the old one's groups.
pub async fn restarts(
    connection: &Connection,
) -> Result<impl Stream<Item = bool> + Unpin + Send + 'static, Error> {
    async {
        let avahi = server::AvahiProxy::new(connection).await?;
        avahi.inner().receive_owner_changed().await
    }
    .await
    .map(|owners| owners.map(|owner| owner.is_some()))
    .map_err(bus_error)
}

pub async fn server_states(
    connection: &Connection,
) -> Result<impl Stream<Item = ServerState> + Unpin + Send + 'static, Error> {
    async {
        let avahi = server::AvahiProxy::new(connection).await?;
        avahi.receive_state_changed().await
    }
    .await
    .map(|changes| {
        changes
            .filter_map(|changed| std::future::ready(changed.args().ok().map(|a| a.state.into())))
    })
    .map_err(bus_error)
}

/// Whether `called` is a name avahi's collision rename makes of `label`, once
/// or more: `-2` appended, or a trailing `-<n>` counted up, not one with a
/// leading zero, which avahi appends to like any other.
pub fn renamed_by_avahi(label: &str, called: &str) -> bool {
    fn numbered(name: &str) -> Option<(&str, u64)> {
        let (stem, n) = name.rsplit_once('-')?;
        let n = (!n.starts_with('0') && n.bytes().all(|b| b.is_ascii_digit()))
            .then(|| n.parse().ok())??;
        Some((stem, n))
    }
    let Some((stem, n)) = numbered(called) else {
        return false;
    };
    match numbered(label) {
        Some((label_stem, m)) => stem == label_stem && n > m,
        None => stem == label && n >= 2,
    }
}

mod server {
    use zbus::proxy;

    #[proxy(
        interface = "org.freedesktop.Avahi.Server",
        default_service = "org.freedesktop.Avahi",
        default_path = "/"
    )]
    pub(crate) trait Avahi {
        fn entry_group_new(&self) -> zbus::Result<zbus::zvariant::OwnedObjectPath>;

        fn get_host_name(&self) -> zbus::Result<String>;

        fn set_host_name(&self, name: &str) -> zbus::Result<()>;

        #[zbus(signal)]
        fn state_changed(&self, state: i32, error: String) -> zbus::Result<()>;
    }
}

#[allow(clippy::too_many_arguments)]
mod entry_group {
    use zbus::proxy;

    #[proxy(
        interface = "org.freedesktop.Avahi.EntryGroup",
        default_service = "org.freedesktop.Avahi"
    )]
    pub(crate) trait EntryGroup {
        fn add_service(
            &self,
            interface: i32,
            protocol: i32,
            flags: u32,
            name: &str,
            type_: &str,
            domain: &str,
            host: &str,
            port: u16,
            txt: Vec<Vec<u8>>,
        ) -> zbus::Result<()>;

        fn add_service_subtype(
            &self,
            interface: i32,
            protocol: i32,
            flags: u32,
            name: &str,
            type_: &str,
            domain: &str,
            subtype: &str,
        ) -> zbus::Result<()>;

        fn add_address(
            &self,
            interface: i32,
            protocol: i32,
            flags: u32,
            name: &str,
            address: &str,
        ) -> zbus::Result<()>;

        fn commit(&self) -> zbus::Result<()>;

        fn free(&self) -> zbus::Result<()>;

        #[zbus(signal)]
        fn state_changed(&self, state: i32, error: String) -> zbus::Result<()>;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn avahis_rename_appends_two_or_counts_a_trailing_number_up() {
        for (label, called) in [
            ("widget", "widget-2"),
            ("widget", "widget-3"),
            ("mybox-123456", "mybox-123457"),
            ("mybox-0042", "mybox-0042-2"),
            ("mybox-012345", "mybox-012345-2"),
        ] {
            assert!(renamed_by_avahi(label, called), "{label} → {called}");
        }
        for (label, called) in [
            ("widget", "widget"),
            ("widget", "widget-1"),
            ("widget", "widget-"),
            ("widget", "widget-x"),
            ("widget", "gadget-2"),
            ("mybox-123456", "mybox-123456-2"),
            ("mybox-123456", "mybox-123455"),
            ("mybox-0042", "mybox-43"),
        ] {
            assert!(!renamed_by_avahi(label, called), "{label} → {called}");
        }
    }

    #[test]
    fn own_addresses_are_global_or_link_local_where_a_family_has_no_global_one() {
        let at = |i: u32, ip: &str| (i, ip.parse::<IpAddr>().unwrap());
        let own = own_addresses([
            at(2, "192.168.1.10"),
            at(2, "169.254.3.4"),
            at(2, "fe80::1"),
            at(3, "169.254.7.8"),
            at(3, "fe80::2"),
            at(3, "fd00::2"),
            at(2, "192.168.1.10"),
        ]);
        assert_eq!(
            own,
            [
                at(2, "192.168.1.10"),
                at(2, "fe80::1"),
                at(3, "169.254.7.8"),
                at(3, "fd00::2"),
            ]
        );
    }

    #[test]
    fn a_groups_state_is_an_adverts_and_a_collision_stays_one() {
        assert_eq!(group_state(0), None);
        assert_eq!(group_state(1), Some(AdvertState::Registering));
        assert_eq!(group_state(2), Some(AdvertState::Established));
        assert_eq!(group_state(3), Some(AdvertState::Collided));
        assert_eq!(group_state(4), Some(AdvertState::Failed));
    }
}
