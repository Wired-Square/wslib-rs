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
        let subtypes = service.subtypes_of_its_kind()?;
        let kind = service.kind.to_string();
        let name = service.instance.as_str();
        let txt = service
            .txt
            .iter()
            .map(|t| t.to_string().into_bytes())
            .collect();
        let group = Group::publish(&self.connection, async |group| {
            group
                .add_service(-1, -1, 0, name, &kind, "", "", service.port, txt)
                .await?;
            for subtype in subtypes {
                group
                    .add_service_subtype(-1, -1, 0, name, &kind, "", &subtype.to_string())
                    .await?;
            }
            Ok(())
        })
        .await?;
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
        addresses: &[(u32, IpAddr)],
    ) -> Result<Self, Error> {
        if addresses.is_empty() {
            return Err(Error::Unsupported("an address group with no addresses"));
        }
        let fqdn = name.fqdn();
        let group = Group::publish(connection, async |group| {
            for (interface, ip) in addresses {
                let interface = i32::try_from(*interface)
                    .map_err(|_| zbus::Error::Failure("interface index out of range".into()))?;
                let protocol = if ip.is_ipv4() { 0 } else { -1 };
                group
                    .add_address(interface, protocol, NO_REVERSE, &fqdn, &ip.to_string())
                    .await?;
            }
            Ok(())
        })
        .await?;
        Ok(Self(group))
    }

    pub fn state(&self) -> watch::Receiver<AdvertState> {
        self.0.state.clone()
    }

    pub async fn withdraw(self) -> Result<(), Error> {
        self.0.withdraw().await
    }
}

/// An entry group this connection holds, and the watch on its state.
#[derive(Debug)]
pub(crate) struct Group {
    proxy: Option<entry_group::EntryGroupProxy<'static>>,
    state: watch::Receiver<AdvertState>,
    watcher: AbortHandle,
}

impl Group {
    /// A new group, filled by `fill`, watched before it is committed so no
    /// state is missed; freed again if anything fails.
    async fn publish(
        connection: &Connection,
        fill: impl AsyncFnOnce(&entry_group::EntryGroupProxy<'static>) -> zbus::Result<()>,
    ) -> Result<Self, Error> {
        let group = async {
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
        let filled = async {
            let changes = group.receive_state_changed().await?;
            fill(&group).await?;
            group.commit().await?;
            zbus::Result::Ok(changes)
        };
        let mut changes = match filled.await {
            Ok(changes) => changes,
            Err(e) => {
                group.free().await.ok();
                return Err(bus_error(e));
            }
        };
        let (states, state) = watch::channel(AdvertState::Registering);
        let watcher = tokio::spawn(async move {
            while let Some(changed) = changes.next().await {
                if let Some(next) = changed.args().ok().and_then(|a| group_state(a.state)) {
                    states.send_replace(next);
                }
            }
        });
        Ok(Self {
            proxy: Some(group),
            state,
            watcher: watcher.abort_handle(),
        })
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
        self.watcher.abort();
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

fn bus_error(e: zbus::Error) -> Error {
    match &e {
        zbus::Error::MethodError(name, _, _)
            if name.as_str() == "org.freedesktop.Avahi.CollisionError" =>
        {
            Error::Collision
        }
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
pub async fn is_running(connection: &Connection) -> zbus::Result<bool> {
    let bus = zbus::fdo::DBusProxy::new(connection).await?;
    Ok(bus.name_has_owner(AVAHI.try_into()?).await?)
}

/// The label `.local` answers to now, avahi's rename of it after a collision included.
pub async fn host_name(connection: &Connection) -> zbus::Result<String> {
    server::AvahiProxy::new(connection)
        .await?
        .get_host_name()
        .await
}

/// The label `.local` answers to from now on, until avahi restarts; avahi
/// keeps this for root and the `netdev` group.
pub async fn set_host_name(connection: &Connection, name: &HostName) -> zbus::Result<()> {
    server::AvahiProxy::new(connection)
        .await?
        .set_host_name(name.as_str())
        .await
}

/// `true` each time an avahi takes the name, `false` each time one leaves
/// it; a new avahi holds none of the old one's groups.
pub async fn restarts(
    connection: &Connection,
) -> zbus::Result<impl Stream<Item = bool> + Unpin + Send + 'static> {
    let avahi = server::AvahiProxy::new(connection).await?;
    Ok(avahi
        .inner()
        .receive_owner_changed()
        .await?
        .map(|owner| owner.is_some()))
}

pub async fn server_states(
    connection: &Connection,
) -> zbus::Result<impl Stream<Item = ServerState> + Unpin + Send + 'static> {
    let avahi = server::AvahiProxy::new(connection).await?;
    Ok(avahi
        .receive_state_changed()
        .await?
        .filter_map(|changed| std::future::ready(changed.args().ok().map(|a| a.state.into()))))
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
    fn a_groups_state_is_an_adverts_and_a_collision_stays_one() {
        assert_eq!(group_state(0), None);
        assert_eq!(group_state(1), Some(AdvertState::Registering));
        assert_eq!(group_state(2), Some(AdvertState::Established));
        assert_eq!(group_state(3), Some(AdvertState::Collided));
        assert_eq!(group_state(4), Some(AdvertState::Failed));
    }
}
