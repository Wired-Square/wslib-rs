use std::collections::HashSet;
use std::fmt;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use mdns_sd::{
    DaemonEvent, IfKind, IfPredicate, ResolvedService, ServiceDaemon, ServiceEvent, ServiceInfo,
};
use tokio::sync::watch;
use tokio::task::AbortHandle;

use crate::service::Held;
use crate::{
    Advert, AdvertState, BrowseEvent, Error, HostName, InstanceName, Resolved, Service,
    ServiceType, Txt,
};

/// Which interfaces the in-process responder answers and asks on.
#[derive(Clone, Default)]
pub enum Interfaces {
    #[default]
    All,
    Loopback,
    /// Those whose name the test accepts, such as `|name| !name.starts_with("docker")`.
    Matching(Arc<dyn Fn(&str) -> bool + Send + Sync>),
}

impl fmt::Debug for Interfaces {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::All => "All",
            Self::Loopback => "Loopback",
            Self::Matching(_) => "Matching(..)",
        })
    }
}

/// The host an in-process advert's address records name.
///
/// Beside a system responder (avahi, or mDNSResponder on macOS) an advert
/// claiming the machine's own `<host>.local` fights it for the name, so the
/// default is `<host>-<program>.local` and `System` is only for a machine
/// with no other responder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Host {
    System,
    Named(HostName),
}

impl Default for Host {
    fn default() -> Self {
        let program = std::env::current_exe()
            .ok()
            .and_then(|exe| exe.file_stem()?.to_str().map(str::to_string))
            .unwrap_or_else(|| "mdns".to_string());
        let name = HostName::nearest(&format!("{}-{program}", machine_name()));
        Self::Named(name.unwrap_or_else(machine_name))
    }
}

#[derive(Debug, Clone, Default)]
pub struct Options {
    pub interfaces: Interfaces,
    pub host: Host,
}

/// An mDNS responder and browser in this process, one daemon shared by every
/// advert and browse made from it and its clones.
#[derive(Debug, Clone)]
pub struct InProcess {
    shared: Arc<Shared>,
}

struct Shared {
    daemon: ServiceDaemon,
    host: String,
    held: Mutex<HashSet<String>>,
}

impl fmt::Debug for Shared {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Shared")
            .field("host", &self.host)
            .finish_non_exhaustive()
    }
}

impl Drop for Shared {
    fn drop(&mut self) {
        self.daemon.shutdown().ok();
    }
}

impl Shared {
    fn hold(&self, name: &str) -> Result<(), Error> {
        if !self.held.lock().unwrap().insert(name.to_lowercase()) {
            return Err(Error::Unsupported("the same advert or browse twice"));
        }
        Ok(())
    }

    fn release(&self, name: &str) {
        self.held.lock().unwrap().remove(&name.to_lowercase());
    }
}

impl InProcess {
    pub fn new(options: Options) -> Result<Self, Error> {
        let daemon = ServiceDaemon::new().map_err(daemon_error)?;
        let only = match options.interfaces {
            Interfaces::All => None,
            Interfaces::Loopback => Some(vec![IfKind::LoopbackV4, IfKind::LoopbackV6]),
            Interfaces::Matching(test) => Some(vec![IfKind::Predicate(IfPredicate::new(
                move |interface| test(&interface.name),
            ))]),
        };
        if let Some(only) = only {
            daemon
                .disable_interface(IfKind::All)
                .map_err(daemon_error)?;
            daemon.enable_interface(only).map_err(daemon_error)?;
        }
        let host = match options.host {
            Host::System => machine_name(),
            Host::Named(name) => name,
        };
        Ok(Self {
            shared: Arc::new(Shared {
                daemon,
                host: format!("{}.", host.fqdn()),
                held: Mutex::default(),
            }),
        })
    }

    /// Advertises `service` with this host's addresses as they come and go;
    /// mdns-sd takes one subtype per advert.
    pub async fn advertise(&self, service: &Service) -> Result<Advert, Error> {
        let kind = service.kind.fqdn();
        let registered_as = match service.subtypes_of_its_kind()? {
            [] => kind.clone(),
            [subtype] => format!("{subtype}.local."),
            _ => return Err(Error::Unsupported("more than one subtype in process")),
        };
        let txt: Vec<(&str, &str)> = service.txt.iter().map(|t| (t.key(), t.value())).collect();
        let info = ServiceInfo::new(
            &registered_as,
            service.instance.as_str(),
            &self.shared.host,
            (),
            service.port,
            &txt[..],
        )
        .map_err(daemon_error)?
        .enable_addr_auto();
        let fullname = info.get_fullname().to_string();
        let monitor = self.shared.daemon.monitor().map_err(daemon_error)?;
        self.shared.hold(&fullname)?;
        if let Err(e) = self.shared.daemon.register(info) {
            self.shared.release(&fullname);
            return Err(daemon_error(e));
        }
        let (states, state) = watch::channel(AdvertState::Registering);
        let watched = fullname.clone();
        let watcher = tokio::spawn(async move {
            while let Ok(event) = monitor.recv_async().await {
                states.send_if_modified(|state| match next_state(&watched, &kind, state, &event) {
                    Some(next) if next != *state => {
                        *state = next;
                        true
                    }
                    _ => false,
                });
            }
        });
        Ok(Advert {
            state,
            held: Held::InProcess(Registered {
                shared: self.shared.clone(),
                fullname: Some(fullname),
                watcher: watcher.abort_handle(),
            }),
        })
    }

    /// Browses for `kind` until the [`Browse`] is dropped; one browse per type at a time.
    pub fn browse(&self, kind: &ServiceType) -> Result<Browse, Error> {
        let fqdn = kind.fqdn();
        self.shared.hold(&fqdn)?;
        let events = self.shared.daemon.browse(&fqdn).map_err(|e| {
            self.shared.release(&fqdn);
            daemon_error(e)
        })?;
        Ok(Browse {
            shared: self.shared.clone(),
            fqdn,
            events,
        })
    }
}

/// A browse for one service type, stopped when dropped.
#[derive(Debug)]
pub struct Browse {
    shared: Arc<Shared>,
    fqdn: String,
    events: mdns_sd::Receiver<ServiceEvent>,
}

impl Browse {
    /// The next instance resolved or removed; `None` once the responder stops.
    pub async fn next(&mut self) -> Option<BrowseEvent> {
        loop {
            let event = self.events.recv_async().await.ok()?;
            if let Some(event) = browse_event(&self.fqdn, event) {
                return Some(event);
            }
        }
    }

    /// Asks `instance` to answer within `timeout`, removing it if it does not.
    pub fn verify(&self, instance: &InstanceName, timeout: Duration) -> Result<(), Error> {
        let fullname = format!("{}.{}", escape(instance.as_str()), self.fqdn);
        self.shared
            .daemon
            .verify(fullname, timeout)
            .map_err(daemon_error)
    }
}

impl Drop for Browse {
    fn drop(&mut self) {
        self.shared.daemon.stop_browse(&self.fqdn).ok();
        self.shared.release(&self.fqdn);
    }
}

#[derive(Debug)]
pub(crate) struct Registered {
    shared: Arc<Shared>,
    fullname: Option<String>,
    watcher: AbortHandle,
}

impl Registered {
    pub(crate) async fn withdraw(mut self) -> Result<(), Error> {
        let Some(fullname) = self.fullname.take() else {
            return Ok(());
        };
        let done = self.shared.daemon.unregister(&fullname);
        self.shared.release(&fullname);
        done.map_err(daemon_error)?.recv_async().await.ok();
        Ok(())
    }
}

impl Drop for Registered {
    fn drop(&mut self) {
        self.watcher.abort();
        if let Some(fullname) = self.fullname.take() {
            self.shared.daemon.unregister(&fullname).ok();
            self.shared.release(&fullname);
        }
    }
}

fn daemon_error(e: mdns_sd::Error) -> Error {
    Error::Daemon(e.to_string())
}

fn machine_name() -> HostName {
    HostName::nearest(&os_host_name()).unwrap_or_else(|| "host".parse().unwrap())
}

#[cfg(unix)]
fn os_host_name() -> String {
    let mut buf = [0u8; 256];
    // SAFETY: `buf` is writable for its whole length, which is what is passed.
    let ok = unsafe { libc::gethostname(buf.as_mut_ptr().cast(), buf.len()) } == 0;
    let name = if ok { &buf[..] } else { &[] };
    let end = name
        .iter()
        .position(|&b| b == 0 || b == b'.')
        .unwrap_or(name.len());
    String::from_utf8_lossy(&name[..end]).into_owned()
}

#[cfg(not(unix))]
fn os_host_name() -> String {
    std::env::var("COMPUTERNAME").unwrap_or_default()
}

/// The advert's state after `event`, for the advert registered as `fullname`
/// of `kind`; `None` when the event is not about it.
fn next_state(
    fullname: &str,
    kind: &str,
    state: &AdvertState,
    event: &DaemonEvent,
) -> Option<AdvertState> {
    match event {
        DaemonEvent::NameChange(change) if change.original.eq_ignore_ascii_case(fullname) => {
            let instance = instance_of(&change.new_name, kind)?;
            unescape(instance).parse().ok().map(AdvertState::Renamed)
        }
        DaemonEvent::Announce(name, _)
            if name.eq_ignore_ascii_case(fullname) && *state == AdvertState::Registering =>
        {
            Some(AdvertState::Established)
        }
        _ => None,
    }
}

fn browse_event(kind: &str, event: ServiceEvent) -> Option<BrowseEvent> {
    match event {
        ServiceEvent::ServiceResolved(found) => resolved(kind, &found).map(BrowseEvent::Resolved),
        ServiceEvent::ServiceRemoved(_, fullname) => instance_of(&fullname, kind)?
            .parse()
            .ok()
            .map(BrowseEvent::Removed),
        _ => None,
    }
}

fn resolved(kind: &str, found: &ResolvedService) -> Option<Resolved> {
    let mut addrs: Vec<IpAddr> = found.addresses.iter().map(|a| a.to_ip_addr()).collect();
    addrs.sort();
    addrs.dedup();
    let txt = found
        .txt_properties
        .iter()
        .filter_map(|p| {
            Txt::new(
                p.key(),
                &String::from_utf8_lossy(p.val().unwrap_or_default()),
            )
            .ok()
        })
        .collect();
    Some(Resolved {
        instance: instance_of(&found.fullname, kind)?.parse().ok()?,
        host: found.host.trim_end_matches('.').to_string(),
        port: found.port,
        addrs,
        txt,
    })
}

/// The instance label of `fullname`, as it came off the wire, without `.kind`.
fn instance_of<'a>(fullname: &'a str, kind: &str) -> Option<&'a str> {
    let at = fullname.len().checked_sub(kind.len() + 1)?;
    let (instance, suffix) = (fullname.get(..at)?, fullname.get(at..)?);
    (suffix.starts_with('.') && suffix[1..].eq_ignore_ascii_case(kind)).then_some(instance)
}

fn escape(instance: &str) -> String {
    instance.replace('\\', "\\\\").replace('.', "\\.")
}

fn unescape(instance: &str) -> String {
    let mut out = String::with_capacity(instance.len());
    let mut chars = instance.chars();
    while let Some(c) = chars.next() {
        out.push(match c {
            '\\' => chars.next().unwrap_or('\\'),
            c => c,
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use mdns_sd::{DnsNameChange, RRType};

    use super::*;

    const KIND: &str = "_http._tcp.local.";

    fn name_change(original: &str, new_name: &str) -> DaemonEvent {
        DaemonEvent::NameChange(DnsNameChange {
            original: original.to_string(),
            new_name: new_name.to_string(),
            rr_type: RRType::SRV,
            intf_name: "en0".to_string(),
        })
    }

    #[test]
    fn an_advert_is_established_when_announced_and_renamed_when_mdns_sd_renames_it() {
        let ours = "Widget\\.1._http._tcp.local.";
        let announced = DaemonEvent::Announce(ours.to_string(), "en0".to_string());
        assert_eq!(
            next_state(ours, KIND, &AdvertState::Registering, &announced),
            Some(AdvertState::Established)
        );

        let renamed = name_change(ours, "Widget\\.1 (2)._http._tcp.local.");
        let state = next_state(ours, KIND, &AdvertState::Registering, &renamed).unwrap();
        assert_eq!(state, AdvertState::Renamed("Widget.1 (2)".parse().unwrap()));
        let again = DaemonEvent::Announce("Widget\\.1 (2)._http._tcp.local.".into(), "en0".into());
        assert_eq!(
            next_state(ours, KIND, &state, &again),
            None,
            "a rename is kept once announced"
        );
    }

    #[test]
    fn events_about_other_names_leave_an_advert_alone() {
        let ours = "Widget._http._tcp.local.";
        for event in [
            DaemonEvent::Announce("Gadget._http._tcp.local.".into(), "en0".into()),
            name_change("box.local.", "box-2.local."),
            DaemonEvent::IpAdd("192.168.1.10".parse().unwrap()),
        ] {
            assert_eq!(
                next_state(ours, KIND, &AdvertState::Registering, &event),
                None,
                "{event:?}"
            );
        }
    }

    #[test]
    fn a_resolved_service_carries_its_instance_host_addresses_and_txt() {
        let info = ServiceInfo::new(
            KIND,
            "Pumpe für Halle 3",
            "widget.local.",
            "192.168.1.10,fe80::1,192.168.1.10",
            8080,
            &[("product", "widget"), ("flag", "")][..],
        )
        .unwrap();
        let event = ServiceEvent::ServiceResolved(Box::new(info.as_resolved_service()));
        let Some(BrowseEvent::Resolved(found)) = browse_event(KIND, event) else {
            panic!("not resolved");
        };
        assert_eq!(found.instance.as_str(), "Pumpe für Halle 3");
        assert_eq!(found.host, "widget.local");
        assert_eq!(found.port, 8080);
        assert_eq!(
            found.addrs,
            [
                "192.168.1.10".parse::<IpAddr>().unwrap(),
                "fe80::1".parse().unwrap()
            ]
        );
        assert_eq!(found.txt("PRODUCT"), Some("widget"));
        assert_eq!(found.txt("flag"), Some(""));
    }

    #[test]
    fn a_removal_names_the_instance_as_it_came_off_the_wire() {
        let removed = ServiceEvent::ServiceRemoved(KIND.into(), "a.b._HTTP._tcp.local.".into());
        assert_eq!(
            browse_event(KIND, removed),
            Some(BrowseEvent::Removed("a.b".parse().unwrap()))
        );
        let other = ServiceEvent::ServiceRemoved(KIND.into(), "a._ipp._tcp.local.".into());
        assert_eq!(browse_event(KIND, other), None);
        assert_eq!(
            browse_event(KIND, ServiceEvent::SearchStarted(KIND.into())),
            None
        );
    }

    #[test]
    fn escaping_round_trips() {
        for name in ["plain", "a.b", "back\\slash", "a\\.b"] {
            assert_eq!(unescape(&escape(name)), name);
        }
    }

    #[test]
    fn the_default_host_is_never_the_machines_own_name() {
        let Host::Named(name) = Host::default() else {
            panic!("the default claims the machine's own name");
        };
        assert_ne!(name, machine_name());
    }
}
