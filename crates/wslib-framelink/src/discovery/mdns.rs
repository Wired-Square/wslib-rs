//! FrameLink's mDNS service types browsed in process, each by a task that
//! feeds the presence tracker. Presence is the tracker's: a removal is only
//! logged, since mdns-sd drops a cache entry on a missed verify or a stopped
//! browse while the device is still there.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tracing::{debug, warn};
use wslib_mdns::{Browse, BrowseEvent, InProcess, InstanceName, Options, Resolved, ServiceType};

use super::ErrorSource;
use super::presence::PresenceTracker;
use crate::{CapabilitySet, Device, DeviceId, Error, Transport};

/// Every known device is asked to answer this often, well inside the ~120 s
/// announcement TTL, so its entry never lapses while it is there.
const REFRESH_INTERVAL: Duration = Duration::from_secs(30);

/// Generous: a device evicted for a slow answer flaps `Lost` then `Seen`.
const VERIFY_TIMEOUT: Duration = Duration::from_secs(30);

/// A device just forgotten is asked at once, and briefly.
const FORGET_VERIFY_TIMEOUT: Duration = Duration::from_secs(2);

/// Each browse is stopped and restarted this often, which empties mdns-sd's
/// retransmission queue and puts a fresh query on the wire for devices that
/// booted since.
const REBROWSE_INTERVAL: Duration = Duration::from_secs(60);

/// Well under `MDNS_STALE_AFTER`, so `Lost` follows the boundary closely.
const STALENESS_SWEEP_INTERVAL: Duration = Duration::from_secs(2);

#[derive(Clone, Copy)]
struct ServiceSpec {
    /// As it ends a device's id.
    service_type: &'static str,
    transport: Transport,
    inferred_caps: CapabilitySet,
}

impl ServiceSpec {
    fn kind(&self) -> ServiceType {
        self.service_type
            .parse()
            .expect("the service types here are valid")
    }

    /// `mdns:<transport>:<instance>.<service type>`, so one device on both
    /// services is two ids.
    fn device_id(&self, instance: &str) -> DeviceId {
        DeviceId::new(format!(
            "mdns:{}:{instance}.{}",
            self.transport, self.service_type
        ))
    }

    fn instance_of<'a>(&self, id: &'a DeviceId) -> Option<&'a str> {
        id.as_str()
            .strip_prefix("mdns:")?
            .strip_prefix(self.transport.to_string().as_str())?
            .strip_prefix(':')?
            .strip_suffix(self.service_type)?
            .strip_suffix('.')
    }
}

const SERVICE_SPECS: [ServiceSpec; 2] = [
    // A transport announcement, claiming no capability.
    ServiceSpec {
        service_type: "_framelink._tcp.local.",
        transport: Transport::Tcp,
        inferred_caps: CapabilitySet::empty(),
    },
    ServiceSpec {
        service_type: "_mcumgr._udp.local.",
        transport: Transport::Udp,
        inferred_caps: CapabilitySet::SMP,
    },
];

/// Asks a browse to verify an instance now.
pub(super) struct Mdns {
    verify: Vec<(ServiceSpec, mpsc::UnboundedSender<InstanceName>)>,
}

impl Mdns {
    pub(super) fn verify_now(&self, id: &DeviceId) {
        for (spec, tx) in &self.verify {
            if let Some(instance) = spec.instance_of(id).and_then(|i| i.parse().ok()) {
                let _ = tx.send(instance);
            }
        }
    }
}

pub(super) fn start(
    tracker: Arc<Mutex<PresenceTracker>>,
) -> Result<(Mdns, Vec<JoinHandle<()>>), Error> {
    let responder = InProcess::new(Options::default())?;
    let mut verify = Vec::new();
    let mut tasks = Vec::new();
    for spec in SERVICE_SPECS {
        let browse = responder.browse(&spec.kind())?;
        let (tx, rx) = mpsc::unbounded_channel();
        verify.push((spec, tx));
        tasks.push(tokio::spawn(follow(
            responder.clone(),
            browse,
            spec,
            Arc::clone(&tracker),
            rx,
        )));
    }
    tasks.push(tokio::spawn(sweep_stale(tracker)));
    Ok((Mdns { verify }, tasks))
}

async fn follow(
    responder: InProcess,
    browse: Browse,
    spec: ServiceSpec,
    tracker: Arc<Mutex<PresenceTracker>>,
    mut verify_now: mpsc::UnboundedReceiver<InstanceName>,
) {
    let mut browse = Some(browse);
    let mut refresh = tokio::time::interval(REFRESH_INTERVAL);
    let mut rebrowse = tokio::time::interval(REBROWSE_INTERVAL);
    refresh.tick().await;
    rebrowse.tick().await;
    loop {
        tokio::select! {
            event = next_event(&mut browse) => match event {
                Some(BrowseEvent::Resolved(found)) => observe(&tracker, spec, &found),
                Some(BrowseEvent::Removed(instance)) => {
                    debug!(id = %spec.device_id(instance.as_str()), "removed (advisory)");
                }
                None => return,
            },
            _ = refresh.tick() => {
                let Some(browse) = &browse else { continue };
                let known: Vec<InstanceName> = tracker
                    .lock()
                    .expect("tracker lock")
                    .ids()
                    .filter_map(|id| spec.instance_of(id)?.parse().ok())
                    .collect();
                for instance in known {
                    if let Err(e) = browse.verify(&instance, VERIFY_TIMEOUT) {
                        debug!(%instance, error = %e, "verify refused");
                    }
                }
            }
            Some(instance) = verify_now.recv() => {
                if let Some(browse) = &browse {
                    browse.verify(&instance, FORGET_VERIFY_TIMEOUT).ok();
                }
            }
            _ = rebrowse.tick() => {
                drop(browse.take());
                browse = responder
                    .browse(&spec.kind())
                    .inspect_err(|e| debug!(service = spec.service_type, error = %e, "rebrowse refused"))
                    .ok();
            }
        }
    }
}

/// Waits forever while there is no browse, until the next rebrowse.
async fn next_event(browse: &mut Option<Browse>) -> Option<BrowseEvent> {
    match browse {
        Some(browse) => browse.next().await,
        None => std::future::pending().await,
    }
}

fn observe(tracker: &Mutex<PresenceTracker>, spec: ServiceSpec, found: &Resolved) {
    let mut tracker = tracker.lock().expect("tracker lock");
    match build_device(spec, found) {
        Some(device) => tracker.observe(device),
        None => {
            let msg = format!(
                "mDNS resolved {}.{} but no IPv4 address",
                found.instance, spec.service_type
            );
            warn!("{msg}");
            tracker.emit_error(ErrorSource::Mdns, msg);
        }
    }
}

/// `None` without an IPv4 address.
fn build_device(spec: ServiceSpec, found: &Resolved) -> Option<Device> {
    let addr = found.addrs.iter().find(|a| a.is_ipv4())?;
    let instance = found.instance.as_str();
    Some(
        Device::builder(spec.device_id(instance), instance)
            .transport(spec.transport)
            .capabilities(spec.inferred_caps)
            .address(SocketAddr::new(*addr, found.port))
            .build(),
    )
}

async fn sweep_stale(tracker: Arc<Mutex<PresenceTracker>>) {
    let mut tick = tokio::time::interval(STALENESS_SWEEP_INTERVAL);
    tick.tick().await;
    loop {
        tick.tick().await;
        tracker.lock().expect("tracker lock").evict_stale();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TCP: ServiceSpec = SERVICE_SPECS[0];
    const UDP: ServiceSpec = SERVICE_SPECS[1];

    fn resolved(instance: &str, addrs: &[&str]) -> Resolved {
        Resolved {
            instance: instance.parse().unwrap(),
            host: "wfl.local".into(),
            port: 120,
            addrs: addrs.iter().map(|a| a.parse().unwrap()).collect(),
            txt: Vec::new(),
        }
    }

    #[test]
    fn an_id_carries_the_transport_and_full_name() {
        assert_eq!(
            TCP.device_id("wfl-1234").as_str(),
            "mdns:tcp:wfl-1234._framelink._tcp.local."
        );
        assert_ne!(TCP.device_id("wfl-1234"), UDP.device_id("wfl-1234"));
    }

    #[test]
    fn an_id_gives_back_its_instance_for_its_own_service_only() {
        let id = UDP.device_id("WFL a.b");
        assert_eq!(UDP.instance_of(&id), Some("WFL a.b"));
        assert_eq!(TCP.instance_of(&id), None);
        assert_eq!(TCP.instance_of(&DeviceId::new("ble:abc")), None);
    }

    #[test]
    fn a_resolved_service_is_a_device_at_its_first_ipv4_address() {
        let device = build_device(UDP, &resolved("wfl-1234", &["fe80::1", "10.0.0.7"])).unwrap();
        assert_eq!(device.id(), &UDP.device_id("wfl-1234"));
        assert_eq!(device.name(), "wfl-1234");
        assert_eq!(device.transports(), &[Transport::Udp]);
        assert_eq!(device.capabilities(), CapabilitySet::SMP);
        assert_eq!(device.address(), Some("10.0.0.7:120".parse().unwrap()));
    }

    #[test]
    fn framelink_over_tcp_claims_no_capability() {
        let device = build_device(TCP, &resolved("wfl", &["10.0.0.7"])).unwrap();
        assert!(device.capabilities().is_empty());
    }

    #[test]
    fn a_service_with_no_ipv4_address_is_no_device() {
        assert!(build_device(TCP, &resolved("wfl", &["fe80::1"])).is_none());
    }

    #[test]
    fn a_device_with_no_ipv4_address_is_reported() {
        let (tx, mut rx) = tokio::sync::broadcast::channel(4);
        let tracker = Mutex::new(PresenceTracker::new(tx, Duration::from_secs(10)));
        observe(&tracker, TCP, &resolved("wfl", &["fe80::1"]));
        assert!(matches!(
            rx.try_recv(),
            Ok(super::super::DiscoveryEvent::Error {
                source: ErrorSource::Mdns,
                ..
            })
        ));
        assert!(tracker.lock().unwrap().snapshot().is_empty());
    }
}
