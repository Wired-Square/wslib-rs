//! FrameLink devices found over mDNS and, with `ble`, over BLE, as one stream
//! of [`DiscoveryEvent`]s.
//!
//! ```no_run
//! # async fn run() -> Result<(), wslib_framelink::Error> {
//! use futures_util::StreamExt;
//! use wslib_framelink::{Discovery, DiscoveryEvent};
//!
//! let discovery = Discovery::start().await?;
//! let mut events = discovery.events();
//! while let Some(event) = events.next().await {
//!     if let DiscoveryEvent::Seen { device } = event {
//!         println!("{} at {:?}", device.name(), device.address());
//!     }
//! }
//! # Ok(()) }
//! ```

#[cfg(feature = "ble")]
pub(crate) mod ble;
mod events;
mod legacy;
mod mdns;
mod presence;
#[cfg(feature = "smp")]
mod smp;

pub use events::{DiscoveryEvent, ErrorSource};
pub use legacy::{FrameLinkDevice, discover};
#[cfg(feature = "smp")]
pub use smp::{OtaEvent, OtaOptions, OtaStream, ota_udp_addr};

use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures_util::Stream;
use tokio::sync::broadcast;
use tokio::task::JoinHandle;
use wslib_mdns::{InProcess, Options};

use crate::{Device, DeviceId, Error, Transport};
use presence::PresenceTracker;

/// Enough for a few hundred unread events; a subscriber further behind
/// misses the oldest.
const EVENT_CHANNEL_CAPACITY: usize = 256;

const RESOLVE_POLL_INTERVAL: Duration = Duration::from_millis(250);

/// An init that fails is tried this many times, its waits doubling from a
/// quarter second to `INIT_MAX_BACKOFF`: about 16 seconds in all.
const INIT_MAX_ATTEMPTS: u32 = 6;
const INIT_MAX_BACKOFF: Duration = Duration::from_secs(8);

/// A running discovery; clones share it, and it stops when the last drops.
#[derive(Clone)]
pub struct Discovery {
    inner: Arc<DiscoveryInner>,
}

struct DiscoveryInner {
    tracker: Arc<Mutex<PresenceTracker>>,
    event_tx: broadcast::Sender<DiscoveryEvent>,
    tasks: Mutex<Vec<JoinHandle<()>>>,
    mdns: Option<mdns::Mdns>,
    #[cfg(feature = "ble")]
    ble_store: Arc<ble::BlePeripheralStore>,
    /// A device's open sessions; repeated opens share them.
    #[cfg(any(feature = "wifi-prov", feature = "smp"))]
    sessions: tokio::sync::Mutex<std::collections::HashMap<DeviceId, ActiveSessions>>,
}

/// Each session holds the device's BLE lease; the link closes when the last
/// is dropped.
#[cfg(any(feature = "wifi-prov", feature = "smp"))]
#[derive(Default)]
struct ActiveSessions {
    #[cfg(feature = "wifi-prov")]
    wifi_prov: Option<Arc<crate::ble::wifi_prov::WifiProvSession>>,
    #[cfg(feature = "smp")]
    smp: Option<Arc<wslib_mcumgr::Session>>,
}

impl Discovery {
    /// Starts every transport, retrying a failed start with backoff. From
    /// then on it keeps re-verifying devices so a stationary one stays seen,
    /// and respawns a scanner that exits, reporting each as an `Error` event.
    pub async fn start() -> Result<Self, Error> {
        Self::start_on(|| Ok(InProcess::new(Options::default())?)).await
    }

    /// [`start`](Self::start), browsing on `responder` instead of a responder
    /// of its own.
    pub async fn start_with(responder: InProcess) -> Result<Self, Error> {
        Self::start_on(|| Ok(responder.clone())).await
    }

    async fn start_on(responder: impl Fn() -> Result<InProcess, Error>) -> Result<Self, Error> {
        let (event_tx, _) = broadcast::channel(EVENT_CHANNEL_CAPACITY);
        let tracker = Arc::new(Mutex::new(PresenceTracker::new(
            event_tx.clone(),
            presence::DEFAULT_STALE_AFTER,
        )));
        let (mdns, tasks) =
            init_with_backoff("mDNS responder", &event_tx, ErrorSource::Mdns, || async {
                mdns::start(responder()?, Arc::clone(&tracker))
            })
            .await?;
        let discovery = Self::with(tracker, event_tx, tasks, Some(mdns));

        #[cfg(feature = "ble")]
        {
            let inner = &discovery.inner;
            let adapter = init_with_backoff(
                "BLE adapter",
                &inner.event_tx,
                ErrorSource::Ble,
                crate::ble::default_adapter,
            )
            .await?;
            let scanner = spawn_supervised_ble_scanner(
                adapter,
                Arc::clone(&inner.tracker),
                Arc::clone(&inner.ble_store),
                inner.event_tx.clone(),
            );
            inner.tasks.lock().expect("tasks lock").push(scanner);
        }
        Ok(discovery)
    }

    fn with(
        tracker: Arc<Mutex<PresenceTracker>>,
        event_tx: broadcast::Sender<DiscoveryEvent>,
        tasks: Vec<JoinHandle<()>>,
        mdns: Option<mdns::Mdns>,
    ) -> Self {
        Self {
            inner: Arc::new(DiscoveryInner {
                tracker,
                event_tx,
                tasks: Mutex::new(tasks),
                mdns,
                #[cfg(feature = "ble")]
                ble_store: Arc::default(),
                #[cfg(any(feature = "wifi-prov", feature = "smp"))]
                sessions: tokio::sync::Mutex::default(),
            }),
        }
    }

    /// Events from now on; each call is a subscriber of its own.
    pub fn events(&self) -> impl Stream<Item = DiscoveryEvent> + Send + Unpin + 'static {
        let rx = self.inner.event_tx.subscribe();
        Box::pin(futures_util::stream::unfold(rx, |mut rx| async move {
            loop {
                match rx.recv().await {
                    Ok(event) => return Some((event, rx)),
                    Err(broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(broadcast::error::RecvError::Closed) => return None,
                }
            }
        }))
    }

    pub async fn devices(&self) -> Vec<Device> {
        self.tracker().snapshot()
    }

    pub async fn get(&self, id: &DeviceId) -> Option<Device> {
        self.tracker().get(id)
    }

    /// `id` itself if seen, else the device of its [`canonical_name`] on
    /// `transport`.
    ///
    /// [`canonical_name`]: crate::registry::canonical_name
    pub async fn resolve_live_id(
        &self,
        id: &DeviceId,
        transport: Transport,
    ) -> Result<DeviceId, Error> {
        if self.get(id).await.is_some() {
            return Ok(id.clone());
        }
        let name = crate::registry::canonical_name(id.as_str());
        self.devices()
            .await
            .into_iter()
            .find(|d| d.name() == name && d.transports().contains(&transport))
            .map(|d| d.id().clone())
            .ok_or_else(|| Error::UnknownDevice(id.clone()))
    }

    /// [`resolve_live_id`](Self::resolve_live_id), waiting up to `deadline`
    /// for the device to be seen.
    pub async fn resolve_live_id_within(
        &self,
        id: &DeviceId,
        transport: Transport,
        deadline: Duration,
    ) -> Result<DeviceId, Error> {
        let poll = async {
            loop {
                if let Ok(live) = self.resolve_live_id(id, transport).await {
                    return live;
                }
                tokio::time::sleep(RESOLVE_POLL_INTERVAL).await;
            }
        };
        tokio::time::timeout(deadline, poll)
            .await
            .map_err(|_| Error::UnknownDevice(id.clone()))
    }

    /// Drops the device as `Lost` now; an mDNS one is asked to answer at
    /// once, so that if it is still there it is `Seen` again promptly.
    pub fn forget(&self, id: &DeviceId) {
        self.tracker().forget(id);
        if let Some(mdns) = &self.inner.mdns {
            mdns.verify_now(id);
        }
    }

    fn tracker(&self) -> std::sync::MutexGuard<'_, PresenceTracker> {
        self.inner.tracker.lock().expect("tracker lock")
    }
}

#[cfg(feature = "wifi-prov")]
impl Discovery {
    /// A provisioning session on a device seen over BLE that advertises
    /// `WIFI_PROV`; a session already open and still connected is shared.
    pub async fn open_wifi_prov(
        &self,
        id: &DeviceId,
    ) -> Result<Arc<crate::ble::wifi_prov::WifiProvSession>, Error> {
        let mut sessions = self.inner.sessions.lock().await;
        let active = sessions.entry(id.clone()).or_default();
        if let Some(existing) = active.wifi_prov.as_ref() {
            if existing.is_connected().await {
                return Ok(Arc::clone(existing));
            }
            tracing::debug!(id = %id, "cached wifi-prov session disconnected; re-opening");
            active.wifi_prov = None;
        }
        let lease = self
            .resolve_ble_lease(id, crate::Capability::WifiProv)
            .await?;
        let session = Arc::new(crate::ble::wifi_prov::open_session(lease).await?);
        active.wifi_prov = Some(Arc::clone(&session));
        Ok(session)
    }
}

#[cfg(any(feature = "wifi-prov", feature = "smp"))]
impl Discovery {
    /// Drops the device's sessions; its BLE link closes once nothing in
    /// flight holds one.
    pub async fn release_device(&self, id: &DeviceId) {
        self.inner.sessions.lock().await.remove(id);
    }
}

#[cfg(any(feature = "wifi-prov", all(feature = "smp", feature = "ble")))]
impl Discovery {
    async fn resolve_ble_lease(
        &self,
        id: &DeviceId,
        capability: crate::Capability,
    ) -> Result<Arc<ble::PeripheralLease>, Error> {
        let device = self
            .get(id)
            .await
            .ok_or_else(|| Error::UnknownDevice(id.clone()))?;
        if !device.transports().contains(&Transport::Ble) {
            return Err(Error::WrongTransport {
                id: id.clone(),
                required: Transport::Ble,
            });
        }
        if !device
            .capabilities()
            .contains(crate::CapabilitySet::from(capability))
        {
            return Err(Error::CapabilityNotAdvertised {
                id: id.clone(),
                capability,
            });
        }
        self.inner
            .ble_store
            .acquire_lease(id)
            .await
            .ok_or_else(|| Error::BleHandleUnavailable(id.clone()))
    }
}

/// Each failure is reported as an `Error` event, for a subscriber already
/// listening.
async fn init_with_backoff<T, F, Fut>(
    label: &'static str,
    event_tx: &broadcast::Sender<DiscoveryEvent>,
    source: ErrorSource,
    mut init: F,
) -> Result<T, Error>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, Error>>,
{
    let mut delay = Duration::from_millis(250);
    let mut attempt = 1;
    loop {
        match init().await {
            Ok(v) => return Ok(v),
            Err(e) => {
                tracing::warn!(attempt, error = %e, "{label} init failed");
                let _ = event_tx.send(DiscoveryEvent::Error {
                    source,
                    message: format!("{label} init attempt {attempt} failed: {e}"),
                });
                if attempt == INIT_MAX_ATTEMPTS {
                    return Err(e);
                }
                tokio::time::sleep(delay).await;
                delay = (delay * 2).min(INIT_MAX_BACKOFF);
                attempt += 1;
            }
        }
    }
}

/// Respawns the scanner whenever it exits, as when the adapter goes, until
/// the adapter cannot be had back.
#[cfg(feature = "ble")]
fn spawn_supervised_ble_scanner(
    adapter: btleplug::platform::Adapter,
    tracker: Arc<Mutex<PresenceTracker>>,
    store: Arc<ble::BlePeripheralStore>,
    event_tx: broadcast::Sender<DiscoveryEvent>,
) -> JoinHandle<()> {
    let first = ble::spawn_scanner(adapter, Arc::clone(&tracker), Arc::clone(&store));
    crate::runtime::ble_runtime().spawn(async move {
        let mut current = first;
        loop {
            let _ = current.await;
            let _ = event_tx.send(DiscoveryEvent::Error {
                source: ErrorSource::Ble,
                message: "BLE scanner exited; respawning".to_owned(),
            });
            let adapter = match init_with_backoff(
                "BLE adapter",
                &event_tx,
                ErrorSource::Ble,
                crate::ble::default_adapter,
            )
            .await
            {
                Ok(a) => a,
                Err(e) => {
                    let _ = event_tx.send(DiscoveryEvent::Error {
                        source: ErrorSource::Ble,
                        message: format!("BLE adapter re-acquire gave up: {e}"),
                    });
                    return;
                }
            };
            current = ble::spawn_scanner(adapter, Arc::clone(&tracker), Arc::clone(&store));
        }
    })
}

impl Drop for DiscoveryInner {
    fn drop(&mut self) {
        if let Ok(mut tasks) = self.tasks.lock() {
            for handle in tasks.drain(..) {
                handle.abort();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CapabilitySet;
    use futures_util::StreamExt;

    impl Discovery {
        pub(crate) fn idle() -> Self {
            let (event_tx, _) = broadcast::channel(EVENT_CHANNEL_CAPACITY);
            let tracker = PresenceTracker::new(event_tx.clone(), presence::DEFAULT_STALE_AFTER);
            Self::with(Arc::new(Mutex::new(tracker)), event_tx, Vec::new(), None)
        }

        fn observe(&self, device: Device) {
            self.tracker().observe(device);
        }
    }

    fn ble_dev(id: &str, name: &str, rssi: i16) -> Device {
        Device::builder(id, name)
            .transport(Transport::Ble)
            .capabilities(CapabilitySet::SMP)
            .rssi(rssi)
            .build()
    }

    fn udp_dev(id: &str, name: &str) -> Device {
        Device::builder(id, name)
            .transport(Transport::Udp)
            .capabilities(CapabilitySet::SMP)
            .address("10.0.0.7:1337".parse().unwrap())
            .build()
    }

    async fn next(events: &mut (impl Stream<Item = DiscoveryEvent> + Unpin)) -> DiscoveryEvent {
        tokio::time::timeout(Duration::from_millis(100), events.next())
            .await
            .expect("event delivered")
            .expect("stream open")
    }

    #[tokio::test]
    async fn events_stream_receives_seen_events() {
        let discovery = Discovery::idle();
        let mut events = discovery.events();
        discovery.observe(ble_dev("ble:abc", "WFL", -50));
        assert!(
            matches!(next(&mut events).await, DiscoveryEvent::Seen { device } if device.id().as_str() == "ble:abc")
        );
    }

    #[tokio::test]
    async fn devices_snapshot_reflects_observations() {
        let discovery = Discovery::idle();
        discovery.observe(ble_dev("ble:abc", "A", -50));
        discovery.observe(ble_dev("ble:def", "B", -60));
        assert_eq!(discovery.devices().await.len(), 2);
    }

    #[tokio::test]
    async fn get_returns_a_known_device_and_none_for_others() {
        let discovery = Discovery::idle();
        discovery.observe(ble_dev("ble:abc", "WFL", -50));
        let dev = discovery.get(&DeviceId::new("ble:abc")).await.unwrap();
        assert_eq!(dev.name(), "WFL");
        assert!(discovery.get(&DeviceId::new("ble:nope")).await.is_none());
    }

    #[tokio::test]
    async fn resolve_live_id_matches_verbatim_then_by_name_and_transport() {
        let discovery = Discovery::idle();
        let live = "mdns:udp:wfl-1234._mcumgr._udp.local.";
        discovery.observe(udp_dev(live, "WFL-1234"));

        let by_id = discovery
            .resolve_live_id(&DeviceId::new(live), Transport::Udp)
            .await
            .unwrap();
        assert_eq!(by_id.as_str(), live);

        let by_name = discovery
            .resolve_live_id(&DeviceId::from("udp:WFL-1234"), Transport::Udp)
            .await
            .unwrap();
        assert_eq!(by_name.as_str(), live);

        let err = discovery
            .resolve_live_id(&DeviceId::from("udp:NOPE"), Transport::Udp)
            .await;
        assert!(matches!(err, Err(Error::UnknownDevice(_))));
    }

    #[tokio::test]
    async fn resolve_live_id_within_returns_once_present() {
        let discovery = Discovery::idle();
        discovery.observe(udp_dev("mdns:udp:wfl-z._mcumgr._udp.local.", "WFL-Z"));
        let id = discovery
            .resolve_live_id_within(
                &DeviceId::from("udp:WFL-Z"),
                Transport::Udp,
                Duration::from_secs(5),
            )
            .await
            .unwrap();
        assert_eq!(id.as_str(), "mdns:udp:wfl-z._mcumgr._udp.local.");
    }

    #[tokio::test]
    async fn resolve_live_id_within_times_out_when_absent() {
        let discovery = Discovery::idle();
        let err = discovery
            .resolve_live_id_within(
                &DeviceId::from("udp:NOPE"),
                Transport::Udp,
                Duration::from_millis(200),
            )
            .await;
        assert!(matches!(err, Err(Error::UnknownDevice(_))));
    }

    #[tokio::test]
    async fn multiple_subscribers_each_receive_events() {
        let discovery = Discovery::idle();
        let mut a = discovery.events();
        let mut b = discovery.events();
        discovery.observe(ble_dev("ble:abc", "WFL", -50));
        assert!(matches!(next(&mut a).await, DiscoveryEvent::Seen { .. }));
        assert!(matches!(next(&mut b).await, DiscoveryEvent::Seen { .. }));
    }

    #[tokio::test]
    async fn forget_emits_lost_to_subscribers() {
        let discovery = Discovery::idle();
        discovery.observe(ble_dev("ble:abc", "WFL", -50));
        let mut events = discovery.events();
        discovery.forget(&DeviceId::new("ble:abc"));
        assert!(
            matches!(next(&mut events).await, DiscoveryEvent::Lost { id } if id.as_str() == "ble:abc")
        );
    }

    #[tokio::test]
    async fn a_lagging_subscriber_skips_to_what_it_can_still_read() {
        let discovery = Discovery::idle();
        let mut events = discovery.events();
        for i in 0..=EVENT_CHANNEL_CAPACITY {
            discovery.observe(ble_dev(&format!("ble:{i}"), "WFL", -50));
        }
        assert!(
            matches!(next(&mut events).await, DiscoveryEvent::Seen { device } if device.id().as_str() == "ble:1")
        );
    }
}
