//! SMP (mcumgr) sessions on discovered devices, and the firmware update that
//! runs over one: upload, test, reset, reconnect, verify, confirm.

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use futures_util::{Stream, StreamExt};
use tokio::sync::mpsc;
use wslib_mcumgr::Session;

use super::{Discovery, DiscoveryEvent};
use crate::registry::{self, ConnectTarget};
use crate::{CapabilitySet, DeviceId, Error, Transport};

/// A just-started discovery may not have seen the device yet.
const RESOLVE_DISCOVERY_TIMEOUT: Duration = Duration::from_secs(15);

const OTA_EVENT_CHANNEL_CAPACITY: usize = 32;

/// A device back on Wi-Fi and re-announced over mDNS takes 18 to 30 seconds.
const DEFAULT_RECONNECT_TIMEOUT: Duration = Duration::from_secs(60);

const UDP_RECONNECT_POLL_INTERVAL: Duration = Duration::from_millis(500);

#[derive(Clone, Debug)]
pub struct OtaOptions {
    /// How long the device may take to come back after its reset.
    pub reconnect_timeout: Duration,
}

impl Default for OtaOptions {
    fn default() -> Self {
        Self {
            reconnect_timeout: DEFAULT_RECONNECT_TIMEOUT,
        }
    }
}

/// The stages of a firmware update, in order; `Confirmed` ends one that
/// succeeded.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum OtaEvent {
    SessionOpened,
    UploadProgress(wslib_mcumgr::UploadProgress),
    Activating,
    /// The image will boot on the next reset.
    Activated {
        hash: Vec<u8>,
    },
    Resetting,
    /// The device may have restarted before it answered.
    ResetSent,
    Reconnecting {
        name: String,
    },
    /// The device's id may differ from before the reset.
    Reconnected {
        device_id: DeviceId,
    },
    Verified {
        active_hash: Vec<u8>,
    },
    Confirming,
    Confirmed,
}

pub type OtaStream = Pin<Box<dyn Stream<Item = Result<OtaEvent, Error>> + Send + 'static>>;

impl Discovery {
    /// An SMP session over UDP to a device seen as `_mcumgr._udp`. Uploads
    /// keep the UDP chunk size: the buffer size a device reports is sized for
    /// BLE and would fragment a datagram.
    pub async fn open_smp_udp(&self, id: &DeviceId) -> Result<Arc<Session>, Error> {
        let mut sessions = self.inner.sessions.lock().await;
        let active = sessions.entry(id.clone()).or_default();
        if let Some(existing) = &active.smp {
            return Ok(Arc::clone(existing));
        }
        let wrong_transport = || Error::WrongTransport {
            id: id.clone(),
            required: Transport::Udp,
        };
        let device = self
            .get(id)
            .await
            .ok_or_else(|| Error::UnknownDevice(id.clone()))?;
        if !device.transports().contains(&Transport::Udp) {
            return Err(wrong_transport());
        }
        let addr = device.address().ok_or_else(wrong_transport)?;
        let session = Arc::new(Session::connect_udp(addr).await?);
        active.smp = Some(Arc::clone(&session));
        Ok(session)
    }

    /// An SMP session over BLE to a device that advertises `SMP`, sharing
    /// the link with the device's other sessions.
    #[cfg(feature = "ble")]
    pub async fn open_smp_ble(&self, id: &DeviceId) -> Result<Arc<Session>, Error> {
        use wslib_mcumgr::ble::{BleTransport, SMP_CHARACTERISTIC_UUID};

        let mut sessions = self.inner.sessions.lock().await;
        let active = sessions.entry(id.clone()).or_default();
        if let Some(existing) = &active.smp {
            if existing.is_connected().await {
                return Ok(Arc::clone(existing));
            }
            tracing::debug!(id = %id, "cached SMP session disconnected; re-opening");
            active.smp = None;
        }
        let lease = self.resolve_ble_lease(id, crate::Capability::Smp).await?;
        let peripheral = lease.ensure_ready().await?.clone();
        let dispatcher =
            crate::ble::notify_dispatcher::NotifyDispatcher::start(&peripheral).await?;
        let rx = dispatcher.subscribe(SMP_CHARACTERISTIC_UUID).await;
        // The stream holds the lease and the dispatcher for the transport's life.
        let notifications = futures_util::stream::unfold(
            (rx, dispatcher, lease),
            |(mut rx, dispatcher, lease)| async move {
                match rx.recv().await {
                    Some(Ok(bytes)) => Some((bytes, (rx, dispatcher, lease))),
                    _ => None,
                }
            },
        );
        let session = Arc::new(Session::ble(
            BleTransport::open(peripheral, notifications).await?,
        ));
        if let Err(e) = session.negotiate_params().await {
            tracing::warn!("mcumgr params unavailable; keeping the fallback chunk size: {e}");
        }
        active.smp = Some(Arc::clone(&session));
        Ok(session)
    }

    /// An SMP session by registry: a `Manual` record's address directly,
    /// otherwise the device as discovery finds it, by id or else by name.
    pub async fn open_smp(
        &self,
        id: &DeviceId,
        transport: Transport,
    ) -> Result<Arc<Session>, Error> {
        match registry::target_for(id, transport) {
            ConnectTarget::Direct(addr) => Ok(Arc::new(Session::connect_udp(addr).await?)),
            ConnectTarget::Discover => {
                let live = self
                    .resolve_live_id_within(id, transport, RESOLVE_DISCOVERY_TIMEOUT)
                    .await?;
                self.open_smp_on(&live, transport).await
            }
        }
    }

    async fn open_smp_on(
        &self,
        id: &DeviceId,
        transport: Transport,
    ) -> Result<Arc<Session>, Error> {
        match transport {
            #[cfg(feature = "ble")]
            Transport::Ble => self.open_smp_ble(id).await,
            Transport::Udp => self.open_smp_udp(id).await,
            other => Err(Error::SmpUnavailable(other)),
        }
    }

    /// A firmware update over BLE, as a stream of its stages.
    #[cfg(feature = "ble")]
    pub fn ota_ble(
        &self,
        device_id: &DeviceId,
        image: Arc<[u8]>,
        options: OtaOptions,
    ) -> impl Stream<Item = Result<OtaEvent, Error>> + Send + Unpin + 'static {
        let source = Source::discovered(self.clone(), device_id.clone(), Transport::Ble);
        run_ota(source, image, options)
    }

    /// A firmware update over UDP, as a stream of its stages.
    pub fn ota_udp(
        &self,
        device_id: &DeviceId,
        image: Arc<[u8]>,
        options: OtaOptions,
    ) -> impl Stream<Item = Result<OtaEvent, Error>> + Send + Unpin + 'static {
        let source = Source::discovered(self.clone(), device_id.clone(), Transport::Udp);
        run_ota(source, image, options)
    }

    /// A firmware update by registry, as [`open_smp`](Self::open_smp) finds
    /// the device; a `Manual` one is reached at its address throughout.
    pub fn ota(
        &self,
        id: &DeviceId,
        image: Arc<[u8]>,
        options: OtaOptions,
        transport: Transport,
    ) -> OtaStream {
        if let ConnectTarget::Direct(addr) = registry::target_for(id, transport) {
            let label = registry::canonical_name(id.as_str()).to_owned();
            return run_ota(async move { Ok(Source::at(addr, label)) }, image, options);
        }
        let (discovery, id) = (self.clone(), id.clone());
        let source = async move {
            let live = discovery
                .resolve_live_id_within(&id, transport, RESOLVE_DISCOVERY_TIMEOUT)
                .await?;
            Source::discovered(discovery, live, transport).await
        };
        run_ota(source, image, options)
    }
}

/// A firmware update over UDP to `addr`, with no discovery: after the reset
/// it polls `addr` until the new image is running. `label` names the device
/// in `Reconnecting`.
pub fn ota_udp_addr(
    addr: SocketAddr,
    label: String,
    image: Arc<[u8]>,
    options: OtaOptions,
) -> impl Stream<Item = Result<OtaEvent, Error>> + Send + Unpin + 'static {
    run_ota(async move { Ok(Source::at(addr, label)) }, image, options)
}

/// Where an update's sessions come from: it needs a second one after the
/// reset, and the device's id or address may have changed by then.
struct Source {
    label: String,
    device_id: DeviceId,
    kind: SourceKind,
}

enum SourceKind {
    Discovered {
        discovery: Discovery,
        transport: Transport,
    },
    At(SocketAddr),
}

type Advertisements = Pin<Box<dyn Stream<Item = DiscoveryEvent> + Send>>;

impl Source {
    /// The device's name is what finds it again after the reset.
    async fn discovered(
        discovery: Discovery,
        device_id: DeviceId,
        transport: Transport,
    ) -> Result<Self, Error> {
        let device = discovery
            .get(&device_id)
            .await
            .ok_or_else(|| Error::UnknownDevice(device_id.clone()))?;
        Ok(Self {
            label: device.name().to_owned(),
            device_id,
            kind: SourceKind::Discovered {
                discovery,
                transport,
            },
        })
    }

    fn at(addr: SocketAddr, label: String) -> Self {
        Self {
            label,
            device_id: DeviceId::new(format!("udp:{addr}")),
            kind: SourceKind::At(addr),
        }
    }

    async fn open(&self, id: &DeviceId) -> Result<Arc<Session>, Error> {
        match &self.kind {
            SourceKind::Discovered {
                discovery,
                transport,
            } => discovery.open_smp_on(id, *transport).await,
            SourceKind::At(addr) => Ok(Arc::new(Session::connect_udp(*addr).await?)),
        }
    }

    /// Subscribed before the session goes, so a quick re-advertisement is
    /// not missed.
    fn arm_reconnect(&self) -> Option<Advertisements> {
        match &self.kind {
            SourceKind::Discovered { discovery, .. } => Some(Box::pin(discovery.events())),
            SourceKind::At(_) => None,
        }
    }

    async fn release(&self, id: &DeviceId) {
        if let SourceKind::Discovered { discovery, .. } = &self.kind {
            discovery.release_device(id).await;
        }
    }

    /// Lost now, so the device's next advertisement is a fresh `Seen`.
    fn forget(&self, id: &DeviceId) {
        if let SourceKind::Discovered { discovery, .. } = &self.kind {
            discovery.forget(id);
        }
    }

    /// The device by its next advertisement; at a fixed address, by the
    /// active slot reporting `expected_hash`, since the old image answers
    /// there until the device restarts.
    async fn reopen(
        &self,
        advertisements: Option<Advertisements>,
        deadline: Duration,
        expected_hash: &[u8],
    ) -> Result<(Arc<Session>, DeviceId), Error> {
        let timeout = Error::Timeout(deadline);
        match (&self.kind, advertisements) {
            (
                SourceKind::Discovered {
                    discovery,
                    transport,
                },
                Some(mut advertisements),
            ) => {
                let seen = async {
                    while let Some(event) = advertisements.next().await {
                        let id = match event {
                            DiscoveryEvent::Seen { device } => device.id().clone(),
                            DiscoveryEvent::Updated { id, .. } => id,
                            _ => continue,
                        };
                        if let Some(device) = discovery.get(&id).await
                            && device.name() == self.label
                            && device.transports().contains(transport)
                            && device.capabilities().contains(CapabilitySet::SMP)
                        {
                            return Some(id);
                        }
                    }
                    None
                };
                let id = tokio::time::timeout(deadline, seen)
                    .await
                    .ok()
                    .flatten()
                    .ok_or(timeout)?;
                Ok((self.open(&id).await?, id))
            }
            _ => {
                let rebooted = async {
                    loop {
                        if let Ok(session) = self.open(&self.device_id).await
                            && let Ok(images) = session.list_images().await
                            && images.iter().any(|s| s.active && s.hash == expected_hash)
                        {
                            return session;
                        }
                        tokio::time::sleep(UDP_RECONNECT_POLL_INTERVAL).await;
                    }
                };
                let session = tokio::time::timeout(deadline, rebooted)
                    .await
                    .map_err(|_| timeout)?;
                Ok((session, self.device_id.clone()))
            }
        }
    }
}

fn run_ota<F>(source: F, image: Arc<[u8]>, options: OtaOptions) -> OtaStream
where
    F: Future<Output = Result<Source, Error>> + Send + 'static,
{
    let (tx, rx) = mpsc::channel(OTA_EVENT_CHANNEL_CAPACITY);
    spawn(async move {
        let source = match source.await {
            Ok(source) => source,
            Err(e) => {
                let _ = tx.send(Err(e)).await;
                return;
            }
        };
        let mut id = source.device_id.clone();
        let result = ota(&source, &mut id, image, options, &tx).await;
        source.release(&id).await;
        if let Err(e) = result {
            let _ = tx.send(Err(e)).await;
        }
    });
    Box::pin(futures_util::stream::unfold(rx, |mut rx| async move {
        rx.recv().await.map(|event| (event, rx))
    }))
}

/// `set_state(test)` then reset suits both overwrite-only and swap MCUboot;
/// the confirm after the reset is a no-op on the first and makes the swap
/// permanent on the second. A dropped stream ends the update.
async fn ota(
    source: &Source,
    id: &mut DeviceId,
    image: Arc<[u8]>,
    options: OtaOptions,
    tx: &mpsc::Sender<Result<OtaEvent, Error>>,
) -> Result<(), Error> {
    macro_rules! emit {
        ($event:expr) => {
            if tx.send(Ok($event)).await.is_err() {
                tracing::debug!("OTA stream dropped; stopping");
                return Ok(());
            }
        };
    }

    let session = source.open(id).await?;
    emit!(OtaEvent::SessionOpened);

    let mut staged_hash = None;
    let mut upload = session.upload(image, None);
    while let Some(progress) = upload.next().await {
        let progress = progress?;
        staged_hash = progress.image_hash.clone().or(staged_hash);
        emit!(OtaEvent::UploadProgress(progress));
    }
    let staged_hash = staged_hash
        .ok_or_else(|| Error::Protocol("the upload ended without the image hash".into()))?;

    emit!(OtaEvent::Activating);
    session.test(&staged_hash).await?;
    emit!(OtaEvent::Activated {
        hash: staged_hash.clone()
    });

    emit!(OtaEvent::Resetting);
    session.reset().await?;
    emit!(OtaEvent::ResetSent);

    let advertisements = source.arm_reconnect();
    drop(session);
    source.release(id).await;
    source.forget(id);

    emit!(OtaEvent::Reconnecting {
        name: source.label.clone()
    });
    let (session, new_id) = source
        .reopen(advertisements, options.reconnect_timeout, &staged_hash)
        .await?;
    *id = new_id;
    emit!(OtaEvent::Reconnected {
        device_id: id.clone()
    });

    let active_hash = session
        .list_images()
        .await?
        .into_iter()
        .find(|slot| slot.active)
        .ok_or_else(|| Error::Protocol("no active image after the reset".into()))?
        .hash;
    if active_hash != staged_hash {
        return Err(Error::OtaVerifyMismatch {
            expected: staged_hash,
            found: active_hash,
        });
    }
    emit!(OtaEvent::Verified { active_hash });

    emit!(OtaEvent::Confirming);
    session.confirm_running().await?;
    emit!(OtaEvent::Confirmed);
    Ok(())
}

fn spawn(task: impl Future<Output = ()> + Send + 'static) {
    #[cfg(feature = "ble")]
    crate::runtime::ble_runtime().spawn(task);
    #[cfg(not(feature = "ble"))]
    tokio::spawn(task);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    #[test]
    fn default_reconnect_timeout_is_sixty_seconds() {
        assert_eq!(
            OtaOptions::default().reconnect_timeout,
            Duration::from_secs(60)
        );
    }

    #[test]
    fn an_address_source_names_its_device_by_the_address() {
        let source = Source::at("127.0.0.1:1337".parse().unwrap(), "test-device".into());
        assert_eq!(source.device_id.as_str(), "udp:127.0.0.1:1337");
        assert_eq!(source.label, "test-device");
    }

    #[tokio::test]
    async fn an_address_source_gives_up_at_its_deadline() {
        let silent = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let source = Source::at(silent.local_addr().unwrap(), "test-device".into());
        let started = Instant::now();

        let result = source
            .reopen(None, Duration::from_millis(300), &[0; 32])
            .await;

        assert!(
            matches!(result, Err(Error::Timeout(_))),
            "{:?}",
            result.err()
        );
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[tokio::test]
    async fn an_update_of_an_unknown_device_fails_at_once() {
        let discovery = Discovery::idle();
        let mut events = discovery.ota_udp(
            &DeviceId::new("mdns:udp:absent"),
            Arc::from(&[][..]),
            OtaOptions::default(),
        );
        assert!(matches!(
            events.next().await,
            Some(Err(Error::UnknownDevice(_)))
        ));
        assert!(events.next().await.is_none());
    }

    #[tokio::test]
    async fn smp_over_tcp_is_refused() {
        let discovery = Discovery::idle();
        let result = discovery
            .open_smp_on(&DeviceId::new("x"), Transport::Tcp)
            .await;
        assert!(matches!(result, Err(Error::SmpUnavailable(Transport::Tcp))));
    }
}
