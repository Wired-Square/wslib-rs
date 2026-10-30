//! SMP (mcumgr) sessions on discovered devices, and the firmware update that
//! runs over one: upload, test, reset, reconnect, verify, confirm.

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use futures_util::{Stream, StreamExt};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use wslib_mcumgr::{Session, UploadOptions};

use super::{Discovery, DiscoveryEvent};
use crate::registry::{self, ConnectTarget};
use crate::{CapabilitySet, DeviceId, Error, Transport};

/// A just-started discovery may not have seen the device yet.
const RESOLVE_DISCOVERY_TIMEOUT: Duration = Duration::from_secs(15);

const OTA_EVENT_CHANNEL_CAPACITY: usize = 32;

/// A device back on Wi-Fi and re-announced over mDNS takes 18 to 30 seconds.
const DEFAULT_RECONNECT_TIMEOUT: Duration = Duration::from_secs(60);

const UDP_RECONNECT_POLL_INTERVAL: Duration = Duration::from_millis(500);

/// How a firmware update runs.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct OtaOptions {
    /// How long the device may take to come back after its reset.
    pub reconnect_timeout: Duration,
    /// How the image is uploaded: its image number and chunk timeouts.
    pub upload: UploadOptions,
}

impl Default for OtaOptions {
    fn default() -> Self {
        Self {
            reconnect_timeout: DEFAULT_RECONNECT_TIMEOUT,
            upload: UploadOptions::default(),
        }
    }
}

impl OtaOptions {
    pub fn with_reconnect_timeout(self, reconnect_timeout: Duration) -> Self {
        Self {
            reconnect_timeout,
            ..self
        }
    }

    pub fn with_upload(self, upload: UploadOptions) -> Self {
        Self { upload, ..self }
    }
}

/// The stages of a firmware update, in order; `Confirmed` ends one that
/// succeeded. Hashes serialise as arrays of bytes, as in `UploadProgress`.
#[derive(Clone, Debug, serde::Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
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

/// Dropping the stream cancels the update only before `Activating`; after
/// that the device keeps the test image and resets.
pub type OtaStream = Pin<Box<dyn Stream<Item = Result<OtaEvent, Error>> + Send + 'static>>;

impl Discovery {
    /// An SMP session over UDP to a device seen as `_mcumgr._udp`. Uploads
    /// keep the UDP chunk size: the buffer size a device reports is sized for
    /// BLE and would fragment a datagram.
    pub async fn open_smp_udp(&self, id: &DeviceId) -> Result<Arc<Session>, Error> {
        self.open_smp_shared(id, async {
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
            Ok(Session::connect_udp(addr).await?)
        })
        .await
    }

    /// An SMP session over BLE to a device that advertises `SMP`, sharing
    /// the link with the device's other sessions.
    #[cfg(feature = "ble")]
    pub async fn open_smp_ble(&self, id: &DeviceId) -> Result<Arc<Session>, Error> {
        use wslib_mcumgr::ble::{BleTransport, SMP_CHARACTERISTIC_UUID};

        self.open_smp_shared(id, async {
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
            let session = Session::ble(BleTransport::open(peripheral, notifications).await?);
            if let Err(e) = session.negotiate_params().await {
                tracing::warn!("mcumgr params unavailable; keeping the fallback chunk size: {e}");
            }
            Ok(session)
        })
        .await
    }

    async fn open_smp_shared(
        &self,
        id: &DeviceId,
        open: impl Future<Output = Result<Session, Error>>,
    ) -> Result<Arc<Session>, Error> {
        self.open_shared(id, |active| &mut active.smp, open).await
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

    /// An SMP session to the seen device `id` over `transport`.
    pub async fn open_smp_on(
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

    /// A firmware update over BLE, as a stream of its stages; see
    /// [`OtaStream`] for what dropping it cancels.
    #[cfg(feature = "ble")]
    pub fn ota_ble(
        &self,
        device_id: &DeviceId,
        image: Arc<[u8]>,
        options: OtaOptions,
    ) -> OtaStream {
        self.ota_on(device_id, image, options, Transport::Ble)
    }

    /// A firmware update over UDP, as a stream of its stages; see
    /// [`OtaStream`] for what dropping it cancels.
    pub fn ota_udp(
        &self,
        device_id: &DeviceId,
        image: Arc<[u8]>,
        options: OtaOptions,
    ) -> OtaStream {
        self.ota_on(device_id, image, options, Transport::Udp)
    }

    /// A firmware update of the seen device `id` over `transport`, as
    /// [`open_smp_on`](Self::open_smp_on) opens one; see [`OtaStream`] for
    /// what dropping it cancels.
    pub fn ota_on(
        &self,
        id: &DeviceId,
        image: Arc<[u8]>,
        options: OtaOptions,
        transport: Transport,
    ) -> OtaStream {
        let source = Source::discovered(self.clone(), id.clone(), transport);
        run_ota(source, image, options)
    }

    /// A firmware update by registry, as [`open_smp`](Self::open_smp) finds
    /// the device; a `Manual` one is reached at its address throughout. See
    /// [`OtaStream`] for what dropping it cancels.
    pub fn ota(
        &self,
        id: &DeviceId,
        image: Arc<[u8]>,
        options: OtaOptions,
        transport: Transport,
    ) -> OtaStream {
        if let ConnectTarget::Direct(addr) = registry::target_for(id, transport) {
            let label = registry::canonical_name(id.as_str()).to_owned();
            let (discovery, id) = (self.clone(), id.clone());
            let source = async move {
                let claim = discovery.claim_update(&id)?;
                Ok(Source {
                    _claim: Some(claim),
                    ..Source::at(addr, label)
                })
            };
            return run_ota(source, image, options);
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
/// in `Reconnecting`. Dropping the stream cancels it only before
/// `Activating`; after that the device keeps the test image and resets.
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
    _claim: Option<UpdateClaim>,
}

/// One update per device at a time: the device has a single upload in
/// progress, and the update's session is shared with any other open.
struct UpdateClaim {
    discovery: Discovery,
    id: DeviceId,
}

impl Discovery {
    fn claim_update(&self, id: &DeviceId) -> Result<UpdateClaim, Error> {
        if !self.updating().insert(id.clone()) {
            return Err(Error::OtaInProgress(id.clone()));
        }
        Ok(UpdateClaim {
            discovery: self.clone(),
            id: id.clone(),
        })
    }

    fn updating(&self) -> std::sync::MutexGuard<'_, std::collections::HashSet<DeviceId>> {
        (self.inner.updating.lock()).unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

impl Drop for UpdateClaim {
    fn drop(&mut self) {
        self.discovery.updating().remove(&self.id);
    }
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
        if !(transport == Transport::Udp || cfg!(feature = "ble") && transport == Transport::Ble) {
            return Err(Error::SmpUnavailable(transport));
        }
        let device = discovery
            .get(&device_id)
            .await
            .ok_or_else(|| Error::UnknownDevice(device_id.clone()))?;
        let claim = discovery.claim_update(&device_id)?;
        Ok(Self {
            label: device.name().to_owned(),
            device_id,
            kind: SourceKind::Discovered {
                discovery,
                transport,
            },
            _claim: Some(claim),
        })
    }

    fn at(addr: SocketAddr, label: String) -> Self {
        Self {
            label,
            device_id: DeviceId::new(format!("udp:{addr}")),
            kind: SourceKind::At(addr),
            _claim: None,
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
    spawn_ota(source, image, options).0
}

/// Dropping the stream stops the task at its next wait.
fn spawn_ota<F>(source: F, image: Arc<[u8]>, options: OtaOptions) -> (OtaStream, JoinHandle<()>)
where
    F: Future<Output = Result<Source, Error>> + Send + 'static,
{
    let (tx, rx) = mpsc::channel(OTA_EVENT_CHANNEL_CAPACITY);
    let task = spawn(async move {
        let source = match until_dropped(&tx, source).await {
            Some(Ok(source)) => source,
            Some(Err(e)) => {
                let _ = tx.send(Err(e)).await;
                return;
            }
            None => return,
        };
        let mut id = source.device_id.clone();
        let result = until_dropped(&tx, ota(&source, &mut id, image, options, &tx)).await;
        source.release(&id).await;
        if let Some(Err(e)) = result {
            let _ = tx.send(Err(e)).await;
        }
    });
    let events = Box::pin(futures_util::stream::unfold(rx, |mut rx| async move {
        rx.recv().await.map(|event| (event, rx))
    }));
    (events, task)
}

/// `None` once the stream is dropped. Dropping `work` mid-request is safe:
/// the session finishes writing a frame it has begun.
async fn until_dropped<T>(
    tx: &mpsc::Sender<Result<OtaEvent, Error>>,
    work: impl Future<Output = T>,
) -> Option<T> {
    tokio::select! {
        done = work => Some(done),
        () = tx.closed() => {
            tracing::debug!("OTA stream dropped; stopping");
            None
        }
    }
}

/// `set_state(test)` then reset suits both overwrite-only and swap MCUboot;
/// the confirm after the reset is a no-op on the first and makes the swap
/// permanent on the second. A dropped stream ends the update, but a test or
/// reset already begun still reaches the device.
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
    let mut upload = session.upload(image, options.upload);
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

fn spawn(task: impl Future<Output = ()> + Send + 'static) -> JoinHandle<()> {
    #[cfg(feature = "ble")]
    return crate::runtime::ble_runtime().spawn(task);
    #[cfg(not(feature = "ble"))]
    tokio::spawn(task)
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

    #[tokio::test]
    async fn the_image_number_in_the_options_reaches_the_device() {
        let device = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let options = OtaOptions::default().with_upload(UploadOptions::default().with_image(2));
        let image = mcuboot_image([0xAB; 32], &IMAGE_BODY);
        let _update = ota_udp_addr(
            device.local_addr().unwrap(),
            "test-device".into(),
            image,
            options,
        );

        let mut first_chunk = [0u8; 2048];
        let (len, _) =
            tokio::time::timeout(Duration::from_secs(5), device.recv_from(&mut first_chunk))
                .await
                .expect("the first chunk")
                .unwrap();

        let image_2 = [&[0x65][..], b"image", &[0x02]].concat();
        assert!(
            first_chunk[..len]
                .windows(image_2.len())
                .any(|w| w == image_2)
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

    const SETTLE: Duration = Duration::from_millis(50);

    async fn loopback_session() -> Session {
        let silent = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        Session::connect_udp(silent.local_addr().unwrap())
            .await
            .unwrap()
    }

    async fn cached(discovery: &Discovery, id: &DeviceId) -> Option<Arc<Session>> {
        let sessions = discovery.inner.sessions.lock().await;
        sessions.get(id).and_then(|active| active.smp.clone())
    }

    #[tokio::test]
    async fn opening_one_device_does_not_hold_up_releasing_another() {
        let discovery = Discovery::idle();
        let a = DeviceId::new("a");
        let opening = discovery.open_smp_shared(&a, std::future::pending());
        let release = async {
            tokio::time::sleep(SETTLE).await;
            tokio::time::timeout(
                Duration::from_secs(1),
                discovery.release_device(&DeviceId::new("b")),
            )
            .await
        };

        tokio::select! {
            _ = opening => panic!("the open never completes"),
            released = release => assert!(released.is_ok(), "release waited on the open"),
        }
    }

    #[tokio::test]
    async fn a_failed_open_leaves_the_session_map_as_it_was() {
        let discovery = Discovery::idle();

        let result = discovery.open_smp_udp(&DeviceId::new("absent")).await;

        assert!(matches!(result, Err(Error::UnknownDevice(_))));
        assert!(discovery.inner.sessions.lock().await.is_empty());
    }

    #[cfg(feature = "wifi-prov")]
    #[tokio::test]
    async fn opening_wifi_on_one_device_holds_up_neither_an_smp_open_nor_a_release_of_another() {
        let discovery = Discovery::idle();
        let a = DeviceId::new("a");
        let opening_wifi =
            discovery.open_shared(&a, |active| &mut active.wifi_prov, std::future::pending());
        let b = DeviceId::new("b");
        let on_b = async {
            tokio::time::sleep(SETTLE).await;
            tokio::time::timeout(Duration::from_secs(1), async {
                discovery
                    .open_smp_shared(&b, async { Ok(loopback_session().await) })
                    .await
                    .unwrap();
                discovery.release_device(&b).await;
            })
            .await
        };

        tokio::select! {
            _ = opening_wifi => panic!("the open never completes"),
            done = on_b => assert!(done.is_ok(), "device b waited on device a"),
        }
    }

    #[tokio::test]
    async fn concurrent_opens_of_one_device_share_one_session() {
        let discovery = Discovery::idle();
        let id = DeviceId::new("a");
        let opens = std::sync::atomic::AtomicUsize::new(0);
        let open = || async {
            opens.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            tokio::time::sleep(SETTLE).await;
            Ok(loopback_session().await)
        };

        let (first, second) = tokio::join!(
            discovery.open_smp_shared(&id, open()),
            discovery.open_smp_shared(&id, open())
        );

        assert!(Arc::ptr_eq(&first.unwrap(), &second.unwrap()));
        assert_eq!(opens.load(std::sync::atomic::Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn a_device_released_while_its_session_opens_does_not_keep_it() {
        let discovery = Discovery::idle();
        let id = DeviceId::new("a");
        let opening = discovery.open_smp_shared(&id, async {
            tokio::time::sleep(SETTLE * 2).await;
            Ok(loopback_session().await)
        });
        let release = async {
            tokio::time::sleep(SETTLE).await;
            discovery.release_device(&id).await;
        };

        let (opened, ()) = tokio::join!(opening, release);

        assert!(opened.is_ok());
        assert!(cached(&discovery, &id).await.is_none());
    }

    /// An MCUboot image with `body` and an IMAGE_TLV_SHA256 of `hash`.
    fn mcuboot_image(hash: [u8; 32], body: &[u8]) -> Arc<[u8]> {
        let mut bin = Vec::new();
        bin.extend_from_slice(&0x96f3_b83d_u32.to_le_bytes());
        bin.extend_from_slice(&0_u32.to_le_bytes());
        bin.extend_from_slice(&16_u16.to_le_bytes());
        bin.extend_from_slice(&0_u16.to_le_bytes());
        bin.extend_from_slice(&(body.len() as u32).to_le_bytes());
        bin.extend_from_slice(body);
        bin.extend_from_slice(&0x6907_u16.to_le_bytes());
        bin.extend_from_slice(&40_u16.to_le_bytes());
        bin.extend_from_slice(&[0x10, 0x00]);
        bin.extend_from_slice(&32_u16.to_le_bytes());
        bin.extend_from_slice(&hash);
        Arc::from(bin)
    }

    const IMAGE_BODY: [u8; 16] = [0x5A; 16];
    /// The header, the body and the 40-byte TLV area; under 256, for the
    /// hand-made CBOR below.
    const IMAGE_LEN: u8 = 16 + IMAGE_BODY.len() as u8 + 4 + 36;

    /// An SMP device on loopback that answers by header alone: an upload
    /// whole in its first chunk (unless `answer_uploads` is off), and any
    /// other request with an empty map, so it never lists the new image.
    /// Returns where each frame came from.
    async fn smp_device(
        answer_uploads: bool,
    ) -> (SocketAddr, Arc<std::sync::Mutex<Vec<SocketAddr>>>) {
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        let senders = Arc::<std::sync::Mutex<Vec<SocketAddr>>>::default();
        let seen = Arc::clone(&senders);
        tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            while let Ok((_, from)) = socket.recv_from(&mut buf).await {
                seen.lock().unwrap().push(from);
                let upload = buf[4..6] == [0, 1] && buf[7] == 1;
                let payload = match upload {
                    false => vec![0xa0],
                    true if answer_uploads => {
                        // {"off": IMAGE_LEN, "match": true}
                        let mut ack = vec![0xa2, 0x63, b'o', b'f', b'f', 0x18, IMAGE_LEN, 0x65];
                        ack.extend_from_slice(b"match");
                        ack.push(0xf5);
                        ack
                    }
                    true => continue,
                };
                let mut reply = vec![buf[0] + 1, 0];
                reply.extend_from_slice(&(payload.len() as u16).to_be_bytes());
                reply.extend_from_slice(&buf[4..8]);
                reply.extend_from_slice(&payload);
                socket.send_to(&reply, from).await.ok();
            }
        });
        (addr, senders)
    }

    fn update_at(addr: SocketAddr) -> (OtaStream, JoinHandle<()>) {
        let image = mcuboot_image([0xAB; 32], &IMAGE_BODY);
        assert_eq!(image.len(), usize::from(IMAGE_LEN));
        let source = async move { Ok(Source::at(addr, "test-device".into())) };
        spawn_ota(source, image, OtaOptions::default())
    }

    async fn until_event(events: &mut OtaStream, wanted: fn(&OtaEvent) -> bool) {
        let found = async {
            while let Some(event) = events.next().await {
                if wanted(&event.unwrap()) {
                    return;
                }
            }
            panic!("the update ended first");
        };
        tokio::time::timeout(Duration::from_secs(5), found)
            .await
            .expect("the event in time");
    }

    /// A write already begun when the update was dropped still lands.
    async fn frames_once_quiet(senders: &std::sync::Mutex<Vec<SocketAddr>>) -> usize {
        tokio::time::sleep(SETTLE).await;
        let before = senders.lock().unwrap().len();
        tokio::time::sleep(UDP_RECONNECT_POLL_INTERVAL + SETTLE * 4).await;
        let after = senders.lock().unwrap().len();
        assert_eq!(before, after, "the dropped update is still talking");
        after
    }

    #[tokio::test]
    async fn dropping_an_update_mid_upload_stops_it_and_leaves_the_device_to_the_next() {
        let (addr, senders) = smp_device(false).await;
        let (mut events, task) = update_at(addr);
        until_event(&mut events, |e| matches!(e, OtaEvent::SessionOpened)).await;
        tokio::time::sleep(SETTLE).await;
        assert_eq!(
            senders.lock().unwrap().len(),
            1,
            "the first chunk, unanswered"
        );

        drop(events);

        tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .expect("the task ends promptly")
            .unwrap();
        let quiet = frames_once_quiet(&senders).await;

        let (mut next, _task) = update_at(addr);
        until_event(&mut next, |e| matches!(e, OtaEvent::SessionOpened)).await;
        tokio::time::sleep(SETTLE).await;
        let senders = senders.lock().unwrap();
        assert_eq!(senders.len(), quiet + 1);
        assert_ne!(
            senders[quiet], senders[0],
            "the next update is a session of its own"
        );
    }

    #[tokio::test]
    async fn dropping_an_update_while_it_waits_for_the_reset_device_stops_it() {
        let (addr, senders) = smp_device(true).await;
        let (mut events, task) = update_at(addr);
        until_event(&mut events, |e| matches!(e, OtaEvent::Reconnecting { .. })).await;

        drop(events);

        tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .expect("the task ends promptly")
            .unwrap();
        frames_once_quiet(&senders).await;
    }

    /// Exhaustive, so a new variant does not compile until it has a golden.
    fn golden_name(event: &OtaEvent) -> &'static str {
        match event {
            OtaEvent::SessionOpened => "session_opened",
            OtaEvent::UploadProgress(p) if p.image_hash.is_some() => "upload_progress_final",
            OtaEvent::UploadProgress(_) => "upload_progress",
            OtaEvent::Activating => "activating",
            OtaEvent::Activated { .. } => "activated",
            OtaEvent::Resetting => "resetting",
            OtaEvent::ResetSent => "reset_sent",
            OtaEvent::Reconnecting { .. } => "reconnecting",
            OtaEvent::Reconnected { .. } => "reconnected",
            OtaEvent::Verified { .. } => "verified",
            OtaEvent::Confirming => "confirming",
            OtaEvent::Confirmed => "confirmed",
        }
    }

    #[test]
    fn every_ota_event_serialises_as_its_golden() {
        let goldens: std::collections::BTreeMap<String, String> =
            serde_json::from_str(include_str!("../../tests/fixtures/ota_goldens.json")).unwrap();
        let progress = |json| OtaEvent::UploadProgress(serde_json::from_str(json).unwrap());
        let samples = [
            OtaEvent::SessionOpened,
            progress(r#"{"bytes_sent":512,"total_bytes":1024,"resumed_from":256}"#),
            progress(r#"{"bytes_sent":1024,"total_bytes":1024,"image_hash":[171,205]}"#),
            OtaEvent::Activating,
            OtaEvent::Activated {
                hash: vec![0xAB, 0xCD],
            },
            OtaEvent::Resetting,
            OtaEvent::ResetSent,
            OtaEvent::Reconnecting {
                name: "WFL-1234".into(),
            },
            OtaEvent::Reconnected {
                device_id: DeviceId::new("mdns:udp:wfl-1234._mcumgr._udp.local."),
            },
            OtaEvent::Verified {
                active_hash: vec![0xAB, 0xCD],
            },
            OtaEvent::Confirming,
            OtaEvent::Confirmed,
        ];

        let checked: std::collections::BTreeSet<&str> = samples
            .iter()
            .map(|event| {
                let name = golden_name(event);
                assert_eq!(
                    serde_json::to_string(event).unwrap(),
                    goldens[name],
                    "{name}"
                );
                name
            })
            .collect();

        assert!(goldens.keys().map(String::as_str).eq(checked));
    }

    fn seen_over_udp_at(addr: SocketAddr) -> (Discovery, DeviceId) {
        let discovery = Discovery::idle();
        let id = DeviceId::new("mdns:udp:wfl-1");
        discovery.observe(
            crate::Device::builder(id.clone(), "WFL-1")
                .transport(Transport::Udp)
                .capabilities(CapabilitySet::SMP)
                .address(addr)
                .build(),
        );
        (discovery, id)
    }

    #[tokio::test]
    async fn ota_on_updates_over_the_transport_it_is_given() {
        let (addr, senders) = smp_device(false).await;
        let (discovery, id) = seen_over_udp_at(addr);
        let image = || mcuboot_image([0xAB; 32], &IMAGE_BODY);

        let mut over_tcp = discovery.ota_on(&id, image(), OtaOptions::default(), Transport::Tcp);
        assert!(matches!(
            over_tcp.next().await,
            Some(Err(Error::SmpUnavailable(Transport::Tcp)))
        ));
        assert!(over_tcp.next().await.is_none());

        let mut over_udp = discovery.ota_on(&id, image(), OtaOptions::default(), Transport::Udp);
        until_event(&mut over_udp, |e| matches!(e, OtaEvent::SessionOpened)).await;
        tokio::time::sleep(SETTLE).await;
        assert_eq!(senders.lock().unwrap().len(), 1, "the first chunk");
    }

    #[tokio::test]
    async fn a_second_update_of_a_device_is_refused_until_the_first_ends() {
        let (addr, _) = smp_device(false).await;
        let (discovery, id) = seen_over_udp_at(addr);
        let update = || {
            let image = mcuboot_image([0xAB; 32], &IMAGE_BODY);
            discovery.ota_udp(&id, image, OtaOptions::default())
        };
        let mut first = update();
        until_event(&mut first, |e| matches!(e, OtaEvent::SessionOpened)).await;

        let mut second = update();
        assert!(
            matches!(second.next().await, Some(Err(Error::OtaInProgress(ref busy))) if *busy == id)
        );
        assert!(second.next().await.is_none());

        drop(first);
        let after_the_first = async {
            loop {
                match update().next().await {
                    Some(Err(Error::OtaInProgress(_))) => tokio::time::sleep(SETTLE).await,
                    other => return other,
                }
            }
        };
        let third = tokio::time::timeout(Duration::from_secs(1), after_the_first)
            .await
            .expect("the first update lets go of the device");
        assert!(matches!(third, Some(Ok(OtaEvent::SessionOpened))));
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
