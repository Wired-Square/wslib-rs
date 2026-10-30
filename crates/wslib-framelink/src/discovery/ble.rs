//! The BLE scanner behind `Discovery`. A peripheral is a device when it
//! advertises the FrameLink service and a local name; its capabilities come
//! from its manufacturer data, and are empty without it.

use super::{ErrorSource, presence::PresenceTracker};
use crate::ble::parse_peripheral;
use crate::runtime::ble_runtime;
use crate::{CapabilitySet, Device, DeviceId, Transport};
use btleplug::api::{
    Central as _, CentralEvent, Peripheral as _, PeripheralProperties, ScanFilter,
};
use btleplug::platform::{Adapter, Peripheral, PeripheralId};
use futures_util::StreamExt;
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tracing::{debug, warn};

/// A connection to a peripheral, shared by every session on it and
/// disconnected when the last drops. The scanner pauses while any lease
/// lives (see [`ScanController`]). A dropped link is noticed by the next
/// operation on it, not watched for.
#[cfg_attr(not(any(feature = "wifi-prov", feature = "smp")), allow(dead_code))]
pub(crate) struct PeripheralLease {
    peripheral: Peripheral,
    ready: tokio::sync::Mutex<bool>,
    scan_controller: Arc<ScanController>,
}

impl PeripheralLease {
    fn new(peripheral: Peripheral, scan_controller: Arc<ScanController>) -> Self {
        scan_controller.lease_acquired();
        Self {
            peripheral,
            ready: tokio::sync::Mutex::new(false),
            scan_controller,
        }
    }

    /// Connects and discovers services, again if the peripheral has dropped
    /// since.
    #[cfg_attr(not(any(feature = "wifi-prov", feature = "smp")), allow(dead_code))]
    pub(crate) async fn ensure_ready(&self) -> Result<&Peripheral, btleplug::Error> {
        let mut guard = self.ready.lock().await;
        let connected = self.peripheral.is_connected().await?;
        if *guard && !connected {
            *guard = false;
        }
        if !*guard {
            self.peripheral.connect().await?;
            self.peripheral.discover_services().await?;
            *guard = true;
        }
        Ok(&self.peripheral)
    }

    #[cfg_attr(not(feature = "wifi-prov"), allow(dead_code))]
    pub(crate) async fn is_connected(&self) -> bool {
        self.peripheral.is_connected().await.unwrap_or(false)
    }
}

/// Pauses the scanner while any lease lives: on macOS it shares
/// CoreBluetooth's dispatch queue with the connection, and running both
/// slows uploads and destabilises the link.
pub(super) struct ScanController {
    active_leases: AtomicUsize,
    scan_enabled: watch::Sender<bool>,
}

impl ScanController {
    fn new() -> Arc<Self> {
        let (scan_enabled, _) = watch::channel(true);
        Arc::new(Self {
            active_leases: AtomicUsize::new(0),
            scan_enabled,
        })
    }

    pub(super) fn watch_scan_enabled(&self) -> watch::Receiver<bool> {
        self.scan_enabled.subscribe()
    }

    fn lease_acquired(&self) {
        let prev = self.active_leases.fetch_add(1, Ordering::AcqRel);
        if prev == 0 {
            let _ = self.scan_enabled.send(false);
        }
    }

    fn lease_released(&self) {
        let prev = self.active_leases.fetch_sub(1, Ordering::AcqRel);
        if prev == 1 {
            let _ = self.scan_enabled.send(true);
        }
    }
}

impl Drop for PeripheralLease {
    fn drop(&mut self) {
        self.scan_controller.lease_released();
        let peripheral = self.peripheral.clone();
        ble_runtime().spawn(async move {
            if let Err(e) = peripheral.disconnect().await {
                warn!("lease drop disconnect failed: {e}");
            }
        });
    }
}

/// Each device's latest peripheral handle, and its lease while one lives.
pub(super) struct BlePeripheralStore {
    scan_controller: Arc<ScanController>,
    entries: Mutex<HashMap<DeviceId, StoreEntry>>,
}

#[derive(Default)]
struct StoreEntry {
    peripheral: Option<Peripheral>,
    lease: Weak<PeripheralLease>,
}

impl Default for BlePeripheralStore {
    fn default() -> Self {
        Self {
            scan_controller: ScanController::new(),
            entries: Mutex::new(HashMap::new()),
        }
    }
}

impl BlePeripheralStore {
    pub(super) fn scan_controller(&self) -> Arc<ScanController> {
        Arc::clone(&self.scan_controller)
    }

    pub fn insert(&self, id: DeviceId, peripheral: Peripheral) {
        let mut entries = self.entries.lock().expect("BlePeripheralStore lock");
        let entry = entries.entry(id).or_default();
        entry.peripheral = Some(peripheral);
    }

    /// The live lease, else a new one over the latest handle; `None` for a
    /// device the scanner never saw.
    #[cfg_attr(not(any(feature = "wifi-prov", feature = "smp")), allow(dead_code))]
    pub async fn acquire_lease(&self, id: &DeviceId) -> Option<Arc<PeripheralLease>> {
        let mut entries = self.entries.lock().expect("BlePeripheralStore lock");
        let entry = entries.get_mut(id)?;
        if let Some(existing) = entry.lease.upgrade() {
            return Some(existing);
        }
        let peripheral = entry.peripheral.clone()?;
        let fresh = Arc::new(PeripheralLease::new(
            peripheral,
            Arc::clone(&self.scan_controller),
        ));
        entry.lease = Arc::downgrade(&fresh);
        Some(fresh)
    }
}

/// BLE has no advertising-stopped signal, so devices gone out of range are
/// swept for.
const EVICT_INTERVAL: Duration = Duration::from_millis(2500);

/// Every peripheral the adapter knows is re-read this often: on macOS
/// btleplug reports a stationary advertiser once, and it would otherwise go
/// stale and never come back.
pub(super) const POLL_INTERVAL: Duration = Duration::from_secs(3);

/// Exits when the adapter fails; stops scanning while any lease lives.
pub(super) fn spawn_scanner(
    adapter: Adapter,
    tracker: Arc<Mutex<PresenceTracker>>,
    store: Arc<BlePeripheralStore>,
) -> JoinHandle<()> {
    let mut scan_enabled = store.scan_controller().watch_scan_enabled();
    ble_runtime().spawn(async move {
        loop {
            while !*scan_enabled.borrow_and_update() {
                debug!("scan paused (lease active)");
                if scan_enabled.changed().await.is_err() {
                    return;
                }
            }

            if let Err(e) = adapter.start_scan(ScanFilter::default()).await {
                tracker
                    .lock()
                    .expect("tracker lock")
                    .emit_error(ErrorSource::Ble, format!("scan start: {e}"));
                return;
            }
            let mut events = match adapter.events().await {
                Ok(s) => s,
                Err(e) => {
                    tracker
                        .lock()
                        .expect("tracker lock")
                        .emit_error(ErrorSource::Ble, format!("events stream: {e}"));
                    return;
                }
            };
            debug!("scan resumed");

            let mut evict_tick = tokio::time::interval(EVICT_INTERVAL);
            evict_tick.tick().await;

            let mut poll_tick = tokio::time::interval(POLL_INTERVAL);
            poll_tick.tick().await;

            loop {
                tokio::select! {
                    changed = scan_enabled.changed() => {
                        if changed.is_err() {
                            let _ = adapter.stop_scan().await;
                            return;
                        }
                        if !*scan_enabled.borrow_and_update() {
                            let _ = adapter.stop_scan().await;
                            break;
                        }
                    }
                    next = events.next() => match next {
                        Some(CentralEvent::DeviceDiscovered(id))
                        | Some(CentralEvent::DeviceUpdated(id)) => {
                            observe_central_event(&adapter, id, &tracker, &store).await;
                        }
                        Some(_) => {}
                        None => {
                            let _ = adapter.stop_scan().await;
                            break;
                        }
                    },
                    _ = evict_tick.tick() => {
                        tracker.lock().expect("tracker lock").evict_stale();
                    }
                    _ = poll_tick.tick() => {
                        let known = match adapter.peripherals().await {
                            Ok(p) => p,
                            Err(e) => {
                                debug!(error = %e, "peripherals enumerate failed");
                                continue;
                            }
                        };
                        for peripheral in known {
                            observe_peripheral(peripheral, &tracker, &store).await;
                        }
                    }
                }
            }
        }
    })
}

async fn observe_central_event(
    adapter: &Adapter,
    id: PeripheralId,
    tracker: &Arc<Mutex<PresenceTracker>>,
    store: &Arc<BlePeripheralStore>,
) {
    let peripheral = match adapter.peripheral(&id).await {
        Ok(p) => p,
        Err(e) => {
            debug!(error = %e, "peripheral handle fetch failed");
            return;
        }
    };
    observe_peripheral(peripheral, tracker, store).await;
}

async fn observe_peripheral(
    peripheral: Peripheral,
    tracker: &Arc<Mutex<PresenceTracker>>,
    store: &Arc<BlePeripheralStore>,
) {
    let props = match peripheral.properties().await {
        Ok(Some(p)) => p,
        Ok(None) => return,
        Err(e) => {
            debug!(error = %e, "properties fetch failed");
            return;
        }
    };
    let ble_id = peripheral.id().to_string();
    if let Some(device) = build_device(ble_id, &props, props.rssi) {
        store.insert(device.id().clone(), peripheral);
        tracker.lock().expect("tracker lock").observe(device);
    }
}

fn build_device(ble_id: String, props: &PeripheralProperties, rssi: Option<i16>) -> Option<Device> {
    let parsed = parse_peripheral(ble_id.clone(), props, rssi)?;
    let caps = parsed
        .payload
        .map(|p| CapabilitySet::from(p.capabilities))
        .unwrap_or(CapabilitySet::empty());
    let id = DeviceId::new(format!("ble:{ble_id}"));
    Some(
        Device::builder(id, parsed.name)
            .transport(Transport::Ble)
            .capabilities(caps)
            .maybe_rssi(parsed.rssi)
            .build(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ble::FRAMELINK_BLE_SERVICE_UUID;
    use btleplug::api::PeripheralProperties;
    use wslib_framelink_protocol::manufacturer_data::{
        COMPANY_ID, CapabilityFlagsBuilder, ManufacturerPayload,
    };

    fn empty_props() -> PeripheralProperties {
        PeripheralProperties::default()
    }

    #[test]
    fn primary_path_decodes_capabilities_from_mfg_data() {
        let mut props = empty_props();
        props.local_name = Some("WFL-Test".into());
        props.services.push(FRAMELINK_BLE_SERVICE_UUID);

        let payload = ManufacturerPayload::new_v1(
            CapabilityFlagsBuilder::new()
                .wifi_prov(true)
                .smp(true)
                .build(),
            0x10,
            0,
            1,
        );
        props
            .manufacturer_data
            .insert(COMPANY_ID, payload.encode().to_vec());

        let dev = build_device("p1".into(), &props, Some(-55)).expect("primary path");
        assert_eq!(dev.id().as_str(), "ble:p1");
        assert_eq!(dev.name(), "WFL-Test");
        assert_eq!(dev.transports(), &[Transport::Ble]);
        assert_eq!(
            dev.capabilities(),
            CapabilitySet::WIFI_PROV | CapabilitySet::SMP
        );
        assert_eq!(dev.rssi(), Some(-55));
    }

    #[test]
    fn primary_path_no_mfg_data_yields_empty_caps() {
        let mut props = empty_props();
        props.local_name = Some("WFL-Test".into());
        props.services.push(FRAMELINK_BLE_SERVICE_UUID);

        let dev = build_device("p1".into(), &props, None).expect("primary path");
        assert!(dev.capabilities().is_empty());
    }

    #[test]
    fn requires_framelink_primary_service_uuid() {
        let mut props = empty_props();
        props.local_name = Some("Random-BLE-Speaker".into());
        props.services.push(uuid::Uuid::from_u128(
            0xdeadbeef_dead_beef_dead_beefdeadbeef,
        ));
        assert!(build_device("p1".into(), &props, None).is_none());
    }

    #[test]
    fn requires_local_name_even_when_framelink_primary_present() {
        let mut props = empty_props();
        props.services.push(FRAMELINK_BLE_SERVICE_UUID);
        assert!(build_device("p2".into(), &props, None).is_none());
    }
}
