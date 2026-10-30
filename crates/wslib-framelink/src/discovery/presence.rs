//! The devices currently seen, turning each observation into the event it
//! amounts to. No I/O.

use super::{DiscoveryEvent, ErrorSource};
use crate::{Device, DeviceId};
use std::collections::HashMap;
use std::time::{Duration, Instant};
use tokio::sync::broadcast;

/// A BLE device unseen this long is lost: three of the scanner's 3 s polls,
/// riding out one dropped advertisement.
pub(crate) const DEFAULT_STALE_AFTER: Duration = Duration::from_secs(10);

/// An mDNS device unresolved this long is lost: past the rebrowse interval,
/// so one lost reply does not flap it.
pub(crate) const MDNS_STALE_AFTER: Duration = Duration::from_secs(90);

pub(crate) struct PresenceTracker {
    state: HashMap<DeviceId, Entry>,
    event_tx: broadcast::Sender<DiscoveryEvent>,
    stale_after: Duration,
    mdns_stale_after: Duration,
}

struct Entry {
    device: Device,
    last_seen: Instant,
}

impl PresenceTracker {
    pub fn new(event_tx: broadcast::Sender<DiscoveryEvent>, stale_after: Duration) -> Self {
        Self {
            state: HashMap::new(),
            event_tx,
            stale_after,
            mdns_stale_after: MDNS_STALE_AFTER,
        }
    }

    pub fn snapshot(&self) -> Vec<Device> {
        self.state.values().map(|e| e.device.clone()).collect()
    }

    pub fn get(&self, id: &DeviceId) -> Option<Device> {
        self.state.get(id).map(|e| e.device.clone())
    }

    pub fn ids(&self) -> impl Iterator<Item = &DeviceId> {
        self.state.keys()
    }

    /// `Seen` for a new id, `Updated` when its name, capabilities or RSSI
    /// changed, else nothing; an id's address and transports never change.
    pub fn observe(&mut self, device: Device) {
        let now = Instant::now();
        let id = device.id().clone();

        match self.state.get_mut(&id) {
            None => {
                let _ = self.event_tx.send(DiscoveryEvent::Seen {
                    device: device.clone(),
                });
                self.state.insert(
                    id,
                    Entry {
                        device,
                        last_seen: now,
                    },
                );
            }
            Some(entry) => {
                entry.last_seen = now;
                let prev = &entry.device;
                let changed = prev.name() != device.name()
                    || prev.capabilities() != device.capabilities()
                    || prev.rssi() != device.rssi();
                if changed {
                    let _ = self.event_tx.send(DiscoveryEvent::Updated {
                        id: id.clone(),
                        name: device.name().to_owned(),
                        capabilities: device.capabilities(),
                        rssi: device.rssi(),
                    });
                    entry.device = device;
                }
            }
        }
    }

    pub fn forget(&mut self, id: &DeviceId) {
        if self.state.remove(id).is_some() {
            let _ = self.event_tx.send(DiscoveryEvent::Lost { id: id.clone() });
        }
    }

    /// `Lost` for each device unseen for its transport's window.
    pub fn evict_stale(&mut self) {
        let now = Instant::now();
        let ble_cutoff = now.checked_sub(self.stale_after).unwrap_or(now);
        let mdns_cutoff = now.checked_sub(self.mdns_stale_after).unwrap_or(now);
        let to_remove: Vec<DeviceId> = self
            .state
            .iter()
            .filter(|(id, entry)| {
                let cutoff = if id.as_str().starts_with("mdns:") {
                    mdns_cutoff
                } else {
                    ble_cutoff
                };
                entry.last_seen < cutoff
            })
            .map(|(id, _)| id.clone())
            .collect();
        for id in to_remove {
            self.state.remove(&id);
            let _ = self.event_tx.send(DiscoveryEvent::Lost { id });
        }
    }

    pub fn emit_error(&self, source: ErrorSource, message: impl Into<String>) {
        let _ = self.event_tx.send(DiscoveryEvent::Error {
            source,
            message: message.into(),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CapabilitySet, Transport};

    fn ble_dev(id: &str, name: &str, rssi: i16, caps: CapabilitySet) -> Device {
        Device::builder(id, name)
            .transport(Transport::Ble)
            .capabilities(caps)
            .rssi(rssi)
            .build()
    }

    fn drain(rx: &mut broadcast::Receiver<DiscoveryEvent>) -> Vec<DiscoveryEvent> {
        let mut out = Vec::new();
        while let Ok(evt) = rx.try_recv() {
            out.push(evt);
        }
        out
    }

    #[test]
    fn first_observation_emits_seen() {
        let (tx, mut rx) = broadcast::channel(16);
        let mut tracker = PresenceTracker::new(tx, DEFAULT_STALE_AFTER);

        let dev = ble_dev("ble:abc", "WFL-Test", -50, CapabilitySet::SMP);
        tracker.observe(dev.clone());

        let events = drain(&mut rx);
        assert_eq!(events.len(), 1);
        assert!(matches!(&events[0], DiscoveryEvent::Seen { device } if device == &dev));
    }

    #[test]
    fn unchanged_re_observation_emits_nothing() {
        let (tx, mut rx) = broadcast::channel(16);
        let mut tracker = PresenceTracker::new(tx, DEFAULT_STALE_AFTER);

        let dev = ble_dev("ble:abc", "WFL-Test", -50, CapabilitySet::SMP);
        tracker.observe(dev.clone());
        let _ = drain(&mut rx);

        tracker.observe(dev);
        assert!(drain(&mut rx).is_empty());
    }

    #[test]
    fn changed_rssi_emits_updated() {
        let (tx, mut rx) = broadcast::channel(16);
        let mut tracker = PresenceTracker::new(tx, DEFAULT_STALE_AFTER);

        tracker.observe(ble_dev("ble:abc", "WFL-Test", -50, CapabilitySet::SMP));
        let _ = drain(&mut rx);

        tracker.observe(ble_dev("ble:abc", "WFL-Test", -65, CapabilitySet::SMP));
        let events = drain(&mut rx);
        assert_eq!(events.len(), 1);
        match &events[0] {
            DiscoveryEvent::Updated {
                id,
                name,
                capabilities,
                rssi,
            } => {
                assert_eq!(id.as_str(), "ble:abc");
                assert_eq!(name, "WFL-Test");
                assert_eq!(*capabilities, CapabilitySet::SMP);
                assert_eq!(*rssi, Some(-65));
            }
            other => panic!("expected Updated, got {other:?}"),
        }
    }

    #[test]
    fn changed_name_emits_updated() {
        let (tx, mut rx) = broadcast::channel(16);
        let mut tracker = PresenceTracker::new(tx, DEFAULT_STALE_AFTER);

        tracker.observe(ble_dev("ble:abc", "Initial", -50, CapabilitySet::SMP));
        let _ = drain(&mut rx);

        tracker.observe(ble_dev("ble:abc", "Resolved-Name", -50, CapabilitySet::SMP));
        let events = drain(&mut rx);
        assert_eq!(events.len(), 1);
        assert!(
            matches!(&events[0], DiscoveryEvent::Updated { name, .. } if name == "Resolved-Name")
        );
    }

    #[test]
    fn changed_capabilities_emits_updated() {
        let (tx, mut rx) = broadcast::channel(16);
        let mut tracker = PresenceTracker::new(tx, DEFAULT_STALE_AFTER);

        tracker.observe(ble_dev("ble:abc", "WFL", -50, CapabilitySet::SMP));
        let _ = drain(&mut rx);

        let new_caps = CapabilitySet::SMP | CapabilitySet::WIFI_PROV;
        tracker.observe(ble_dev("ble:abc", "WFL", -50, new_caps));
        let events = drain(&mut rx);
        assert_eq!(events.len(), 1);
        assert!(
            matches!(&events[0], DiscoveryEvent::Updated { capabilities, .. } if *capabilities == new_caps)
        );
    }

    #[test]
    fn forget_emits_lost_when_known() {
        let (tx, mut rx) = broadcast::channel(16);
        let mut tracker = PresenceTracker::new(tx, DEFAULT_STALE_AFTER);

        tracker.observe(ble_dev("ble:abc", "WFL", -50, CapabilitySet::SMP));
        let _ = drain(&mut rx);

        tracker.forget(&DeviceId::new("ble:abc"));
        let events = drain(&mut rx);
        assert_eq!(events.len(), 1);
        assert!(matches!(&events[0], DiscoveryEvent::Lost { id } if id.as_str() == "ble:abc"));
        assert!(tracker.get(&DeviceId::new("ble:abc")).is_none());
    }

    #[test]
    fn forget_unknown_id_is_noop() {
        let (tx, mut rx) = broadcast::channel(16);
        let mut tracker = PresenceTracker::new(tx, DEFAULT_STALE_AFTER);

        tracker.forget(&DeviceId::new("ble:unknown"));
        assert!(drain(&mut rx).is_empty());
    }

    #[test]
    fn evict_stale_emits_lost_for_old_entries() {
        let (tx, mut rx) = broadcast::channel(16);
        let mut tracker = PresenceTracker::new(tx, Duration::from_nanos(0));

        tracker.observe(ble_dev("ble:abc", "WFL", -50, CapabilitySet::SMP));
        tracker.observe(ble_dev("ble:def", "WFL2", -60, CapabilitySet::WIFI_PROV));
        let _ = drain(&mut rx);

        std::thread::sleep(Duration::from_millis(2));
        tracker.evict_stale();

        let events = drain(&mut rx);
        let lost_ids: Vec<_> = events
            .iter()
            .filter_map(|e| {
                if let DiscoveryEvent::Lost { id } = e {
                    Some(id.as_str().to_owned())
                } else {
                    None
                }
            })
            .collect();
        assert_eq!(lost_ids.len(), 2);
        assert!(lost_ids.contains(&"ble:abc".to_owned()));
        assert!(lost_ids.contains(&"ble:def".to_owned()));
    }

    #[test]
    fn evict_stale_keeps_fresh_entries() {
        let (tx, mut rx) = broadcast::channel(16);
        let mut tracker = PresenceTracker::new(tx, Duration::from_secs(60));

        tracker.observe(ble_dev("ble:abc", "WFL", -50, CapabilitySet::SMP));
        let _ = drain(&mut rx);

        tracker.evict_stale();
        assert!(drain(&mut rx).is_empty());
        assert_eq!(tracker.snapshot().len(), 1);
    }

    #[test]
    fn snapshot_returns_all_known_devices() {
        let (tx, _rx) = broadcast::channel(16);
        let mut tracker = PresenceTracker::new(tx, DEFAULT_STALE_AFTER);

        tracker.observe(ble_dev("ble:abc", "A", -50, CapabilitySet::SMP));
        tracker.observe(ble_dev("ble:def", "B", -60, CapabilitySet::WIFI_PROV));

        let snap = tracker.snapshot();
        assert_eq!(snap.len(), 2);
        let ids: Vec<_> = snap.iter().map(|d| d.id().as_str().to_owned()).collect();
        assert!(ids.contains(&"ble:abc".to_owned()));
        assert!(ids.contains(&"ble:def".to_owned()));
    }

    #[test]
    fn re_observation_after_change_keeps_state_in_sync() {
        let (tx, mut rx) = broadcast::channel(16);
        let mut tracker = PresenceTracker::new(tx, DEFAULT_STALE_AFTER);

        tracker.observe(ble_dev("ble:abc", "WFL", -50, CapabilitySet::SMP));
        let _ = drain(&mut rx);

        tracker.observe(ble_dev("ble:abc", "WFL", -60, CapabilitySet::SMP));
        let _ = drain(&mut rx);

        tracker.observe(ble_dev("ble:abc", "WFL", -60, CapabilitySet::SMP));
        assert!(drain(&mut rx).is_empty());
    }

    fn mdns_dev(id: &str, name: &str) -> Device {
        Device::builder(id, name)
            .transport(Transport::Tcp)
            .capabilities(CapabilitySet::empty())
            .build()
    }

    #[test]
    fn emit_error_does_not_touch_state() {
        let (tx, mut rx) = broadcast::channel(16);
        let mut tracker = PresenceTracker::new(tx, DEFAULT_STALE_AFTER);
        tracker.observe(ble_dev("ble:abc", "WFL", -50, CapabilitySet::SMP));
        let _ = drain(&mut rx);

        tracker.emit_error(ErrorSource::Ble, "transient adapter glitch");

        let events = drain(&mut rx);
        assert_eq!(events.len(), 1);
        assert!(matches!(
            &events[0],
            DiscoveryEvent::Error { source: ErrorSource::Ble, message } if message == "transient adapter glitch"
        ));
        assert_eq!(tracker.snapshot().len(), 1, "state must survive errors");
    }

    fn tracker_with_mdns_stale(
        tx: broadcast::Sender<DiscoveryEvent>,
        mdns_stale_after: Duration,
    ) -> PresenceTracker {
        let mut tracker = PresenceTracker::new(tx, DEFAULT_STALE_AFTER);
        tracker.mdns_stale_after = mdns_stale_after;
        tracker
    }

    #[test]
    fn evict_stale_emits_lost_for_old_mdns_entries() {
        let (tx, mut rx) = broadcast::channel(16);
        let mut tracker = tracker_with_mdns_stale(tx, Duration::from_nanos(0));
        let id = DeviceId::new("mdns:tcp:wfl-abcd._framelink._tcp.local.");

        tracker.observe(mdns_dev(id.as_str(), "wfl-abcd"));
        let _ = drain(&mut rx);

        std::thread::sleep(Duration::from_millis(2));
        tracker.evict_stale();

        let events = drain(&mut rx);
        assert_eq!(events.len(), 1);
        assert!(matches!(&events[0], DiscoveryEvent::Lost { id: ev_id } if ev_id == &id));
        assert!(tracker.get(&id).is_none());
    }

    #[test]
    fn evict_stale_keeps_fresh_mdns_entries() {
        let (tx, mut rx) = broadcast::channel(16);
        let mut tracker = tracker_with_mdns_stale(tx, Duration::from_secs(60));
        let id = DeviceId::new("mdns:tcp:wfl-abcd._framelink._tcp.local.");

        tracker.observe(mdns_dev(id.as_str(), "wfl-abcd"));
        let _ = drain(&mut rx);

        tracker.evict_stale();
        assert!(drain(&mut rx).is_empty());
        assert!(tracker.get(&id).is_some());
    }

    #[test]
    fn observe_refreshes_mdns_last_seen() {
        let (tx, mut rx) = broadcast::channel(16);
        let mut tracker = tracker_with_mdns_stale(tx, Duration::from_millis(50));
        let id = DeviceId::new("mdns:tcp:wfl-abcd._framelink._tcp.local.");

        tracker.observe(mdns_dev(id.as_str(), "wfl-abcd"));
        std::thread::sleep(Duration::from_millis(30));
        tracker.observe(mdns_dev(id.as_str(), "wfl-abcd"));
        let _ = drain(&mut rx);

        std::thread::sleep(Duration::from_millis(30));
        tracker.evict_stale();
        assert!(drain(&mut rx).is_empty());
        assert!(tracker.get(&id).is_some());
    }

    #[test]
    fn evict_stale_uses_separate_thresholds_per_transport() {
        let (tx, mut rx) = broadcast::channel(16);
        let mut tracker = PresenceTracker::new(tx, Duration::from_nanos(0));
        tracker.mdns_stale_after = Duration::from_secs(60);

        tracker.observe(ble_dev("ble:abc", "WFL", -50, CapabilitySet::SMP));
        tracker.observe(mdns_dev(
            "mdns:tcp:wfl-1234._framelink._tcp.local.",
            "wfl-1234",
        ));
        let _ = drain(&mut rx);

        std::thread::sleep(Duration::from_millis(2));
        tracker.evict_stale();

        let events = drain(&mut rx);
        let lost_ids: Vec<_> = events
            .iter()
            .filter_map(|e| {
                if let DiscoveryEvent::Lost { id } = e {
                    Some(id.as_str().to_owned())
                } else {
                    None
                }
            })
            .collect();
        assert_eq!(lost_ids, vec!["ble:abc".to_owned()]);
        assert!(tracker.get(&DeviceId::new("ble:abc")).is_none());
        assert!(
            tracker
                .get(&DeviceId::new("mdns:tcp:wfl-1234._framelink._tcp.local."))
                .is_some()
        );
    }
}
