use crate::{CapabilitySet, Device, DeviceId};
use serde::{Deserialize, Serialize};

/// A change in the devices seen. `Updated` is a change of name,
/// capabilities or RSSI; `Lost` is a device unseen too long. `Error` is a
/// transport's hiccup, and the stream goes on. A session's own link drop is
/// its error, not an event.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
#[non_exhaustive]
pub enum DiscoveryEvent {
    Seen {
        device: Device,
    },
    Updated {
        id: DeviceId,
        name: String,
        capabilities: CapabilitySet,
        rssi: Option<i16>,
    },
    Lost {
        id: DeviceId,
    },
    Error {
        source: ErrorSource,
        message: String,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum ErrorSource {
    Ble,
    Mdns,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Capability, Transport};

    #[test]
    fn seen_event_serde_round_trips() {
        let dev = Device::builder("ble:abc", "WFL-Test")
            .transport(Transport::Ble)
            .capabilities(CapabilitySet::SMP)
            .rssi(-67)
            .build();
        let evt = DiscoveryEvent::Seen { device: dev };
        let json = serde_json::to_string(&evt).unwrap();
        let back: DiscoveryEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(back, evt);
    }

    #[test]
    fn updated_event_serialises_with_kind_tag() {
        let evt = DiscoveryEvent::Updated {
            id: DeviceId::new("ble:abc"),
            name: "WFL-Test".into(),
            capabilities: [Capability::WifiProv].into_iter().collect(),
            rssi: Some(-50),
        };
        let json = serde_json::to_string(&evt).unwrap();
        assert!(json.contains(r#""kind":"updated""#), "got {json}");
        let back: DiscoveryEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(back, evt);
    }

    #[test]
    fn lost_event_serialises_with_kind_tag() {
        let evt = DiscoveryEvent::Lost {
            id: DeviceId::new("ble:abc"),
        };
        let json = serde_json::to_string(&evt).unwrap();
        assert_eq!(json, r#"{"kind":"lost","id":"ble:abc"}"#);
    }

    #[test]
    fn error_event_carries_source() {
        let evt = DiscoveryEvent::Error {
            source: ErrorSource::Ble,
            message: "adapter polling stuttered".into(),
        };
        let json = serde_json::to_string(&evt).unwrap();
        assert!(json.contains(r#""source":"ble""#), "got {json}");
        let back: DiscoveryEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(back, evt);
    }
}
