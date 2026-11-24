use std::error::Error;
use std::iter::successors;
use std::sync::Arc;

use crate::{CapabilitySet, Device, DeviceId};
use serde::{Deserialize, Serialize};

pub(crate) type Cause = Arc<dyn Error + Send + Sync>;

/// A change in the devices seen. `Updated` is a change of name,
/// capabilities or RSSI; `Lost` is a device unseen too long. `Error` is a
/// transport's hiccup, and the stream goes on. A session's own link drop is
/// its error, not an event.
#[derive(Clone, Debug, Serialize, Deserialize)]
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
    /// `message` is this crate's sentence; `cause`, on the live value only,
    /// is the error behind it. `causes` is what `cause` and each error under
    /// it say, outermost first, for a reader of the serialised form.
    Error {
        source: ErrorSource,
        message: String,
        #[serde(skip)]
        cause: Option<Cause>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        causes: Vec<String>,
    },
}

impl DiscoveryEvent {
    /// An `Error` whose `causes` are read from `cause`.
    pub fn error(
        source: ErrorSource,
        message: impl Into<String>,
        cause: Option<Arc<dyn Error + Send + Sync>>,
    ) -> Self {
        let outermost = cause
            .as_deref()
            .map(|cause| cause as &(dyn Error + 'static));
        Self::Error {
            source,
            message: message.into(),
            causes: successors(outermost, |&error| error.source())
                .map(ToString::to_string)
                .collect(),
            cause,
        }
    }
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

    fn round_trips(evt: &DiscoveryEvent) -> String {
        let json = serde_json::to_string(evt).unwrap();
        let back: DiscoveryEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(serde_json::to_string(&back).unwrap(), json);
        json
    }

    #[test]
    fn seen_event_serde_round_trips() {
        let dev = Device::builder("ble:abc", "WFL-Test")
            .transport(Transport::Ble)
            .capabilities(CapabilitySet::SMP)
            .rssi(-67)
            .build();
        let json = round_trips(&DiscoveryEvent::Seen {
            device: dev.clone(),
        });
        let back: DiscoveryEvent = serde_json::from_str(&json).unwrap();
        assert!(matches!(back, DiscoveryEvent::Seen { device } if device == dev));
    }

    #[test]
    fn updated_event_serialises_with_kind_tag() {
        let json = round_trips(&DiscoveryEvent::Updated {
            id: DeviceId::new("ble:abc"),
            name: "WFL-Test".into(),
            capabilities: [Capability::WifiProv].into_iter().collect(),
            rssi: Some(-50),
        });
        assert!(json.contains(r#""kind":"updated""#), "got {json}");
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
    fn error_event_serialises_what_each_cause_says_and_keeps_the_cause_itself_off_the_wire() {
        let evt = DiscoveryEvent::error(
            ErrorSource::Ble,
            "adapter polling stuttered",
            Some(Arc::new(crate::Error::Mdns(wslib_mdns::Error::Thread(
                std::io::Error::other("no threads left"),
            )))),
        );
        let json = round_trips(&evt);
        assert_eq!(
            json,
            r#"{"kind":"error","source":"ble","message":"adapter polling stuttered","causes":["mDNS failed","the mDNS responder's event thread could not start","no threads left"]}"#
        );
        let back: DiscoveryEvent = serde_json::from_str(&json).unwrap();
        assert!(
            matches!(&back, DiscoveryEvent::Error { cause: None, causes, .. } if causes.len() == 3)
        );
    }

    #[test]
    fn error_event_with_no_cause_serialises_no_causes() {
        let json = round_trips(&DiscoveryEvent::error(
            ErrorSource::Mdns,
            "no IPv4 address",
            None,
        ));
        assert_eq!(
            json,
            r#"{"kind":"error","source":"mdns","message":"no IPv4 address"}"#
        );
        let back: DiscoveryEvent = serde_json::from_str(&json).unwrap();
        assert!(matches!(&back, DiscoveryEvent::Error { causes, .. } if causes.is_empty()));
    }
}
