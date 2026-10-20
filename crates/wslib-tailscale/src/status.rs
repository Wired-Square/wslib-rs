use std::fmt;
use std::net::IpAddr;

use serde::{Deserialize, Deserializer};

/// The node as `/localapi/v0/status` reports it.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
#[non_exhaustive]
pub struct Status {
    pub backend_state: BackendState,
    #[serde(rename = "Self", default)]
    pub own: Option<OwnNode>,
    #[serde(rename = "TailscaleIPs", default, deserialize_with = "null_as_empty")]
    pub addresses: Vec<IpAddr>,
    #[serde(default, deserialize_with = "null_as_empty")]
    pub health: Vec<String>,
}

/// This machine's own node in a [`Status`].
#[derive(Debug, Clone, Deserialize)]
#[non_exhaustive]
pub struct OwnNode {
    #[serde(rename = "DNSName", default)]
    pub dns_name: String,
    #[serde(rename = "HostName", default)]
    pub host_name: String,
}

/// The node's settings as `/localapi/v0/prefs` reports them.
#[derive(Debug, Clone, Deserialize)]
#[non_exhaustive]
pub struct Prefs {
    #[serde(rename = "ControlURL", default, deserialize_with = "empty_as_none")]
    pub control_url: Option<String>,
}

/// Where tailscaled is in its life; `Other` holds a state newer than this crate.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum BackendState {
    NoState,
    NeedsLogin,
    NeedsMachineAuth,
    Stopped,
    Starting,
    Running,
    Other(String),
}

impl Status {
    /// The node's DNS name without its trailing dot, if it has one.
    pub fn name(&self) -> Option<&str> {
        let name = self.own.as_ref()?.dns_name.trim_end_matches('.');
        (!name.is_empty()).then_some(name)
    }

    /// The node's name while it is on its tailnet.
    ///
    /// Only the control server names a node, and a logged-out node keeps the
    /// name it had, so a node that needs a login is not enrolled.
    pub fn enrolled(&self) -> Option<&str> {
        match self.backend_state {
            BackendState::NoState | BackendState::NeedsLogin => None,
            _ => self.name(),
        }
    }
}

impl BackendState {
    /// The name tailscaled gives the state.
    pub fn as_str(&self) -> &str {
        match self {
            Self::NoState => "NoState",
            Self::NeedsLogin => "NeedsLogin",
            Self::NeedsMachineAuth => "NeedsMachineAuth",
            Self::Stopped => "Stopped",
            Self::Starting => "Starting",
            Self::Running => "Running",
            Self::Other(state) => state,
        }
    }
}

impl From<String> for BackendState {
    fn from(state: String) -> Self {
        match state.as_str() {
            "NoState" => Self::NoState,
            "NeedsLogin" => Self::NeedsLogin,
            "NeedsMachineAuth" => Self::NeedsMachineAuth,
            "Stopped" => Self::Stopped,
            "Starting" => Self::Starting,
            "Running" => Self::Running,
            _ => Self::Other(state),
        }
    }
}

impl fmt::Display for BackendState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for BackendState {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer).map(Self::from)
    }
}

/// Go writes a nil slice as `null`.
fn null_as_empty<'de, D: Deserializer<'de>, T: Deserialize<'de>>(
    deserializer: D,
) -> Result<Vec<T>, D::Error> {
    Option::deserialize(deserializer).map(Option::unwrap_or_default)
}

fn empty_as_none<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Option<String>, D::Error> {
    Option::<String>::deserialize(deserializer).map(|s| s.filter(|s| !s.is_empty()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn status(json: serde_json::Value) -> Status {
        serde_json::from_value(json).unwrap()
    }

    #[test]
    fn an_enrolled_node_has_its_name_addresses_and_health() {
        let status = status(json!({
            "BackendState": "Running",
            "TailscaleIPs": ["100.64.0.7", "fd7a:115c:a1e0::7"],
            "Health": ["no DERP home"],
            "Self": {"DNSName": "box-1.example.ts.net.", "HostName": "box-1"},
            "Peer": {},
        }));
        assert_eq!(status.backend_state, BackendState::Running);
        assert_eq!(status.enrolled(), Some("box-1.example.ts.net"));
        assert_eq!(status.own.unwrap().host_name, "box-1");
        assert_eq!(status.addresses.len(), 2);
        assert_eq!(status.health, ["no DERP home"]);
    }

    #[test]
    fn a_node_needing_a_login_is_not_enrolled_even_with_a_name() {
        let status = status(json!({
            "BackendState": "NeedsLogin",
            "Self": {"DNSName": "box-1.example.ts.net.", "HostName": "box-1"},
        }));
        assert_eq!(status.name(), Some("box-1.example.ts.net"));
        assert_eq!(status.enrolled(), None);
    }

    #[test]
    fn a_node_without_a_dns_name_is_not_enrolled_whatever_its_state() {
        let status = status(json!({
            "BackendState": "Starting",
            "Self": {"DNSName": "", "HostName": "box-1"},
        }));
        assert_eq!(status.enrolled(), None);
    }

    #[test]
    fn null_slices_and_self_read_as_empty() {
        let status = status(json!({
            "BackendState": "NoState",
            "TailscaleIPs": null,
            "Health": null,
            "Self": null,
        }));
        assert!(status.addresses.is_empty() && status.health.is_empty());
        assert!(status.own.is_none());
    }

    #[test]
    fn an_unknown_state_is_kept_by_name() {
        let status = status(json!({"BackendState": "Dreaming"}));
        assert_eq!(status.backend_state, BackendState::Other("Dreaming".into()));
        assert_eq!(status.backend_state.to_string(), "Dreaming");
    }

    #[test]
    fn an_empty_control_url_is_none() {
        let prefs = |url| serde_json::from_value::<Prefs>(json!({"ControlURL": url})).unwrap();
        assert_eq!(prefs("").control_url, None);
        assert_eq!(
            prefs("https://hs.example.com").control_url.as_deref(),
            Some("https://hs.example.com")
        );
    }
}
