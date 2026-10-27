//! What a host reports that the appliance reads: the clock, what a factory
//! reset did, and the box's identity as a bundle carries it.

use std::net::Ipv4Addr;

use serde::{Deserialize, Serialize};

/// The box's clock: `GET /api/host/clock`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(tag = "state", rename_all = "snake_case")]
#[cfg_attr(feature = "ts", ts(export))]
pub enum ClockView {
    Ready {
        /// The mechanism in use — "systemd-timedated".
        via: String,
        /// An IANA name, or `None` when timedated cannot name one.
        timezone: Option<String>,
        ntp: Ntp,
        /// Whether the kernel counts its clock as synchronised, by anything.
        synced: bool,
        /// The server systemd-timesyncd is using, if any.
        server: Option<String>,
    },
    Unsupported {
        because: String,
    },
}

/// Whether the NTP service systemd-timedated manages is running.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "ts", ts(export))]
pub enum Ntp {
    On,
    Off,
    /// systemd-timedated knows of no NTP service to switch on.
    Absent,
}

/// How an interface gets its IPv4 address: `PUT /api/host/interfaces/{name}/address`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(tag = "method", rename_all = "snake_case")]
#[cfg_attr(feature = "ts", ts(export))]
pub enum AddressConfig {
    Dhcp {
        /// Resolvers to use instead of the lease's; empty means the lease's.
        #[serde(default)]
        dns: Vec<Ipv4Addr>,
    },
    Static {
        address: Ipv4Addr,
        /// CIDR prefix length, not a netmask.
        prefix: u8,
        gateway: Option<Ipv4Addr>,
        #[serde(default)]
        dns: Vec<Ipv4Addr>,
    },
}

impl AddressConfig {
    /// Refuse what would take the box off the network; call it before taking a checkpoint.
    pub fn validate(&self) -> Result<(), String> {
        let dns = match self {
            Self::Dhcp { dns } | Self::Static { dns, .. } => dns,
        };
        if let Some(bad) = dns.iter().find(|d| d.is_unspecified() || d.is_broadcast()) {
            return Err(format!("{bad} is not a resolver address"));
        }
        let Self::Static {
            address,
            prefix,
            gateway,
            ..
        } = self
        else {
            return Ok(());
        };
        if !(1..=30).contains(prefix) {
            return Err(format!(
                "/{prefix} is not a usable prefix for a host — /31 and /32 leave no room for \
                 a gateway, and /0 is not a subnet"
            ));
        }
        if address.is_unspecified() {
            return Err("0.0.0.0 is not an address to give an interface".into());
        }
        if address.is_broadcast() || address.is_multicast() {
            return Err(format!("{address} is not a host address"));
        }
        if address.is_loopback() {
            return Err(format!(
                "{address} is a loopback address — the box would answer only to itself"
            ));
        }
        if let Some(gateway) = gateway {
            if !same_subnet(*address, *gateway, *prefix) {
                return Err(format!(
                    "gateway {gateway} is not reachable from {address}/{prefix} — nothing \
                     outside this subnet would be reachable"
                ));
            }
            if gateway == address {
                return Err("the gateway cannot be this interface's own address".into());
            }
        }
        Ok(())
    }

    /// The address a client would reach this box on afterwards; `None` for DHCP.
    pub fn resulting_address(&self) -> Option<Ipv4Addr> {
        match self {
            Self::Dhcp { .. } => None,
            Self::Static { address, .. } => Some(*address),
        }
    }

    /// Whether this would leave `address` off the interface's subnet; DHCP never does.
    pub fn strands(&self, address: Ipv4Addr) -> bool {
        match self {
            Self::Dhcp { .. } => false,
            Self::Static {
                address: ours,
                prefix,
                ..
            } => !same_subnet(*ours, address, *prefix),
        }
    }
}

/// Total in the prefix: 0 masks nothing, and past 32 masks everything.
fn same_subnet(a: Ipv4Addr, b: Ipv4Addr, prefix: u8) -> bool {
    let mask = u32::MAX
        .checked_shl(32u32.saturating_sub(u32::from(prefix)))
        .unwrap_or(0);
    (u32::from(a) & mask) == (u32::from(b) & mask)
}

/// What a factory reset did.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts", ts(export))]
pub struct ResetReport {
    pub erased: Vec<String>,
    pub kept: Vec<String>,
    /// Each a sentence; `erased` and `kept` are list items.
    pub warnings: Vec<String>,
}

/// One account's authorised-keys file, verbatim, as a bundle carries it.
#[doc(hidden)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SshKeyFile {
    /// The account, which names the file: one path segment.
    pub user: String,
    pub contents: String,
}

/// One interface's addressing, as a bundle carries it and a restore reports.
#[doc(hidden)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InterfaceAddress {
    pub name: String,
    pub address: AddressConfig,
}

/// `eth0 at 10.0.50.12/24 via 10.0.50.1`, or `eth0 from DHCP`.
impl std::fmt::Display for InterfaceAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.address {
            AddressConfig::Dhcp { .. } => write!(f, "{} from DHCP", self.name),
            AddressConfig::Static {
                address,
                prefix,
                gateway,
                ..
            } => {
                write!(f, "{} at {address}/{prefix}", self.name)?;
                match gateway {
                    Some(gateway) => write!(f, " via {gateway}"),
                    None => Ok(()),
                }
            }
        }
    }
}

/// The box's name and addressing, as a bundle carries it.
#[doc(hidden)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostSection {
    pub hostname: String,
    pub interfaces: Vec<InterfaceAddress>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn static_at(address: &str, prefix: u8, gateway: Option<&str>) -> AddressConfig {
        AddressConfig::Static {
            address: address.parse().unwrap(),
            prefix,
            gateway: gateway.map(|g| g.parse().unwrap()),
            dns: Vec::new(),
        }
    }

    #[test]
    fn an_address_that_would_take_the_box_off_the_network_is_refused() {
        assert!(
            static_at("10.0.50.12", 24, Some("10.0.50.1"))
                .validate()
                .is_ok()
        );
        assert!(
            static_at("10.0.50.12", 16, Some("10.0.60.1"))
                .validate()
                .is_ok()
        );
        assert!(AddressConfig::Dhcp { dns: Vec::new() }.validate().is_ok());

        let refused = |config: AddressConfig| config.validate().unwrap_err();
        assert!(refused(static_at("10.0.50.12", 24, Some("10.0.60.1"))).contains("not reachable"));
        assert!(refused(static_at("10.0.50.12", 24, Some("10.0.50.12"))).contains("own address"));
        for prefix in [0, 31, 32, 33] {
            assert!(
                static_at("10.0.50.12", prefix, None).validate().is_err(),
                "/{prefix}"
            );
        }
        for address in ["0.0.0.0", "255.255.255.255", "224.0.0.1", "127.0.0.1"] {
            assert!(
                static_at(address, 24, None).validate().is_err(),
                "{address}"
            );
        }
        assert!(
            AddressConfig::Dhcp {
                dns: vec![Ipv4Addr::UNSPECIFIED]
            }
            .validate()
            .unwrap_err()
            .contains("resolver")
        );
    }

    #[test]
    fn a_prefix_off_either_end_does_not_panic() {
        let (a, b) = ("10.0.0.1".parse().unwrap(), "192.168.0.2".parse().unwrap());
        assert!(same_subnet(a, b, 0), "0 masks nothing");
        assert!(!same_subnet(a, b, 40), "past 32 masks everything");
    }

    #[test]
    fn dhcp_promises_no_address_and_strands_nobody() {
        let dhcp = AddressConfig::Dhcp { dns: Vec::new() };
        assert_eq!(dhcp.resulting_address(), None);
        assert!(!dhcp.strands("10.0.60.7".parse().unwrap()));
        let fixed = static_at("10.0.50.12", 24, None);
        assert_eq!(
            fixed.resulting_address(),
            Some("10.0.50.12".parse().unwrap())
        );
        assert!(fixed.strands("10.0.60.7".parse().unwrap()));
        assert!(!fixed.strands("10.0.50.7".parse().unwrap()));
        assert!(static_at("10.0.50.12", 40, None).strands("10.0.60.7".parse().unwrap()));
    }

    #[test]
    fn the_method_is_the_serde_tag() {
        let json = serde_json::to_string(&AddressConfig::Dhcp { dns: Vec::new() }).unwrap();
        assert!(json.contains("\"method\":\"dhcp\""), "{json}");
        let json = serde_json::to_string(&static_at("10.0.50.12", 24, None)).unwrap();
        assert!(json.contains("\"method\":\"static\""), "{json}");
    }
}
