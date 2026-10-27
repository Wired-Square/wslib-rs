//! What this installation is: the build, the box it runs on, and whether each
//! optional part of it came up. The appliance's facts are typed fields, a
//! product's are [`Fact`]s, and its optional parts are [`Subsystem`]s.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::Availability;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts", ts(export))]
#[non_exhaustive]
pub struct AboutView {
    /// The product's name, as the version row is labelled.
    pub product: String,
    /// The product's version and the commit it was built from.
    pub version: String,
    #[cfg_attr(feature = "ts", ts(type = "number"))]
    pub daemon_uptime_s: u64,
    /// `now − uptime`, not a stamp taken at start.
    pub daemon_started_at: DateTime<Utc>,
    #[cfg_attr(feature = "ts", ts(type = "number | null"))]
    pub host_uptime_s: Option<u64>,
    /// The kernel's name as the daemon sees it.
    pub hostname: Option<String>,
    /// What a bundle's [`box_id`](crate::backup::BundleHeader::box_id) is compared with.
    pub box_id: Option<String>,
    /// `PRETTY_NAME` from `/etc/os-release`, or e.g. `macOS 26.6.2`.
    pub os: Option<String>,
    pub kernel: Option<String>,
    pub architecture: String,
    pub facts: Vec<Fact>,
    pub subsystems: Vec<Subsystem>,
}

/// One labelled value under "This installation", as `Devices`: `2 of 3 reachable`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts", ts(export))]
pub struct Fact {
    pub label: String,
    pub value: String,
}

impl Fact {
    pub fn new(label: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            label: label.into(),
            value: value.into(),
        }
    }
}

/// One optional part of the installation, and whether it is in use.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts", ts(export))]
pub struct Subsystem {
    pub name: String,
    pub availability: Availability,
}

impl Subsystem {
    pub fn new(name: impl Into<String>, availability: Availability) -> Self {
        Self {
            name: name.into(),
            availability,
        }
    }
}
