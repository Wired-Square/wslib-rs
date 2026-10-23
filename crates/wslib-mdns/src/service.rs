use std::fmt;
use std::net::IpAddr;

use tokio::sync::watch;

use crate::{InstanceName, Invalid, ServiceType, Subtype, Txt};

/// A service to advertise.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Service {
    pub kind: ServiceType,
    pub subtypes: Vec<Subtype>,
    pub instance: InstanceName,
    pub port: u16,
    pub txt: Vec<Txt>,
}

impl Service {
    pub fn new(kind: ServiceType, instance: InstanceName, port: u16) -> Self {
        Self {
            kind,
            subtypes: Vec::new(),
            instance,
            port,
            txt: Vec::new(),
        }
    }

    #[cfg(any(feature = "in-process", feature = "avahi"))]
    pub(crate) fn subtypes_of_its_kind(&self) -> Result<&[Subtype], Error> {
        if self.subtypes.iter().any(|s| s.kind() != &self.kind) {
            return Err(Error::Unsupported("a subtype of another service type"));
        }
        Ok(&self.subtypes)
    }
}

/// A service found on the network, with its host's addresses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolved {
    pub instance: InstanceName,
    /// The target host, such as `widget.local`.
    pub host: String,
    pub port: u16,
    pub addrs: Vec<IpAddr>,
    pub txt: Vec<Txt>,
}

impl Resolved {
    pub fn txt(&self, key: &str) -> Option<&str> {
        self.txt
            .iter()
            .find(|t| t.key().eq_ignore_ascii_case(key))
            .map(Txt::value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BrowseEvent {
    Resolved(Resolved),
    Removed(InstanceName),
}

/// Where an advert stands on the network.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum AdvertState {
    Registering,
    Established,
    /// Another host holds the name and the advert is down; nothing renames it.
    Collided,
    /// Established under this name, after another host held the one asked for.
    Renamed(InstanceName),
    /// The responder withdrew it for a reason of its own.
    Failed,
}

/// A published advert, withdrawn when dropped.
#[derive(Debug)]
pub struct Advert {
    pub(crate) state: watch::Receiver<AdvertState>,
    pub(crate) held: Held,
}

#[derive(Debug)]
pub(crate) enum Held {
    #[cfg(feature = "in-process")]
    InProcess(crate::in_process::Registered),
    #[cfg(feature = "avahi")]
    Avahi(crate::avahi::Group),
}

impl Advert {
    pub fn state(&self) -> watch::Receiver<AdvertState> {
        self.state.clone()
    }

    /// Withdraws it now, waiting until the responder has.
    pub async fn withdraw(self) -> Result<(), Error> {
        match self.held {
            #[cfg(feature = "in-process")]
            Held::InProcess(registered) => registered.withdraw().await,
            #[cfg(feature = "avahi")]
            Held::Avahi(group) => group.withdraw().await,
        }
    }
}

#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// What this responder cannot publish, or a second browse of one type.
    Unsupported(&'static str),
    Invalid(Invalid),
    /// Another avahi client on this machine already holds the name.
    #[cfg(feature = "avahi")]
    Collision(zbus::Error),
    /// Nothing owns `org.freedesktop.Avahi` on the bus.
    #[cfg(feature = "avahi")]
    NotRunning(zbus::Error),
    #[cfg(feature = "avahi")]
    Bus(zbus::Error),
    /// The in-process responder refused, in its own words.
    #[cfg(feature = "in-process")]
    Daemon(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsupported(what) => write!(f, "unsupported: {what}"),
            Self::Invalid(e) => e.fmt(f),
            #[cfg(feature = "avahi")]
            Self::Collision(_) => f.write_str("another client of avahi already holds the name"),
            #[cfg(feature = "avahi")]
            Self::NotRunning(_) => f.write_str("avahi is not running"),
            #[cfg(feature = "avahi")]
            Self::Bus(e) => write!(f, "avahi: {e}"),
            #[cfg(feature = "in-process")]
            Self::Daemon(e) => write!(f, "mDNS: {e}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            #[cfg(feature = "avahi")]
            Self::Bus(e) | Self::Collision(e) | Self::NotRunning(e) => Some(e),
            Self::Invalid(e) => Some(e),
            _ => None,
        }
    }
}

impl From<Invalid> for Error {
    fn from(e: Invalid) -> Self {
        Self::Invalid(e)
    }
}
