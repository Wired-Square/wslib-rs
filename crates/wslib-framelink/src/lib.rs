//! A FrameLink device over TCP: [`FrameLinkSession`] serialises requests and
//! replies and carries the device's stream. With `discovery`, [`Discovery`]
//! finds devices over mDNS, and over BLE with `ble`; with `smp`, it opens
//! their SMP sessions and updates their firmware.

pub mod board;
mod capability;
mod client;
mod device;
mod error;
mod identify;
mod probe;
mod session;

#[cfg(feature = "ble")]
pub mod ble;
#[cfg(feature = "discovery")]
pub mod discovery;
#[cfg(feature = "discovery")]
pub mod registry;
#[cfg(all(feature = "ble", feature = "discovery"))]
mod runtime;

pub use capability::{Capability, CapabilityIter, CapabilitySet};
pub use client::FramingStats;
pub use device::{Device, DeviceBuilder, DeviceId, Transport};
pub use error::Error;
pub use identify::{DEFAULT_TX_QUEUE_DEPTH, DeviceIdentity};
pub use probe::{Probe, probe, probe_version};
pub use session::{
    FileProgress, FileUploadOutcome, FrameLinkSession, SessionConfig, TransmitStats,
};

#[cfg(feature = "discovery")]
pub use discovery::{Discovery, DiscoveryEvent, ErrorSource};
#[cfg(feature = "smp")]
pub use discovery::{OtaEvent, OtaOptions, OtaStream, ota_udp_addr};
#[cfg(feature = "smp")]
pub use wslib_mcumgr::{self as mcumgr, ImageSlot, UploadProgress};
