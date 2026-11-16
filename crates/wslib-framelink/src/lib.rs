//! A FrameLink device over TCP, or over ISO-TP on CAN with `can`.
//! [`FrameLinkSession`] serialises requests and replies and carries the
//! device's stream. [`Peer`] names the device it talks to. With `discovery`,
//! [`Discovery`] finds devices over mDNS, and over BLE with `ble`. With `smp`,
//! it opens their SMP sessions and updates their firmware.

pub mod board;
mod capability;
mod client;
mod device;
mod error;
mod identify;
mod peer;
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
#[cfg(feature = "can")]
pub use client::can_link_config;
pub use device::{Device, DeviceBuilder, DeviceId, Transport};
pub use error::Error;
pub use identify::{DEFAULT_TX_QUEUE_DEPTH, DeviceIdentity};
pub use peer::{Peer, PeerParseError};
pub use probe::{Probe, probe, probe_version};
pub use session::{
    FileProgress, FileUploadOutcome, FrameLinkSession, SessionConfig, TransmitStats,
};
pub use wslib_can_bus::{BusConfig, CanBus, CanMode};
pub use wslib_framelink_protocol::can_id::{
    DeviceId as CanDeviceId, DeviceIdError as CanDeviceIdError,
};

#[cfg(feature = "smp")]
pub use discovery::{
    CancelOutcome, OtaCancel, OtaEvent, OtaOptions, OtaStream, ota_udp_addr,
    ota_udp_addr_cancellable,
};
#[cfg(feature = "discovery")]
pub use discovery::{Discovery, DiscoveryEvent, ErrorSource};
#[cfg(feature = "smp")]
pub use wslib_mcumgr::{self as mcumgr, ImageSlot, UploadOptions, UploadProgress};
