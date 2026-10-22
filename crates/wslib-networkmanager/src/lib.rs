//! NetworkManager over D-Bus, typed: devices and their addresses, Wi-Fi scan
//! and join, checkpoints, profile updates and the Wi-Fi radio.
//!
//! ```no_run
//! # async fn run() -> Result<(), Box<dyn std::error::Error>> {
//! use wslib_networkmanager::{Client, DeviceKind};
//!
//! let nm = Client::new(zbus::Connection::system().await?);
//! let devices = nm.devices().await?;
//! let wifi = devices.iter().find(|d| d.kind == DeviceKind::Wifi).ok_or("no Wi-Fi")?;
//! for network in nm.scan(&wifi.path).await? {
//!     println!("{} {}%", String::from_utf8_lossy(&network.ssid), network.strength);
//! }
//! let profile = wifi.wifi_profile(b"Ops", Some("correct horse"))?;
//! nm.add_and_activate(profile, &wifi.path).await?;
//! # Ok(())
//! # }
//! ```
//!
//! The `testing` feature adds [`testing::FakeNetworkManager`], on Unix.

mod client;
mod device;
mod profile;
mod props;
mod proxy;
#[cfg(all(unix, feature = "testing"))]
pub mod testing;
mod wifi;

pub use client::{Client, Joined, RollbackResult, WifiRadio, checkpoint};
pub use device::{AccessPoint, Address, Device, DeviceKind, DeviceState, IpConfig, reason};
pub use profile::{Ipv4, ProfileIpv4, connection_type, set_ipv4};
pub use proxy::{
    DeviceProxy, Group, NetworkManagerProxy, NmObjectsProxy, NmSettingsProxy, Objects,
    ProfileProxy, Settings, WirelessProxy,
};
pub use wifi::{JoinError, Security};
