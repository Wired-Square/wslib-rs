use std::collections::HashMap;

use zbus::proxy;
use zbus::zvariant::{ObjectPath, OwnedObjectPath, OwnedValue};

/// One setting group's properties, `a{sv}`.
pub type Group = HashMap<String, OwnedValue>;

/// A connection profile's settings, `a{sa{sv}}`: a group name (`connection`,
/// `ipv4`, `802-11-wireless`) to its properties.
pub type Settings = HashMap<String, Group>;

/// `GetManagedObjects`' answer: path, then interface, then property.
pub type Objects = HashMap<OwnedObjectPath, HashMap<String, Group>>;

/// NetworkManager's root object: activation, checkpoints and the Wi-Fi radio.
#[proxy(
    interface = "org.freedesktop.NetworkManager",
    default_service = "org.freedesktop.NetworkManager",
    default_path = "/org/freedesktop/NetworkManager"
)]
pub trait NetworkManager {
    fn activate_connection(
        &self,
        connection: &ObjectPath<'_>,
        device: &ObjectPath<'_>,
        specific_object: &ObjectPath<'_>,
    ) -> zbus::Result<OwnedObjectPath>;

    /// The new profile's path and its active connection's.
    fn add_and_activate_connection(
        &self,
        connection: Settings,
        device: &ObjectPath<'_>,
        specific_object: &ObjectPath<'_>,
    ) -> zbus::Result<(OwnedObjectPath, OwnedObjectPath)>;

    fn checkpoint_create(
        &self,
        devices: &[&ObjectPath<'_>],
        rollback_timeout: u32,
        flags: u32,
    ) -> zbus::Result<OwnedObjectPath>;

    fn checkpoint_destroy(&self, checkpoint: &ObjectPath<'_>) -> zbus::Result<()>;

    /// Each device's path to its `NMRollbackResult`.
    fn checkpoint_rollback(
        &self,
        checkpoint: &ObjectPath<'_>,
    ) -> zbus::Result<HashMap<String, u32>>;

    #[zbus(property)]
    fn checkpoints(&self) -> zbus::Result<Vec<OwnedObjectPath>>;
    #[zbus(property)]
    fn wireless_enabled(&self) -> zbus::Result<bool>;
    #[zbus(property)]
    fn set_wireless_enabled(&self, enabled: bool) -> zbus::Result<()>;
    #[zbus(property)]
    fn wireless_hardware_enabled(&self) -> zbus::Result<bool>;
}

/// NetworkManager's whole object tree in one round trip.
#[proxy(
    interface = "org.freedesktop.DBus.ObjectManager",
    default_service = "org.freedesktop.NetworkManager",
    default_path = "/org/freedesktop"
)]
pub trait NmObjects {
    fn get_managed_objects(&self) -> zbus::Result<Objects>;
}

#[proxy(
    interface = "org.freedesktop.NetworkManager.Settings",
    default_service = "org.freedesktop.NetworkManager",
    default_path = "/org/freedesktop/NetworkManager/Settings"
)]
pub trait NmSettings {
    fn list_connections(&self) -> zbus::Result<Vec<OwnedObjectPath>>;
}

/// One device, at its path in the tree.
#[proxy(
    interface = "org.freedesktop.NetworkManager.Device",
    default_service = "org.freedesktop.NetworkManager"
)]
pub trait Device {
    /// Applies a changed profile without deactivating; `version_id` 0 is
    /// whatever is current.
    fn reapply(&self, connection: Settings, version_id: u64, flags: u32) -> zbus::Result<()>;
}

/// A Wi-Fi device, at its path in the tree.
#[proxy(
    interface = "org.freedesktop.NetworkManager.Device.Wireless",
    default_service = "org.freedesktop.NetworkManager"
)]
pub trait Wireless {
    /// Refused while a scan runs or soon after one, so poll `LastScan` rather
    /// than calling this in a loop.
    fn request_scan(&self, options: HashMap<&str, OwnedValue>) -> zbus::Result<()>;

    /// `CLOCK_BOOTTIME` milliseconds, or -1 for never.
    #[zbus(property)]
    fn last_scan(&self) -> zbus::Result<i64>;
}

/// One connection profile, at its path under `Settings`.
#[proxy(
    interface = "org.freedesktop.NetworkManager.Settings.Connection",
    default_service = "org.freedesktop.NetworkManager"
)]
pub trait Profile {
    /// The settings without their secrets.
    fn get_settings(&self) -> zbus::Result<Settings>;

    fn delete(&self) -> zbus::Result<()>;

    fn update2(
        &self,
        settings: Settings,
        flags: u32,
        args: HashMap<&str, OwnedValue>,
    ) -> zbus::Result<HashMap<String, OwnedValue>>;
}
