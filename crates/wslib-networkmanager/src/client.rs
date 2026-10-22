use std::collections::HashMap;
use std::time::Duration;

use zbus::fdo;
use zbus::names::OwnedUniqueName;
use zbus::proxy::{Builder, CacheProperties, Defaults};
use zbus::zvariant::{ObjectPath, OwnedObjectPath};

use crate::proxy::{
    DeviceProxy, NetworkManagerProxy, NmObjectsProxy, NmSettingsProxy, ProfileProxy, WirelessProxy,
};
use crate::{AccessPoint, Device, Objects, Profile, Settings};

/// `CheckpointCreate`'s flags.
pub mod checkpoint {
    /// Destroys every other checkpoint first, so an orphan cannot block this one.
    pub const DESTROY_ALL: u32 = 0x1;
    /// Rolling back deletes the profiles added since.
    pub const DELETE_NEW_CONNECTIONS: u32 = 0x2;
    pub const DISCONNECT_NEW_DEVICES: u32 = 0x4;
    pub const ALLOW_OVERLAPPING: u32 = 0x8;
}

/// `Update2`'s flag to write the profile to disk, so it survives a reboot.
const TO_DISK: u32 = 0x1;
pub(crate) const NM: &str = "org.freedesktop.NetworkManager";
const SCAN_POLL: Duration = Duration::from_millis(250);
const SCAN_POLLS: u32 = 30;

/// `NMRollbackResult`: how one device came back from a checkpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RollbackResult {
    Ok,
    NoDevice,
    DeviceUnmanaged,
    Failed,
}

impl From<u32> for RollbackResult {
    fn from(result: u32) -> Self {
        match result {
            0 => Self::Ok,
            1 => Self::NoDevice,
            2 => Self::DeviceUnmanaged,
            _ => Self::Failed,
        }
    }
}

/// NetworkManager's `WirelessEnabled` switch, which it persists itself, and
/// the kill switch that leaves it inert.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WifiRadio {
    pub enabled: bool,
    /// `None` when NetworkManager would not say.
    pub hardware_enabled: Option<bool>,
}

/// A profile added and the active connection it started.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Joined {
    pub profile: OwnedObjectPath,
    pub active: OwnedObjectPath,
}

/// NetworkManager on a bus connection.
///
/// Properties are read fresh on every call.
#[derive(Debug, Clone)]
pub struct Client {
    bus: zbus::Connection,
}

impl Client {
    pub fn new(bus: zbus::Connection) -> Self {
        Self { bus }
    }

    async fn proxy<P: From<zbus::Proxy<'static>> + Defaults>(&self) -> zbus::Result<P> {
        Builder::new(&self.bus)
            .cache_properties(CacheProperties::No)
            .build()
            .await
    }

    async fn proxy_at<P: From<zbus::Proxy<'static>> + Defaults>(
        &self,
        path: &ObjectPath<'_>,
    ) -> zbus::Result<P> {
        Builder::new(&self.bus)
            .path(path.to_owned())?
            .cache_properties(CacheProperties::No)
            .build()
            .await
    }

    /// The unique name of the NetworkManager running now, `None` when none
    /// is. A checkpoint lives no longer than the instance that made it.
    pub async fn owner(&self) -> zbus::Result<Option<OwnedUniqueName>> {
        let bus: fdo::DBusProxy<'_> = self.proxy().await?;
        match bus.get_name_owner(NM.try_into()?).await {
            Ok(owner) => Ok(Some(owner)),
            Err(fdo::Error::NameHasNoOwner(_)) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// The root object's proxy, for what the client does not wrap.
    pub async fn manager(&self) -> zbus::Result<NetworkManagerProxy<'static>> {
        self.proxy().await
    }

    /// The object tree. Nobody owning NetworkManager's name is a host on some
    /// other network stack.
    pub async fn objects(&self) -> zbus::Result<Objects> {
        self.proxy::<NmObjectsProxy<'_>>()
            .await?
            .get_managed_objects()
            .await
    }

    /// Every device, by interface name, read in one round trip.
    pub async fn devices(&self) -> zbus::Result<Vec<Device>> {
        Ok(Device::from_objects(&self.objects().await?))
    }

    /// The networks `device` sees, after a scan if NetworkManager takes one:
    /// it refuses one while another runs or just after, and what it already
    /// holds is still an answer. Waits up to 7.5 s for the scan to finish.
    pub async fn scan(&self, device: &ObjectPath<'_>) -> zbus::Result<Vec<AccessPoint>> {
        let wifi: WirelessProxy<'_> = self.proxy_at(device).await?;
        let before = wifi.last_scan().await.unwrap_or(-1);
        if wifi.request_scan(HashMap::new()).await.is_ok() {
            for _ in 0..SCAN_POLLS {
                tokio::time::sleep(SCAN_POLL).await;
                if wifi.last_scan().await.unwrap_or(-1) > before {
                    break;
                }
            }
        }
        Ok(self
            .devices()
            .await?
            .into_iter()
            .find(|d| d.path.as_ref() == *device)
            .map(|d| d.networks().into_iter().cloned().collect())
            .unwrap_or_default())
    }

    /// Adds `profile` and activates it on `device`; for a Wi-Fi join, from
    /// [`Device::wifi_profile`]. A wrong passphrase is not this call's error:
    /// it shows later as the device's state and reason.
    pub async fn add_and_activate(
        &self,
        profile: Settings,
        device: &ObjectPath<'_>,
    ) -> zbus::Result<Joined> {
        let (profile, active) = self
            .manager()
            .await?
            .add_and_activate_connection(
                profile,
                device,
                &ObjectPath::from_static_str_unchecked("/"),
            )
            .await?;
        Ok(Joined { profile, active })
    }

    /// Applies `settings` to `device` in place, or activates `profile` on it
    /// for the changes NetworkManager cannot make in place.
    pub async fn apply(
        &self,
        device: &ObjectPath<'_>,
        profile: &ObjectPath<'_>,
        settings: Settings,
    ) -> zbus::Result<()> {
        let reapplied = self
            .proxy_at::<DeviceProxy<'_>>(device)
            .await?
            .reapply(settings, 0, 0)
            .await;
        if reapplied.is_err() {
            self.activate(profile, device).await?;
        }
        Ok(())
    }

    /// Starts a saved `profile` on `device`, answering the active connection;
    /// as with [`add_and_activate`](Self::add_and_activate), a failure shows later.
    pub async fn activate(
        &self,
        profile: &ObjectPath<'_>,
        device: &ObjectPath<'_>,
    ) -> zbus::Result<OwnedObjectPath> {
        self.manager()
            .await?
            .activate_connection(profile, device, &ObjectPath::from_static_str_unchecked("/"))
            .await
    }

    /// Drops `device`'s active connection and keeps its profile, which
    /// NetworkManager then does not autoconnect on `device` until it is activated.
    pub async fn disconnect(&self, device: &ObjectPath<'_>) -> zbus::Result<()> {
        self.proxy_at::<DeviceProxy<'_>>(device)
            .await?
            .disconnect()
            .await
    }

    /// Every profile NetworkManager holds, saved or generated.
    pub async fn profiles(&self) -> zbus::Result<Vec<OwnedObjectPath>> {
        self.proxy::<NmSettingsProxy<'_>>()
            .await?
            .list_connections()
            .await
    }

    /// Every profile NetworkManager holds, read one round trip each.
    pub async fn saved(&self) -> zbus::Result<Vec<Profile>> {
        let mut saved = Vec::new();
        for path in self.profiles().await? {
            let settings = self.settings(&path).await?;
            saved.extend(Profile::read(path, &settings));
        }
        Ok(saved)
    }

    /// A profile's settings, without its secrets.
    pub async fn settings(&self, profile: &ObjectPath<'_>) -> zbus::Result<Settings> {
        self.proxy_at::<ProfileProxy<'_>>(profile)
            .await?
            .get_settings()
            .await
    }

    /// Replaces a profile's settings and writes it to disk; a device using it
    /// keeps the old ones until [`apply`](Self::apply).
    pub async fn update_profile(
        &self,
        profile: &ObjectPath<'_>,
        settings: Settings,
    ) -> zbus::Result<()> {
        self.proxy_at::<ProfileProxy<'_>>(profile)
            .await?
            .update2(settings, TO_DISK, HashMap::new())
            .await
            .map(drop)
    }

    /// Removes a profile, from disk and from any device using it.
    pub async fn delete_profile(&self, profile: &ObjectPath<'_>) -> zbus::Result<()> {
        self.proxy_at::<ProfileProxy<'_>>(profile)
            .await?
            .delete()
            .await
    }

    /// A restore point over `devices` that NetworkManager rolls back by
    /// itself after `rollback_timeout_s` seconds (0 for never) unless it is
    /// destroyed first. Its timer outlives this process; neither a reboot nor
    /// a NetworkManager restart rolls it back.
    pub async fn create_checkpoint(
        &self,
        devices: &[&ObjectPath<'_>],
        rollback_timeout_s: u32,
        flags: u32,
    ) -> zbus::Result<OwnedObjectPath> {
        self.manager()
            .await?
            .checkpoint_create(devices, rollback_timeout_s, flags)
            .await
    }

    /// Keeps what changed since the checkpoint.
    pub async fn destroy_checkpoint(&self, checkpoint: &ObjectPath<'_>) -> zbus::Result<()> {
        self.manager().await?.checkpoint_destroy(checkpoint).await
    }

    /// Undoes what changed since the checkpoint, now, answering how each
    /// device came back.
    pub async fn roll_back(
        &self,
        checkpoint: &ObjectPath<'_>,
    ) -> zbus::Result<HashMap<String, RollbackResult>> {
        Ok(self
            .manager()
            .await?
            .checkpoint_rollback(checkpoint)
            .await?
            .into_iter()
            .map(|(device, result)| (device, result.into()))
            .collect())
    }

    /// The checkpoints NetworkManager still holds, which is how a restarted
    /// process finds its own.
    pub async fn checkpoints(&self) -> zbus::Result<Vec<OwnedObjectPath>> {
        self.manager().await?.checkpoints().await
    }

    pub async fn wifi_radio(&self) -> zbus::Result<WifiRadio> {
        let manager = self.manager().await?;
        Ok(WifiRadio {
            enabled: manager.wireless_enabled().await?,
            hardware_enabled: manager.wireless_hardware_enabled().await.ok(),
        })
    }

    /// Switches `WirelessEnabled`; accepted, and inert, under the kill switch.
    pub async fn set_wifi_enabled(&self, enabled: bool) -> zbus::Result<()> {
        self.manager().await?.set_wireless_enabled(enabled).await
    }
}
