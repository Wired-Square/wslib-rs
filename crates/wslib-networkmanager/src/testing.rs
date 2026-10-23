//! An in-process fake NetworkManager, served over a socket pair.
//!
//! ```no_run
//! # async fn run() -> zbus::Result<()> {
//! use wslib_networkmanager::testing::{FakeAccessPoint, FakeDevice, FakeNetworkManager};
//! use wslib_networkmanager::{Client, Security};
//!
//! let fake = FakeNetworkManager::new().with(
//!     FakeDevice::wifi("wlan0")
//!         .access_point(FakeAccessPoint::new("Ops", 70, Security::WpaPsk).passphrase("correct horse")),
//! );
//! let (bus, _served) = fake.connect().await?;
//! let nm = Client::new(bus);
//! let wlan0 = nm.devices().await?.remove(0);
//! nm.add_and_activate(wlan0.wifi_profile(b"Ops", Some("correct horse")).unwrap(), &wlan0.path)
//!     .await?;
//! # Ok(())
//! # }
//! ```

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex, MutexGuard};

use zbus::connection::Builder;
use zbus::object_server::ObjectServer;
use zbus::zvariant::{ObjectPath, OwnedObjectPath, OwnedValue, Value};
use zbus::{Connection, Guid, fdo};

use crate::client::NM;
use crate::interface::{
    ACCESS_POINT, ACTIVE_CONNECTION, DEVICE, IP4_CONFIG, IP6_CONFIG, WIRED, WIRELESS,
};
use crate::props::{group, owned, text};
use crate::{
    Address, DeviceState, Group, Objects, Security, Settings, WifiRadio, checkpoint, reason,
};

const ETHERNET: u32 = 1;
const WIFI: u32 = 2;
const ROOT: &str = "/org/freedesktop/NetworkManager";

/// An access point a [`FakeDevice`] sees.
#[derive(Debug, Clone)]
pub struct FakeAccessPoint {
    ssid: Vec<u8>,
    strength: u8,
    security: Security,
    passphrase: Option<String>,
}

impl FakeAccessPoint {
    pub fn new(ssid: impl Into<Vec<u8>>, strength: u8, security: Security) -> Self {
        Self {
            ssid: ssid.into(),
            strength,
            security,
            passphrase: None,
        }
    }

    /// The only passphrase a join is accepted with; without one, any is.
    pub fn passphrase(mut self, passphrase: &str) -> Self {
        self.passphrase = Some(passphrase.into());
        self
    }

    fn flags(&self) -> (u32, u32, u32) {
        let rsn = match self.security {
            Security::Open => return (0, 0, 0),
            Security::Wep => 0,
            Security::Owe => Security::KEY_MGMT_OWE,
            Security::WpaPsk => Security::KEY_MGMT_PSK,
            Security::Sae => Security::KEY_MGMT_SAE,
            Security::Eap => Security::KEY_MGMT_802_1X,
        };
        (Security::PRIVACY, 0, rsn)
    }
}

/// A wired or Wi-Fi device for [`FakeNetworkManager::with`].
#[derive(Debug, Clone)]
pub struct FakeDevice {
    dev: Dev,
    active: Option<Settings>,
}

#[derive(Debug, Clone)]
struct Dev {
    interface: String,
    device_type: u32,
    state: Option<u32>,
    reason: u32,
    managed: bool,
    hw_address: Option<String>,
    carrier: Option<bool>,
    addresses: Vec<Address>,
    gateways: Vec<IpAddr>,
    dns: Vec<IpAddr>,
    profile: Option<usize>,
    access_points: Vec<FakeAccessPoint>,
    associated: Option<usize>,
    last_scan: i64,
}

impl FakeDevice {
    /// A device of any `NMDeviceType`: loopback (32), TUN (16), Wi-Fi P2P (30), …
    pub fn other(interface: &str, device_type: u32) -> Self {
        Self {
            dev: Dev {
                interface: interface.into(),
                device_type,
                state: None,
                reason: 0,
                managed: true,
                hw_address: None,
                carrier: (device_type == ETHERNET).then_some(true),
                addresses: Vec::new(),
                gateways: Vec::new(),
                dns: Vec::new(),
                profile: None,
                access_points: Vec::new(),
                associated: None,
                last_scan: -1,
            },
            active: None,
        }
    }

    pub fn ethernet(interface: &str) -> Self {
        Self::other(interface, ETHERNET)
    }

    pub fn wifi(interface: &str) -> Self {
        Self::other(interface, WIFI)
    }

    /// The state and its `NMDeviceStateReason`; `Activated` with an
    /// [`active`](Self::active) profile and `Disconnected` without, otherwise.
    pub fn state(mut self, state: DeviceState, reason: u32) -> Self {
        self.dev.state = Some(code(state));
        self.dev.reason = reason;
        self
    }

    pub fn unmanaged(mut self) -> Self {
        self.dev.managed = false;
        self.state(DeviceState::Unmanaged, 0)
    }

    /// No carrier, `Unavailable`, with the reason NetworkManager leaves after boot.
    pub fn unplugged(mut self) -> Self {
        self.dev.carrier = Some(false);
        self.state(DeviceState::Unavailable, 2)
    }

    pub fn hw_address(mut self, address: &str) -> Self {
        self.dev.hw_address = Some(address.into());
        self
    }

    /// An address it has now, in its family's IP configuration.
    pub fn address(mut self, address: impl Into<IpAddr>, prefix: u8) -> Self {
        self.dev.addresses.push(Address {
            address: address.into(),
            prefix,
        });
        self
    }

    pub fn gateway(mut self, gateway: IpAddr) -> Self {
        self.dev.gateways.push(gateway);
        self
    }

    pub fn dns(mut self, resolver: IpAddr) -> Self {
        self.dev.dns.push(resolver);
        self
    }

    /// The profile its active connection runs.
    pub fn active(mut self, profile: Settings) -> Self {
        self.active = Some(profile);
        self
    }

    pub fn access_point(mut self, ap: FakeAccessPoint) -> Self {
        self.dev.access_points.push(ap);
        self
    }
}

fn code(state: DeviceState) -> u32 {
    match state {
        DeviceState::Unknown => 0,
        DeviceState::Unmanaged => 10,
        DeviceState::Unavailable => 20,
        DeviceState::Disconnected => 30,
        DeviceState::Prepare => 40,
        DeviceState::Config => 50,
        DeviceState::NeedAuth => 60,
        DeviceState::IpConfig => 70,
        DeviceState::IpCheck => 80,
        DeviceState::Secondaries => 90,
        DeviceState::Activated => 100,
        DeviceState::Deactivating => 110,
        DeviceState::Failed => 120,
    }
}

#[derive(Debug, Clone)]
struct Snapshot {
    devices: Vec<Dev>,
    active: Vec<Option<Settings>>,
    uuids: Option<Vec<String>>,
}

#[derive(Debug)]
struct State {
    devices: Vec<Dev>,
    profiles: Vec<Option<Settings>>,
    checkpoints: Vec<(OwnedObjectPath, Snapshot)>,
    made_checkpoints: usize,
    instance: u32,
    radio: WifiRadio,
    unserved: Vec<usize>,
    vanishing: Vec<OwnedObjectPath>,
    refusing: Vec<String>,
    heard: Vec<String>,
}

impl Dev {
    fn wifi(&self) -> bool {
        self.device_type == WIFI
    }
}

impl State {
    fn hear(&mut self, method: &str, what: String) -> fdo::Result<()> {
        self.heard
            .push(format!("{method} {what}").trim_end().to_string());
        self.refused(method)
    }

    fn refused(&self, method: &str) -> fdo::Result<()> {
        if self.refusing.iter().any(|m| m == method) {
            return Err(fdo::Error::Failed(format!("{method} refused")));
        }
        Ok(())
    }

    fn device(&self, path: &ObjectPath<'_>) -> fdo::Result<usize> {
        (0..self.devices.len())
            .find(|&i| device_path(i).as_ref() == *path)
            .ok_or_else(|| fdo::Error::UnknownObject(format!("no device at {path}")))
    }

    fn profile(&self, path: &ObjectPath<'_>) -> fdo::Result<usize> {
        (0..self.profiles.len())
            .find(|&i| self.profiles[i].is_some() && profile_path(i).as_ref() == *path)
            .ok_or_else(|| fdo::Error::UnknownObject(format!("no profile at {path}")))
    }

    fn activate(&mut self, device: usize, profile: usize) {
        let settings = self.profiles[profile].clone().unwrap_or_default();
        let dev = &mut self.devices[device];
        dev.profile = Some(profile);
        (dev.state, dev.reason, dev.associated) = (Some(code(DeviceState::Activated)), 0, None);
        if !dev.wifi() {
            return;
        }
        let ssid = ssid_of(&settings);
        let psk = settings
            .get("802-11-wireless-security")
            .and_then(|s| text(s, "psk"));
        let found = dev.access_points.iter().position(|ap| ap.ssid == ssid);
        (dev.state, dev.reason, dev.associated) = match found {
            None => (
                Some(code(DeviceState::Failed)),
                reason::SSID_NOT_FOUND,
                None,
            ),
            Some(ap) => match &dev.access_points[ap].passphrase {
                Some(wanted) if psk.as_ref() != Some(wanted) => {
                    (Some(code(DeviceState::Failed)), reason::NO_SECRETS, None)
                }
                _ => (Some(code(DeviceState::Activated)), 0, Some(ap)),
            },
        };
        if dev.associated.is_none() {
            dev.profile = None;
        }
    }

    /// Adds a profile with the `connection.uuid` and `connection.id` NetworkManager fills in.
    fn hold(&mut self, mut settings: Settings) -> usize {
        let at = self.profiles.len();
        let ssid = ssid_of(&settings);
        let id = if ssid.is_empty() {
            format!("Connection {}", at + 1)
        } else {
            String::from_utf8_lossy(&ssid).into_owned()
        };
        let filled = group([
            (
                "uuid",
                Value::from(format!("00000000-0000-4000-8000-{at:012x}")),
            ),
            ("id", Value::from(id)),
        ]);
        complete(&mut settings, &filled);
        self.profiles.push(Some(settings));
        self.unserved.push(at);
        at
    }

    fn delete(&mut self, profile: usize) {
        self.profiles[profile] = None;
        for dev in self
            .devices
            .iter_mut()
            .filter(|d| d.profile == Some(profile))
        {
            (dev.profile, dev.state, dev.associated) = (None, None, None);
        }
    }

    fn held_uuids(&self) -> impl Iterator<Item = (usize, String)> + '_ {
        self.profiles
            .iter()
            .enumerate()
            .filter_map(|(i, p)| Some((i, uuid_of(p.as_ref()?)?)))
    }

    /// As `nm_checkpoint_rollback`: each device's profile then is updated, or
    /// added back at a new path, and run again; no other profile comes back.
    fn roll_back(&mut self, at: usize) -> HashMap<String, u32> {
        let (_, snapshot) = self.checkpoints.remove(at);
        for (i, (mut dev, active)) in snapshot
            .devices
            .into_iter()
            .zip(snapshot.active)
            .enumerate()
        {
            dev.last_scan = self.devices[i].last_scan;
            dev.profile = active.map(|settings| {
                let uuid = uuid_of(&settings);
                let held = self
                    .held_uuids()
                    .find(|(_, held)| Some(held) == uuid.as_ref())
                    .map(|(at, _)| at);
                match held {
                    Some(at) => {
                        self.profiles[at] = Some(settings);
                        at
                    }
                    None => self.hold(settings),
                }
            });
            self.devices[i] = dev;
        }
        if let Some(kept) = snapshot.uuids {
            let new: Vec<_> = self
                .held_uuids()
                .filter(|(_, uuid)| !kept.contains(uuid))
                .map(|(i, _)| i)
                .collect();
            for profile in new {
                self.delete(profile);
            }
        }
        (0..self.devices.len())
            .map(|i| (device_path(i).to_string(), 0))
            .collect()
    }

    fn tree(&self) -> Objects {
        let mut objects = Objects::new();
        for (i, dev) in self.devices.iter().enumerate() {
            let none = path("/");
            let has = |v6: bool| {
                dev.addresses.iter().any(|a| a.address.is_ipv6() == v6)
                    || dev.gateways.iter().any(|g| g.is_ipv6() == v6)
            };
            let linked = |yes: bool, kind: &str| {
                if yes {
                    path(&format!("{ROOT}/{kind}/{i}"))
                } else {
                    none.clone()
                }
            };
            let state = dev.state.unwrap_or(code(if dev.profile.is_some() {
                DeviceState::Activated
            } else {
                DeviceState::Disconnected
            }));
            let mut interfaces = HashMap::from([(
                DEVICE.to_string(),
                group([
                    ("Interface", Value::from(dev.interface.clone())),
                    ("DeviceType", Value::from(dev.device_type)),
                    ("State", Value::from(state)),
                    ("StateReason", Value::from((state, dev.reason))),
                    ("Managed", Value::from(dev.managed)),
                    (
                        "HwAddress",
                        Value::from(dev.hw_address.clone().unwrap_or_default()),
                    ),
                    ("Ip4Config", Value::from(linked(has(false), "IP4Config"))),
                    ("Ip6Config", Value::from(linked(has(true), "IP6Config"))),
                    (
                        "ActiveConnection",
                        Value::from(linked(dev.profile.is_some(), "ActiveConnection")),
                    ),
                ]),
            )]);
            if let Some(carrier) = dev.carrier {
                interfaces.insert(
                    WIRED.to_string(),
                    group([("Carrier", Value::from(carrier))]),
                );
            }
            if dev.wifi() {
                let ap_path = |j: usize| path(&format!("{ROOT}/AccessPoint/{}", i * 1000 + j));
                interfaces.insert(
                    WIRELESS.to_string(),
                    group([
                        (
                            "AccessPoints",
                            Value::from(
                                (0..dev.access_points.len())
                                    .map(ap_path)
                                    .collect::<Vec<_>>(),
                            ),
                        ),
                        (
                            "ActiveAccessPoint",
                            Value::from(dev.associated.map_or(none.clone(), ap_path)),
                        ),
                        ("LastScan", Value::from(dev.last_scan)),
                    ]),
                );
                for (j, ap) in dev.access_points.iter().enumerate() {
                    let (flags, wpa, rsn) = ap.flags();
                    objects.insert(
                        ap_path(j),
                        HashMap::from([(
                            ACCESS_POINT.to_string(),
                            group([
                                ("Ssid", Value::from(ap.ssid.clone())),
                                ("Strength", Value::from(ap.strength)),
                                ("Flags", Value::from(flags)),
                                ("WpaFlags", Value::from(wpa)),
                                ("RsnFlags", Value::from(rsn)),
                            ]),
                        )]),
                    );
                }
            }
            objects.insert(device_path(i), interfaces);
            let family = |v6: bool| -> Group {
                let address_data: Vec<HashMap<String, Value>> = dev
                    .addresses
                    .iter()
                    .filter(|a| a.address.is_ipv6() == v6)
                    .map(|a| {
                        HashMap::from([
                            ("address".to_string(), Value::from(a.address.to_string())),
                            ("prefix".to_string(), Value::from(u32::from(a.prefix))),
                        ])
                    })
                    .collect();
                let gateway = dev.gateways.iter().find(|g| g.is_ipv6() == v6);
                let mut config = group([
                    ("AddressData", Value::from(address_data)),
                    (
                        "Gateway",
                        Value::from(gateway.map(ToString::to_string).unwrap_or_default()),
                    ),
                ]);
                let dns = dev.dns.iter().filter(|d| d.is_ipv6() == v6);
                if v6 {
                    let bytes: Vec<Vec<u8>> = dns
                        .filter_map(|d| match d {
                            IpAddr::V6(d) => Some(d.octets().to_vec()),
                            IpAddr::V4(_) => None,
                        })
                        .collect();
                    config.insert("Nameservers".into(), owned(Value::from(bytes)));
                } else {
                    let entries: Vec<HashMap<String, Value>> = dns
                        .map(|d| {
                            HashMap::from([("address".to_string(), Value::from(d.to_string()))])
                        })
                        .collect();
                    config.insert("NameserverData".into(), owned(Value::from(entries)));
                }
                config
            };
            for (v6, kind, interface) in [
                (false, "IP4Config", IP4_CONFIG),
                (true, "IP6Config", IP6_CONFIG),
            ] {
                if has(v6) {
                    objects.insert(
                        linked(true, kind),
                        HashMap::from([(interface.to_string(), family(v6))]),
                    );
                }
            }
            if let Some(profile) = dev.profile {
                objects.insert(
                    linked(true, "ActiveConnection"),
                    HashMap::from([(
                        ACTIVE_CONNECTION.to_string(),
                        group([("Connection", Value::from(profile_path(profile)))]),
                    )]),
                );
            }
        }
        objects
    }
}

fn path(p: &str) -> OwnedObjectPath {
    OwnedObjectPath::try_from(p).expect("an object path")
}

fn device_path(i: usize) -> OwnedObjectPath {
    path(&format!("{ROOT}/Devices/{i}"))
}

fn profile_path(i: usize) -> OwnedObjectPath {
    path(&format!("{ROOT}/Settings/{i}"))
}

fn ssid_of(settings: &Settings) -> Vec<u8> {
    crate::profile::ssid(settings).unwrap_or_default()
}

fn uuid_of(settings: &Settings) -> Option<String> {
    text(settings.get("connection")?, "uuid")
}

/// Fills in each of `fallback`'s `connection` keys that `settings` lacks.
fn complete(settings: &mut Settings, fallback: &Group) {
    let connection = settings.entry("connection".into()).or_default();
    for (key, value) in fallback {
        connection
            .entry(key.clone())
            .or_insert_with(|| value.clone());
    }
}

/// A fake NetworkManager; clones share its state.
///
/// A join succeeds when the device sees the SSID and the passphrase is the
/// access point's, and otherwise leaves the device `Failed` with
/// `SSID_NOT_FOUND` or `NO_SECRETS`, as NetworkManager does after accepting
/// the call. A checkpoint rolls back on [`expire_checkpoints`](Self::expire_checkpoints),
/// not on a timer.
#[derive(Debug, Clone)]
pub struct FakeNetworkManager {
    state: Arc<Mutex<State>>,
}

impl Default for FakeNetworkManager {
    fn default() -> Self {
        Self::new()
    }
}

impl FakeNetworkManager {
    /// No devices, the Wi-Fi radio on.
    pub fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(State {
                devices: Vec::new(),
                profiles: Vec::new(),
                checkpoints: Vec::new(),
                made_checkpoints: 0,
                radio: WifiRadio {
                    enabled: true,
                    hardware_enabled: Some(true),
                },
                instance: 1,
                unserved: Vec::new(),
                vanishing: Vec::new(),
                refusing: Vec::new(),
                heard: Vec::new(),
            })),
        }
    }

    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap()
    }

    pub fn with(self, device: FakeDevice) -> Self {
        let FakeDevice { mut dev, active } = device;
        let mut state = self.state();
        dev.profile = active.map(|profile| state.hold(profile));
        state.devices.push(dev);
        drop(state);
        self
    }

    /// A saved profile no device is running.
    pub fn saved(self, profile: Settings) -> Self {
        self.state().hold(profile);
        self
    }

    pub fn set_radio(&self, radio: WifiRadio) {
        self.state().radio = radio;
    }

    pub fn radio(&self) -> WifiRadio {
        self.state().radio
    }

    /// Makes every later call to `method`, by its D-Bus member name, fail.
    pub fn refuse(&self, method: &str) {
        self.state().refusing.push(method.into());
    }

    /// Deletes `profile` just after the next `ListConnections` lists it, as a
    /// deletion racing a listing does.
    pub fn vanish_after_listing(&self, profile: &ObjectPath<'_>) {
        self.state().vanishing.push(profile.to_owned().into());
    }

    /// Each call that changes something, as its member name and arguments.
    pub fn heard(&self) -> Vec<String> {
        self.state().heard.clone()
    }

    /// The profiles it holds, secrets included.
    pub fn profiles(&self) -> Vec<Settings> {
        self.state().profiles.iter().flatten().cloned().collect()
    }

    /// Restarts NetworkManager: a new [`owner`](crate::Client::owner), and
    /// every checkpoint gone without a rollback.
    pub fn restart(&self) {
        let mut state = self.state();
        state.instance += 1;
        state.checkpoints.clear();
    }

    /// Rolls every checkpoint back, as NetworkManager does when one's timer runs out.
    pub fn expire_checkpoints(&self) {
        let mut state = self.state();
        while !state.checkpoints.is_empty() {
            state.roll_back(0);
        }
    }

    /// `(client, served)`: a peer-to-peer connection to the fake, and the
    /// fake's own end, which must be kept alive as long as the client is used.
    pub async fn connect(&self) -> zbus::Result<(Connection, Connection)> {
        let (ours, theirs) = tokio::net::UnixStream::pair()?;
        let mut served = Builder::unix_stream(theirs)
            .server(Guid::generate())?
            .p2p()
            .serve_at(ROOT, Root(self.clone()))?
            .serve_at("/org/freedesktop", Tree(self.clone()))?
            .serve_at(format!("{ROOT}/Settings"), Profiles(self.clone()))?
            .serve_at("/org/freedesktop/DBus", Bus(self.clone()))?;
        let (devices, profiles) = {
            let state = self.state();
            (state.devices.clone(), state.profiles.len())
        };
        for (i, dev) in devices.iter().enumerate() {
            served = served.serve_at(device_path(i), DeviceObject(self.clone(), i))?;
            if dev.wifi() {
                served = served.serve_at(device_path(i), WirelessObject(self.clone(), i))?;
            }
        }
        for i in 0..profiles {
            served = served.serve_at(profile_path(i), ProfileObject(self.clone(), i))?;
        }
        self.state().unserved.clear();
        let client = Builder::unix_stream(ours).p2p().build();
        let (served, client) = tokio::try_join!(served.build(), client)?;
        Ok((client, served))
    }

    /// Serves the profiles added since; a client learns a new path only from
    /// a call that runs this first.
    async fn serve_new_profiles(&self, server: &ObjectServer) -> zbus::Result<()> {
        let new = std::mem::take(&mut self.state().unserved);
        for i in new {
            server
                .at(profile_path(i), ProfileObject(self.clone(), i))
                .await?;
        }
        Ok(())
    }
}

struct Root(FakeNetworkManager);

#[zbus::interface(name = "org.freedesktop.NetworkManager")]
impl Root {
    #[zbus(name = "ActivateConnection")]
    fn activate_connection(
        &self,
        connection: ObjectPath<'_>,
        device: ObjectPath<'_>,
        _specific_object: ObjectPath<'_>,
    ) -> fdo::Result<OwnedObjectPath> {
        let mut state = self.0.state();
        state.hear("ActivateConnection", format!("{connection} {device}"))?;
        let (profile, device) = (state.profile(&connection)?, state.device(&device)?);
        state.activate(device, profile);
        Ok(path(&format!("{ROOT}/ActiveConnection/{device}")))
    }

    #[zbus(name = "AddAndActivateConnection")]
    async fn add_and_activate_connection(
        &self,
        connection: Settings,
        device: ObjectPath<'_>,
        _specific_object: ObjectPath<'_>,
        #[zbus(object_server)] server: &ObjectServer,
    ) -> fdo::Result<(OwnedObjectPath, OwnedObjectPath)> {
        let (profile, device) = {
            let mut state = self.0.state();
            state.hear(
                "AddAndActivateConnection",
                format!(
                    "{device} {}",
                    String::from_utf8_lossy(&ssid_of(&connection))
                ),
            )?;
            let device = state.device(&device)?;
            let profile = state.hold(connection);
            state.activate(device, profile);
            (profile, device)
        };
        self.0.serve_new_profiles(server).await?;
        Ok((
            profile_path(profile),
            path(&format!("{ROOT}/ActiveConnection/{device}")),
        ))
    }

    #[zbus(name = "CheckpointCreate")]
    fn checkpoint_create(
        &self,
        devices: Vec<ObjectPath<'_>>,
        rollback_timeout: u32,
        flags: u32,
    ) -> fdo::Result<OwnedObjectPath> {
        let mut state = self.0.state();
        state.hear(
            "CheckpointCreate",
            format!("{} {rollback_timeout} {flags:#x}", devices.len()),
        )?;
        if flags & checkpoint::DESTROY_ALL != 0 {
            state.checkpoints.clear();
        } else if !state.checkpoints.is_empty() && flags & checkpoint::ALLOW_OVERLAPPING == 0 {
            return Err(fdo::Error::Failed(
                "a checkpoint already covers these devices".into(),
            ));
        }
        state.made_checkpoints += 1;
        let made = path(&format!("{ROOT}/Checkpoint/{}", state.made_checkpoints));
        let snapshot = Snapshot {
            devices: state.devices.clone(),
            active: state
                .devices
                .iter()
                .map(|d| state.profiles[d.profile?].clone())
                .collect(),
            uuids: (flags & checkpoint::DELETE_NEW_CONNECTIONS != 0)
                .then(|| state.held_uuids().map(|(_, uuid)| uuid).collect()),
        };
        state.checkpoints.push((made.clone(), snapshot));
        Ok(made)
    }

    #[zbus(name = "CheckpointDestroy")]
    fn checkpoint_destroy(&self, checkpoint: ObjectPath<'_>) -> fdo::Result<()> {
        let mut state = self.0.state();
        state.hear("CheckpointDestroy", checkpoint.to_string())?;
        let at = checkpoint_at(&state, &checkpoint)?;
        state.checkpoints.remove(at);
        Ok(())
    }

    #[zbus(name = "CheckpointRollback")]
    async fn checkpoint_rollback(
        &self,
        checkpoint: ObjectPath<'_>,
        #[zbus(object_server)] server: &ObjectServer,
    ) -> fdo::Result<HashMap<String, u32>> {
        let results = {
            let mut state = self.0.state();
            state.hear("CheckpointRollback", checkpoint.to_string())?;
            let at = checkpoint_at(&state, &checkpoint)?;
            state.roll_back(at)
        };
        self.0.serve_new_profiles(server).await?;
        Ok(results)
    }

    #[zbus(property, name = "Checkpoints")]
    fn checkpoints(&self) -> Vec<OwnedObjectPath> {
        self.0
            .state()
            .checkpoints
            .iter()
            .map(|(p, _)| p.clone())
            .collect()
    }

    #[zbus(property, name = "WirelessEnabled")]
    fn wireless_enabled(&self) -> bool {
        self.0.state().radio.enabled
    }

    #[zbus(property, name = "WirelessEnabled")]
    fn set_wireless_enabled(&self, enabled: bool) -> zbus::Result<()> {
        let mut state = self.0.state();
        state.hear("WirelessEnabled", enabled.to_string())?;
        state.radio.enabled = enabled;
        Ok(())
    }

    #[zbus(property, name = "WirelessHardwareEnabled")]
    fn wireless_hardware_enabled(&self) -> fdo::Result<bool> {
        self.0
            .state()
            .radio
            .hardware_enabled
            .ok_or_else(|| fdo::Error::Failed("unreadable".into()))
    }
}

fn checkpoint_at(state: &State, checkpoint: &ObjectPath<'_>) -> fdo::Result<usize> {
    state
        .checkpoints
        .iter()
        .position(|(p, _)| p.as_ref() == *checkpoint)
        .ok_or_else(|| fdo::Error::InvalidArgs(format!("no checkpoint {checkpoint}")))
}

struct Bus(FakeNetworkManager);

#[zbus::interface(name = "org.freedesktop.DBus")]
impl Bus {
    #[zbus(name = "GetNameOwner")]
    fn get_name_owner(&self, name: String) -> fdo::Result<String> {
        if name != NM {
            return Err(fdo::Error::NameHasNoOwner(format!("nobody owns {name}")));
        }
        Ok(format!(":1.{}", self.0.state().instance))
    }
}

struct Tree(FakeNetworkManager);

#[zbus::interface(name = "org.freedesktop.DBus.ObjectManager")]
impl Tree {
    #[zbus(name = "GetManagedObjects")]
    async fn get_managed_objects(
        &self,
        #[zbus(object_server)] server: &ObjectServer,
    ) -> fdo::Result<Objects> {
        self.0.serve_new_profiles(server).await?;
        Ok(self.0.state().tree())
    }
}

struct Profiles(FakeNetworkManager);

#[zbus::interface(name = "org.freedesktop.NetworkManager.Settings")]
impl Profiles {
    #[zbus(name = "ListConnections")]
    async fn list_connections(
        &self,
        #[zbus(object_server)] server: &ObjectServer,
    ) -> fdo::Result<Vec<OwnedObjectPath>> {
        self.0.serve_new_profiles(server).await?;
        let mut state = self.0.state();
        let listed = (0..state.profiles.len())
            .filter(|&i| state.profiles[i].is_some())
            .map(profile_path)
            .collect();
        for profile in std::mem::take(&mut state.vanishing) {
            if let Ok(i) = state.profile(&profile) {
                state.delete(i);
            }
        }
        Ok(listed)
    }
}

struct DeviceObject(FakeNetworkManager, usize);

#[zbus::interface(name = "org.freedesktop.NetworkManager.Device")]
impl DeviceObject {
    #[zbus(name = "Reapply")]
    fn reapply(&self, connection: Settings, _version_id: u64, _flags: u32) -> fdo::Result<()> {
        let mut state = self.0.state();
        let method = connection
            .get("ipv4")
            .and_then(|ipv4| text(ipv4, "method"))
            .unwrap_or_default();
        let heard = format!("{} {method}", state.devices[self.1].interface);
        state.hear("Reapply", heard)
    }

    #[zbus(name = "Disconnect")]
    fn disconnect(&self) -> Result<(), DeviceError> {
        let mut state = self.0.state();
        let interface = state.devices[self.1].interface.clone();
        state
            .hear("Disconnect", interface)
            .map_err(|e| DeviceError::Failed(e.to_string()))?;
        let dev = &mut state.devices[self.1];
        if dev.profile.is_none() {
            return Err(DeviceError::NotActive("This device is not active".into()));
        }
        (dev.profile, dev.associated) = (None, None);
        (dev.state, dev.reason) = (
            Some(code(DeviceState::Disconnected)),
            reason::USER_REQUESTED,
        );
        Ok(())
    }
}

#[derive(Debug, zbus::DBusError)]
#[zbus(prefix = "org.freedesktop.NetworkManager.Device")]
enum DeviceError {
    Failed(String),
    NotActive(String),
}

struct WirelessObject(FakeNetworkManager, usize);

#[zbus::interface(name = "org.freedesktop.NetworkManager.Device.Wireless")]
impl WirelessObject {
    #[zbus(name = "RequestScan")]
    fn request_scan(&self, _options: HashMap<String, OwnedValue>) -> fdo::Result<()> {
        let mut state = self.0.state();
        state.hear("RequestScan", String::new())?;
        let dev = &mut state.devices[self.1];
        dev.last_scan = dev.last_scan.max(0) + 1_000;
        Ok(())
    }

    #[zbus(property, name = "LastScan")]
    fn last_scan(&self) -> i64 {
        self.0.state().devices[self.1].last_scan
    }
}

struct ProfileObject(FakeNetworkManager, usize);

impl ProfileObject {
    fn held(&self, state: &State) -> fdo::Result<()> {
        state.profile(&profile_path(self.1)).map(drop)
    }
}

#[zbus::interface(name = "org.freedesktop.NetworkManager.Settings.Connection")]
impl ProfileObject {
    #[zbus(name = "GetSettings")]
    fn get_settings(&self) -> fdo::Result<Settings> {
        let state = self.0.state();
        self.held(&state)?;
        state.refused("GetSettings")?;
        let mut settings = state.profiles[self.1].clone().unwrap_or_default();
        if let Some(secured) = settings.get_mut("802-11-wireless-security") {
            secured.remove("psk");
        }
        Ok(settings)
    }

    #[zbus(name = "Update2")]
    fn update2(
        &self,
        mut settings: Settings,
        flags: u32,
        _args: HashMap<String, OwnedValue>,
    ) -> fdo::Result<HashMap<String, OwnedValue>> {
        let mut state = self.0.state();
        self.held(&state)?;
        state.hear("Update2", format!("{} {flags:#x}", profile_path(self.1)))?;
        if let Some(old) = state.profiles[self.1]
            .as_ref()
            .and_then(|p| p.get("connection"))
        {
            complete(&mut settings, old);
        }
        state.profiles[self.1] = Some(settings);
        Ok(HashMap::new())
    }

    #[zbus(name = "Delete")]
    fn delete(&self) -> fdo::Result<()> {
        let mut state = self.0.state();
        self.held(&state)?;
        state.hear("Delete", profile_path(self.1).to_string())?;
        state.delete(self.1);
        Ok(())
    }
}
