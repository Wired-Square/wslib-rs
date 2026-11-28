//! An in-process fake BlueZ, served over a socket pair.
//!
//! It keeps what BlueZ 5.85 was measured to do: a `Pair()` fails with
//! `AuthenticationFailed` while no agent is registered, and bonds without
//! asking the agent while one is; a pairing started by an encrypted read asks
//! the agent through `RequestAuthorization`.
//!
//! ```no_run
//! # async fn run() -> Result<(), Box<dyn std::error::Error>> {
//! use std::time::Duration;
//!
//! use wslib_ble::testing::{FakeBluez, FakeDevice};
//! use wslib_ble::{Address, Pairing};
//!
//! let address: Address = "AA:BB:CC:DD:EE:FF".parse()?;
//! let fake = FakeBluez::new().with(FakeDevice::new("hci0", address));
//! let (bus, _served) = fake.connect().await?;
//! let pairing = Pairing::confirm_on(bus, "hci0", &address).await?;
//! pairing.pair(Duration::from_secs(1)).await?;
//! assert!(fake.paired("hci0", &address));
//! # Ok(())
//! # }
//! ```

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};

use tokio::sync::Notify;
use zbus::connection::Builder;
use zbus::object_server::ObjectServer;
use zbus::zvariant::{ObjectPath, OwnedObjectPath, OwnedValue, Value};
use zbus::{Connection, DBusError, Guid};

use crate::bluez::{
    ADAPTER, DEVICE, DEVICE_ADAPTER, DEVICE_ADDRESS, Objects, Properties, ROOT, error_name,
};
use crate::{Address, Refusal};

const DEVICE_PAIRED: &str = "Paired";
const AGENT: &str = "org.bluez.Agent1";
const REQUEST_AUTHORIZATION: &str = "RequestAuthorization";
const REJECTED: &str = "org.bluez.Error.Rejected";
const NO_SUCH_DEVICE: &str = "Does Not Exist";
const NO_SUCH_AGENT: &str = "No such agent";
const NO_PAIRING: &str = "No pairing in progress";
const ALREADY_PAIRED: &str = "Already Exists";
const AGENT_REGISTERED: &str = "Already Exists";
const NO_AGENT: &str = "Authentication Failed";
const CANCELLED: &str = "Authentication Canceled";

/// A device a [`FakeBluez`] adapter has discovered.
#[derive(Debug, Clone)]
pub struct FakeDevice {
    adapter: String,
    address: Address,
    paired: bool,
    vanishing: bool,
    refusing: Option<Refusal>,
    silent: bool,
    pairing: bool,
    cancelled: Arc<Notify>,
}

impl FakeDevice {
    /// The text a [`refusing`](Self::refusing) device's error carries.
    pub const REFUSAL_DETAIL: &str = "scripted";

    pub fn new(adapter: &str, address: Address) -> Self {
        Self {
            adapter: adapter.into(),
            address,
            paired: false,
            vanishing: false,
            refusing: None,
            silent: false,
            pairing: false,
            cancelled: Arc::default(),
        }
    }

    /// Already bonded, so a `Pair()` answers `AlreadyExists`.
    pub fn bonded(mut self) -> Self {
        self.paired = true;
        self
    }

    /// Answers a `Pair()` with this refusal, though an agent is registered.
    pub fn refusing(mut self, reason: Refusal) -> Self {
        self.refusing = Some(reason);
        self
    }

    /// Leaves a `Pair()` unanswered until a `CancelPairing`.
    pub fn silent(mut self) -> Self {
        self.silent = true;
        self
    }

    /// The object path BlueZ gives the device.
    pub fn path(&self) -> OwnedObjectPath {
        device_path(&self.adapter, &self.address)
    }
}

/// The object path BlueZ gives `address` on `adapter`; panics on an adapter
/// name no object path holds.
pub fn device_path(adapter: &str, address: &Address) -> OwnedObjectPath {
    let node = address.to_string().replace(':', "_");
    OwnedObjectPath::try_from(format!("{ROOT}/{adapter}/dev_{node}"))
        .expect("an adapter name is one path element")
}

fn adapter_path(adapter: &str) -> OwnedObjectPath {
    OwnedObjectPath::try_from(format!("{ROOT}/{adapter}"))
        .expect("an adapter name is one path element")
}

fn owned(value: Value<'_>) -> OwnedValue {
    OwnedValue::try_from(value).expect("a value without file descriptors converts")
}

/// What a registered agent said to a pairing BlueZ asked it about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Asked {
    Accepted,
    Rejected,
    /// No agent is registered, so nothing was asked and the pairing fails.
    NoAgent,
}

#[derive(Debug, DBusError)]
#[zbus(prefix = "org.bluez.Error")]
enum Fault {
    #[zbus(error)]
    ZBus(zbus::Error),
    AlreadyExists(String),
    DoesNotExist(String),
    AuthenticationFailed(String),
    AuthenticationRejected(String),
    AuthenticationCanceled(String),
    AuthenticationTimeout(String),
    ConnectionAttemptFailed(String),
}

impl Fault {
    fn scripted(reason: Refusal) -> Self {
        let detail = FakeDevice::REFUSAL_DETAIL.to_string();
        match reason {
            Refusal::AuthenticationFailed => Self::AuthenticationFailed(detail),
            Refusal::AuthenticationRejected => Self::AuthenticationRejected(detail),
            Refusal::AuthenticationCanceled => Self::AuthenticationCanceled(detail),
            Refusal::AuthenticationTimeout => Self::AuthenticationTimeout(detail),
            Refusal::ConnectionAttemptFailed => Self::ConnectionAttemptFailed(detail),
        }
    }
}

#[derive(Debug, Default)]
struct State {
    adapters: Vec<String>,
    devices: Vec<FakeDevice>,
    agent: Option<(OwnedObjectPath, String)>,
    asked: usize,
    heard: Vec<String>,
}

impl State {
    fn device(&mut self, path: &ObjectPath<'_>) -> Result<&mut FakeDevice, Fault> {
        self.devices
            .iter_mut()
            .find(|device| device.path().as_ref() == *path)
            .ok_or_else(|| Fault::DoesNotExist(NO_SUCH_DEVICE.into()))
    }

    fn tree(&self) -> Objects {
        let adapters = self.adapters.iter().map(|adapter| {
            let interfaces = HashMap::from([(ADAPTER.to_string(), Properties::new())]);
            (adapter_path(adapter), interfaces)
        });
        let devices = self.devices.iter().map(|device| {
            let properties = Properties::from([
                (
                    DEVICE_ADDRESS.to_string(),
                    owned(Value::from(device.address.to_string())),
                ),
                (
                    DEVICE_ADAPTER.to_string(),
                    owned(Value::from(adapter_path(&device.adapter).into_inner())),
                ),
                (DEVICE_PAIRED.to_string(), owned(Value::from(device.paired))),
            ]);
            let interfaces = HashMap::from([(DEVICE.to_string(), properties)]);
            (device.path(), interfaces)
        });
        adapters.chain(devices).collect()
    }
}

/// A scripted BlueZ: the adapters, the devices each has discovered, and the
/// agent registered with it.
#[derive(Debug, Clone, Default)]
pub struct FakeBluez {
    state: Arc<Mutex<State>>,
}

impl FakeBluez {
    pub fn new() -> Self {
        Self::default()
    }

    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap()
    }

    fn read<T>(
        &self,
        adapter: &str,
        address: &Address,
        of: impl Fn(&FakeDevice) -> T,
    ) -> Option<T> {
        let path = device_path(adapter, address);
        self.state().device(&path).ok().map(|device| of(device))
    }

    /// An adapter, which may have discovered nothing.
    pub fn adapter(self, adapter: &str) -> Self {
        let mut state = self.state();
        if !state.adapters.iter().any(|a| a == adapter) {
            state.adapters.push(adapter.into());
        }
        drop(state);
        self
    }

    /// A device, and its adapter if the fake has not that one yet.
    pub fn with(self, device: FakeDevice) -> Self {
        let fake = self.adapter(&device.adapter);
        fake.state().devices.push(device);
        fake
    }

    /// Keeps listing the device, yet answers `DoesNotExist` to its removal,
    /// as when it goes between the two calls.
    pub fn vanishing(self, adapter: &str, address: &Address) -> Self {
        let path = device_path(adapter, address);
        if let Ok(device) = self.state().device(&path) {
            device.vanishing = true;
        }
        self
    }

    /// Whether `adapter` still holds a record of `address`.
    pub fn knows(&self, adapter: &str, address: &Address) -> bool {
        self.read(adapter, address, |_| ()).is_some()
    }

    /// Whether the device is bonded.
    pub fn paired(&self, adapter: &str, address: &Address) -> bool {
        self.read(adapter, address, |device| device.paired) == Some(true)
    }

    /// Whether a `Pair()` of the device is still unanswered.
    pub fn pairing(&self, adapter: &str, address: &Address) -> bool {
        self.read(adapter, address, |device| device.pairing) == Some(true)
    }

    /// The registered agent's object path and capability.
    pub fn agent(&self) -> Option<(OwnedObjectPath, String)> {
        self.state().agent.clone()
    }

    /// How many times the agent has been asked about a pairing.
    pub fn asked(&self) -> usize {
        self.state().asked
    }

    /// The calls received that change something, in order, as `Method arguments`.
    pub fn heard(&self) -> Vec<String> {
        self.state().heard.clone()
    }

    /// Starts the pairing an encrypted read of the device would, from `served`:
    /// asks the registered agent to authorise it, and bonds if it accepts.
    pub async fn implicit_pairing(
        &self,
        served: &Connection,
        adapter: &str,
        address: &Address,
    ) -> zbus::Result<Asked> {
        let device = device_path(adapter, address);
        let Some((agent, _)) = self.agent() else {
            return Ok(Asked::NoAgent);
        };
        self.state().asked += 1;
        let answer = served
            .call_method(
                None::<&str>,
                &agent,
                Some(AGENT),
                REQUEST_AUTHORIZATION,
                &(&device,),
            )
            .await;
        match answer {
            Ok(_) => {
                if let Ok(device) = self.state().device(&device) {
                    device.paired = true;
                }
                Ok(Asked::Accepted)
            }
            Err(error) if error_name(&error) == Some(REJECTED) => Ok(Asked::Rejected),
            Err(error) => Err(error),
        }
    }

    /// A client connection, and the served end to keep alive beside it.
    pub async fn connect(&self) -> zbus::Result<(Connection, Connection)> {
        let (ours, theirs) = tokio::net::UnixStream::pair()?;
        let mut served = Builder::unix_stream(theirs)
            .server(Guid::generate())?
            .p2p()
            .serve_at("/", Tree(self.clone()))?
            .serve_at(ROOT, AgentManager(self.clone()))?;
        let (adapters, devices) = {
            let state = self.state();
            let devices: Vec<_> = state.devices.iter().map(FakeDevice::path).collect();
            (state.adapters.clone(), devices)
        };
        for adapter in adapters {
            served = served.serve_at(adapter_path(&adapter), AdapterObject(self.clone()))?;
        }
        for device in devices {
            served = served.serve_at(device.clone(), DeviceObject(self.clone(), device))?;
        }
        let client = Builder::unix_stream(ours).p2p().build();
        let (served, client) = tokio::try_join!(served.build(), client)?;
        Ok((client, served))
    }
}

struct Tree(FakeBluez);

#[zbus::interface(name = "org.freedesktop.DBus.ObjectManager")]
impl Tree {
    fn get_managed_objects(&self) -> Objects {
        self.0.state().tree()
    }
}

struct AgentManager(FakeBluez);

#[zbus::interface(name = "org.bluez.AgentManager1")]
impl AgentManager {
    fn register_agent(&self, agent: ObjectPath<'_>, capability: String) -> Result<(), Fault> {
        let mut state = self.0.state();
        state
            .heard
            .push(format!("RegisterAgent {agent} {capability}"));
        if state.agent.is_some() {
            return Err(Fault::AlreadyExists(AGENT_REGISTERED.into()));
        }
        state.agent = Some((agent.into(), capability));
        Ok(())
    }

    fn unregister_agent(&self, agent: ObjectPath<'_>) -> Result<(), Fault> {
        let mut state = self.0.state();
        state.heard.push(format!("UnregisterAgent {agent}"));
        let registered = state
            .agent
            .take_if(|(path, _)| path.as_ref() == agent)
            .is_some();
        if !registered {
            return Err(Fault::DoesNotExist(NO_SUCH_AGENT.into()));
        }
        Ok(())
    }

    fn request_default_agent(&self, agent: ObjectPath<'_>) {
        let mut state = self.0.state();
        state.heard.push(format!("RequestDefaultAgent {agent}"));
    }
}

struct AdapterObject(FakeBluez);

#[zbus::interface(name = "org.bluez.Adapter1")]
impl AdapterObject {
    async fn remove_device(
        &self,
        device: ObjectPath<'_>,
        #[zbus(object_server)] server: &ObjectServer,
    ) -> Result<(), Fault> {
        {
            let mut state = self.0.state();
            state.heard.push(format!("RemoveDevice {device}"));
            let known = state
                .devices
                .iter()
                .position(|d| !d.vanishing && d.path().as_ref() == device)
                .ok_or_else(|| Fault::DoesNotExist(NO_SUCH_DEVICE.into()))?;
            state.devices.remove(known);
        }
        server.remove::<DeviceObject, _>(&device).await?;
        Ok(())
    }
}

struct DeviceObject(FakeBluez, OwnedObjectPath);

#[zbus::interface(name = "org.bluez.Device1")]
impl DeviceObject {
    async fn pair(&self) -> Result<(), Fault> {
        let cancelled = {
            let mut state = self.0.state();
            state.heard.push(format!("Pair {}", self.1));
            let agent = state.agent.is_some();
            let device = state.device(&self.1)?;
            if device.paired {
                return Err(Fault::AlreadyExists(ALREADY_PAIRED.into()));
            }
            if !agent {
                return Err(Fault::AuthenticationFailed(NO_AGENT.into()));
            }
            if let Some(reason) = device.refusing {
                return Err(Fault::scripted(reason));
            }
            if !device.silent {
                device.paired = true;
                return Ok(());
            }
            device.pairing = true;
            device.cancelled.clone()
        };
        cancelled.notified().await;
        Err(Fault::AuthenticationCanceled(CANCELLED.into()))
    }

    fn cancel_pairing(&self) -> Result<(), Fault> {
        let mut state = self.0.state();
        state.heard.push(format!("CancelPairing {}", self.1));
        let device = state.device(&self.1)?;
        if !device.pairing {
            return Err(Fault::DoesNotExist(NO_PAIRING.into()));
        }
        device.pairing = false;
        device.cancelled.notify_one();
        Ok(())
    }
}
