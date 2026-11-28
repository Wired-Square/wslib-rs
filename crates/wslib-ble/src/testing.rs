//! An in-process fake BlueZ, served over a socket pair.
//!
//! ```no_run
//! # async fn run() -> Result<(), Box<dyn std::error::Error>> {
//! use wslib_ble::testing::{FakeBluez, FakeDevice};
//! use wslib_ble::{Address, forget_on};
//!
//! let address: Address = "AA:BB:CC:DD:EE:FF".parse()?;
//! let fake = FakeBluez::new().with(FakeDevice::new("hci0", address));
//! let (bus, _served) = fake.connect().await?;
//! forget_on(&bus, "hci0", &address).await?;
//! # Ok(())
//! # }
//! ```

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};

use zbus::connection::Builder;
use zbus::zvariant::{ObjectPath, OwnedObjectPath, OwnedValue, Value};
use zbus::{Connection, DBusError, Guid};

use crate::Address;
use crate::bluez::{ADAPTER, DEVICE, DEVICE_ADAPTER, DEVICE_ADDRESS, Objects, Properties, ROOT};

const DEVICE_PAIRED: &str = "Paired";

/// A device a [`FakeBluez`] adapter has discovered.
#[derive(Debug, Clone)]
pub struct FakeDevice {
    adapter: String,
    address: Address,
    paired: bool,
    vanishing: bool,
}

impl FakeDevice {
    pub fn new(adapter: &str, address: Address) -> Self {
        Self {
            adapter: adapter.into(),
            address,
            paired: false,
            vanishing: false,
        }
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

#[derive(Debug, DBusError)]
#[zbus(prefix = "org.bluez.Error")]
enum Fault {
    #[zbus(error)]
    ZBus(zbus::Error),
    DoesNotExist(String),
}

#[derive(Debug, Default)]
struct State {
    adapters: Vec<String>,
    devices: Vec<FakeDevice>,
    heard: Vec<String>,
}

impl State {
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

/// A scripted BlueZ: the adapters, and the devices each has discovered.
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
        for device in &mut self.state().devices {
            device.vanishing |= device.path() == path;
        }
        self
    }

    /// Whether `adapter` still holds a record of `address`.
    pub fn knows(&self, adapter: &str, address: &Address) -> bool {
        let path = device_path(adapter, address);
        self.state().devices.iter().any(|d| d.path() == path)
    }

    /// The calls received that change something, in order, as `Method argument`.
    pub fn heard(&self) -> Vec<String> {
        self.state().heard.clone()
    }

    /// A client connection, and the served end to keep alive beside it.
    pub async fn connect(&self) -> zbus::Result<(Connection, Connection)> {
        let (ours, theirs) = tokio::net::UnixStream::pair()?;
        let mut served = Builder::unix_stream(theirs)
            .server(Guid::generate())?
            .p2p()
            .serve_at("/", Tree(self.clone()))?;
        for adapter in self.state().adapters.clone() {
            served = served.serve_at(adapter_path(&adapter), AdapterObject(self.clone()))?;
        }
        let client = Builder::unix_stream(ours).p2p().build();
        let (served, client) = tokio::try_join!(served.build(), client)?;
        Ok((client, served))
    }
}

struct Tree(FakeBluez);

#[zbus::interface(name = "org.freedesktop.DBus.ObjectManager")]
impl Tree {
    #[zbus(name = "GetManagedObjects")]
    fn get_managed_objects(&self) -> Objects {
        self.0.state().tree()
    }
}

struct AdapterObject(FakeBluez);

#[zbus::interface(name = "org.bluez.Adapter1")]
impl AdapterObject {
    #[zbus(name = "RemoveDevice")]
    fn remove_device(&self, device: ObjectPath<'_>) -> Result<(), Fault> {
        let mut state = self.0.state();
        state.heard.push(format!("RemoveDevice {device}"));
        let known = state
            .devices
            .iter()
            .position(|d| !d.vanishing && d.path().as_ref() == device)
            .ok_or_else(|| Fault::DoesNotExist("Does Not Exist".into()))?;
        state.devices.remove(known);
        Ok(())
    }
}
