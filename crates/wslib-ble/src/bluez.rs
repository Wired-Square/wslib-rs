use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use tokio::time::timeout;
use zbus::zvariant::{ObjectPath, OwnedObjectPath, OwnedValue};
use zbus::{Connection, DBusError, interface, proxy};

use crate::{Address, ForgetError, Forgotten, PairError, Paired, Refusal};

pub(crate) const ROOT: &str = "/org/bluez";
pub(crate) const ADAPTER: &str = "org.bluez.Adapter1";
pub(crate) const DEVICE: &str = "org.bluez.Device1";
pub(crate) const DEVICE_ADDRESS: &str = "Address";
pub(crate) const DEVICE_ADAPTER: &str = "Adapter";
const ALREADY_EXISTS: &str = "org.bluez.Error.AlreadyExists";
const DOES_NOT_EXIST: &str = "org.bluez.Error.DoesNotExist";
const UNKNOWN_OBJECT: &str = "org.freedesktop.DBus.Error.UnknownObject";
const UNKNOWN_METHOD: &str = "org.freedesktop.DBus.Error.UnknownMethod";
const AGENT_PATH: ObjectPath<'static> = ObjectPath::from_static_str_unchecked("/wslib/ble/agent");
const AGENT_CAPABILITY: &str = "NoInputNoOutput";
const NOT_THIS_DEVICE: &str = "not the device being paired";
const NOT_JUST_WORKS: &str = "only a pairing that asks a person nothing is authorised";

/// How long withdrawing the agent or cancelling a pairing may take.
pub(crate) const WITHDRAW_LIMIT: Duration = Duration::from_secs(5);

pub(crate) type Properties = HashMap<String, OwnedValue>;
pub(crate) type Objects = HashMap<OwnedObjectPath, HashMap<String, Properties>>;

#[proxy(
    interface = "org.freedesktop.DBus.ObjectManager",
    default_service = "org.bluez",
    default_path = "/"
)]
trait ObjectManager {
    fn get_managed_objects(&self) -> zbus::Result<Objects>;
}

#[proxy(interface = "org.bluez.Adapter1", default_service = "org.bluez")]
trait Adapter {
    fn remove_device(&self, device: &ObjectPath<'_>) -> zbus::Result<()>;
}

#[proxy(
    interface = "org.bluez.AgentManager1",
    default_service = "org.bluez",
    default_path = "/org/bluez"
)]
trait AgentManager {
    fn register_agent(&self, agent: &ObjectPath<'_>, capability: &str) -> zbus::Result<()>;
    fn unregister_agent(&self, agent: &ObjectPath<'_>) -> zbus::Result<()>;
}

#[proxy(interface = "org.bluez.Device1", default_service = "org.bluez")]
trait Device {
    fn pair(&self) -> zbus::Result<()>;
    fn cancel_pairing(&self) -> zbus::Result<()>;
}

pub(crate) struct Located {
    pub(crate) adapter: OwnedObjectPath,
    pub(crate) device: Option<OwnedObjectPath>,
}

fn prop<T: TryFrom<OwnedValue>>(properties: &Properties, key: &str) -> Option<T> {
    T::try_from(properties.get(key)?.clone()).ok()
}

pub(crate) fn error_name(error: &zbus::Error) -> Option<&str> {
    match error {
        zbus::Error::MethodError(name, _, _) => Some(name.as_str()),
        _ => None,
    }
}

fn error_detail(error: &zbus::Error) -> Option<String> {
    match error {
        zbus::Error::MethodError(_, detail, _) => detail.clone(),
        _ => None,
    }
}

pub(crate) async fn locate(
    connection: &Connection,
    adapter: &str,
    address: &Address,
) -> zbus::Result<Option<Located>> {
    let Ok(adapter) = OwnedObjectPath::try_from(format!("{ROOT}/{adapter}")) else {
        return Ok(None);
    };
    let objects = ObjectManagerProxy::new(connection)
        .await?
        .get_managed_objects()
        .await?;
    let is_adapter = objects
        .get(&adapter)
        .is_some_and(|interfaces| interfaces.contains_key(ADAPTER));
    if !is_adapter {
        return Ok(None);
    }
    let device = objects.into_iter().find_map(|(path, interfaces)| {
        let device = interfaces.get(DEVICE)?;
        let on: OwnedObjectPath = prop(device, DEVICE_ADAPTER)?;
        let at: Address = prop::<String>(device, DEVICE_ADDRESS)?.parse().ok()?;
        (on == adapter && at == *address).then_some(path)
    });
    Ok(Some(Located { adapter, device }))
}

/// Removes the bond with `address` and BlueZ's record of it on `adapter`,
/// over `connection`; the device must be discovered again before it is used.
pub async fn forget_on(
    connection: &Connection,
    adapter: &str,
    address: &Address,
) -> Result<Forgotten, ForgetError> {
    let located = locate(connection, adapter, address)
        .await
        .map_err(ForgetError::Service)?
        .ok_or_else(|| ForgetError::NoAdapter {
            adapter: adapter.into(),
        })?;
    let Some(device) = located.device else {
        return Ok(Forgotten::NotKnown);
    };
    let removed = async {
        AdapterProxy::builder(connection)
            .path(located.adapter)?
            .build()
            .await?
            .remove_device(&device)
            .await
    };
    match removed.await {
        Ok(()) => Ok(Forgotten::Removed),
        Err(error) if error_name(&error) == Some(DOES_NOT_EXIST) => Ok(Forgotten::NotKnown),
        Err(error) => Err(ForgetError::Service(error)),
    }
}

#[derive(Debug, DBusError)]
#[zbus(prefix = "org.bluez.Error")]
enum AgentError {
    #[zbus(error)]
    ZBus(zbus::Error),
    Rejected(String),
}

fn not_just_works<T>() -> Result<T, AgentError> {
    Err(AgentError::Rejected(NOT_JUST_WORKS.into()))
}

struct Agent {
    device: OwnedObjectPath,
}

#[interface(name = "org.bluez.Agent1")]
impl Agent {
    fn release(&self) {}

    fn request_pin_code(&self, _device: ObjectPath<'_>) -> Result<String, AgentError> {
        not_just_works()
    }

    fn display_pin_code(&self, _device: ObjectPath<'_>, _pin: &str) -> Result<(), AgentError> {
        not_just_works()
    }

    fn request_passkey(&self, _device: ObjectPath<'_>) -> Result<u32, AgentError> {
        not_just_works()
    }

    fn display_passkey(
        &self,
        _device: ObjectPath<'_>,
        _passkey: u32,
        _entered: u16,
    ) -> Result<(), AgentError> {
        not_just_works()
    }

    fn request_confirmation(
        &self,
        _device: ObjectPath<'_>,
        _passkey: u32,
    ) -> Result<(), AgentError> {
        not_just_works()
    }

    fn request_authorization(&self, device: ObjectPath<'_>) -> Result<(), AgentError> {
        if self.device.as_ref() == device {
            Ok(())
        } else {
            Err(AgentError::Rejected(NOT_THIS_DEVICE.into()))
        }
    }

    fn authorize_service(&self, _device: ObjectPath<'_>, _uuid: &str) -> Result<(), AgentError> {
        not_just_works()
    }

    fn cancel(&self) {}
}

async fn withdraw(connection: &Connection) -> zbus::Result<()> {
    let unregistered = async {
        AgentManagerProxy::new(connection)
            .await?
            .unregister_agent(&AGENT_PATH)
            .await
    };
    let unregistered = unregistered.await;
    connection
        .object_server()
        .remove::<Agent, _>(AGENT_PATH)
        .await?;
    unregistered
}

fn gone(error: &zbus::Error) -> bool {
    matches!(error_name(error), Some(UNKNOWN_OBJECT | UNKNOWN_METHOD))
}

#[derive(Debug)]
pub(crate) struct Session {
    connection: Connection,
    adapter: String,
    address: Address,
    device: OwnedObjectPath,
    unsettled: AtomicBool,
}

impl Session {
    pub(crate) async fn confirm(
        connection: Connection,
        adapter: &str,
        address: &Address,
    ) -> Result<Self, PairError> {
        let located = locate(&connection, adapter, address)
            .await
            .map_err(PairError::Service)?
            .ok_or_else(|| PairError::NoAdapter {
                adapter: adapter.into(),
            })?;
        let device = located.device.ok_or_else(|| PairError::UnknownDevice {
            adapter: adapter.into(),
            address: *address,
        })?;
        let agent = Agent {
            device: device.clone(),
        };
        let served = connection
            .object_server()
            .at(AGENT_PATH, agent)
            .await
            .map_err(PairError::Service)?;
        if !served {
            return Err(PairError::AgentExists);
        }
        let registered = async {
            AgentManagerProxy::new(&connection)
                .await?
                .register_agent(&AGENT_PATH, AGENT_CAPABILITY)
                .await
        };
        if let Err(error) = registered.await {
            let _ = connection
                .object_server()
                .remove::<Agent, _>(AGENT_PATH)
                .await;
            return Err(PairError::Service(error));
        }
        Ok(Self {
            connection,
            adapter: adapter.into(),
            address: *address,
            device,
            unsettled: AtomicBool::new(false),
        })
    }

    async fn device(&self) -> Result<DeviceProxy<'static>, PairError> {
        let device = async {
            DeviceProxy::builder(&self.connection)
                .path(self.device.clone())?
                .build()
                .await
        };
        device.await.map_err(PairError::Service)
    }

    async fn settle(&self, device: &DeviceProxy<'_>) -> Result<(), PairError> {
        let cancelled = timeout(WITHDRAW_LIMIT, device.cancel_pairing())
            .await
            .map_err(|_| PairError::TimedOut {
                limit: WITHDRAW_LIMIT,
            })?;
        match cancelled {
            Err(error) if error_name(&error) != Some(DOES_NOT_EXIST) && !gone(&error) => {
                Err(PairError::Service(error))
            }
            _ => {
                self.unsettled.store(false, Ordering::Release);
                Ok(())
            }
        }
    }

    pub(crate) async fn pair(&self, limit: Duration) -> Result<Paired, PairError> {
        let device = self.device().await?;
        if self.unsettled.load(Ordering::Acquire) {
            self.settle(&device).await?;
        }
        self.unsettled.store(true, Ordering::Release);
        let Ok(answer) = timeout(limit, device.pair()).await else {
            let _ = self.settle(&device).await;
            return Err(PairError::TimedOut { limit });
        };
        self.unsettled.store(false, Ordering::Release);
        let Err(error) = answer else {
            return Ok(Paired::New);
        };
        let name = error_name(&error);
        if name == Some(ALREADY_EXISTS) {
            return Ok(Paired::Existing);
        }
        if gone(&error) {
            return Err(PairError::UnknownDevice {
                adapter: self.adapter.clone(),
                address: self.address,
            });
        }
        match name.and_then(Refusal::from_name) {
            Some(reason) => Err(PairError::Refused {
                reason,
                detail: error_detail(&error),
            }),
            None => Err(PairError::Service(error)),
        }
    }

    pub(crate) async fn close(self) -> Result<(), PairError> {
        let settled = async {
            if self.unsettled.load(Ordering::Acquire) {
                self.settle(&self.device().await?).await?;
            }
            Ok(())
        };
        let settled = settled.await;
        let withdrawn = timeout(WITHDRAW_LIMIT, withdraw(&self.connection))
            .await
            .map_err(|_| PairError::TimedOut {
                limit: WITHDRAW_LIMIT,
            })?;
        withdrawn.map_err(PairError::Service)?;
        settled
    }
}

#[cfg(test)]
mod tests {
    use zbus::proxy::Defaults;

    use super::*;

    const SERVICE: &str = "org.bluez";

    fn service<P: Defaults>() -> Option<&'static str> {
        P::DESTINATION.as_ref().map(|name| name.as_str())
    }

    #[test]
    fn the_names_bluez_is_reached_by_are_fixed() {
        assert_eq!(service::<ObjectManagerProxy<'_>>(), Some(SERVICE));
        assert_eq!(service::<AdapterProxy<'_>>(), Some(SERVICE));
        assert_eq!(service::<DeviceProxy<'_>>(), Some(SERVICE));
        assert_eq!(service::<AgentManagerProxy<'_>>(), Some(SERVICE));
        let manager = AgentManagerProxy::PATH.as_ref().map(|path| path.as_str());
        assert_eq!(manager, Some(ROOT));
        assert_eq!(ROOT, "/org/bluez");
        assert_eq!(AGENT_CAPABILITY, "NoInputNoOutput");
    }
}
