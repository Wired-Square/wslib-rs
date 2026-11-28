use std::collections::HashMap;

use zbus::zvariant::{ObjectPath, OwnedObjectPath, OwnedValue};
use zbus::{Connection, proxy};

use crate::{Address, ForgetError, Forgotten};

pub(crate) const ROOT: &str = "/org/bluez";
pub(crate) const ADAPTER: &str = "org.bluez.Adapter1";
pub(crate) const DEVICE: &str = "org.bluez.Device1";
pub(crate) const DEVICE_ADDRESS: &str = "Address";
pub(crate) const DEVICE_ADAPTER: &str = "Adapter";
const DOES_NOT_EXIST: &str = "org.bluez.Error.DoesNotExist";

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
