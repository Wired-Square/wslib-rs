use std::collections::HashSet;
use std::time::Duration;

use btleplug::api::{
    Central as _, CentralEvent, Manager as _, Peripheral as _, PeripheralProperties, ScanFilter,
};
use btleplug::platform::{Adapter, Manager};
use futures_util::StreamExt;
use tokio::time::Instant;
use wslib_framelink_protocol::manufacturer_data::{COMPANY_ID, ManufacturerPayload};

use super::uuids::FRAMELINK_BLE_SERVICE_UUID;
use crate::Error;

/// A FrameLink device seen in a BLE scan.
#[derive(Clone, Debug)]
pub struct DiscoveredBleDevice {
    /// The advertised local name, such as `"WiredFlexLink-9C1C"`.
    pub name: String,
    /// btleplug's peripheral id, stable while the adapter lives.
    pub ble_id: String,
    pub rssi: Option<i16>,
    /// `None` when the advertisement carries no manufacturer data this crate
    /// decodes.
    pub payload: Option<ManufacturerPayload>,
}

/// The device an advertisement describes, if it advertises the FrameLink
/// service and a local name.
pub fn parse_peripheral(
    ble_id: String,
    props: &PeripheralProperties,
    rssi: Option<i16>,
) -> Option<DiscoveredBleDevice> {
    if !props.services.contains(&FRAMELINK_BLE_SERVICE_UUID) {
        return None;
    }
    let name = props.local_name.clone()?;
    let payload = props
        .manufacturer_data
        .get(&COMPANY_ID)
        .and_then(|bytes| ManufacturerPayload::decode(bytes).ok());
    Some(DiscoveredBleDevice {
        name,
        ble_id,
        rssi,
        payload,
    })
}

/// Every FrameLink device `adapter` sees within `timeout`, each once.
pub async fn scan(adapter: &Adapter, timeout: Duration) -> Result<Vec<DiscoveredBleDevice>, Error> {
    adapter.start_scan(ScanFilter::default()).await?;
    let mut events = adapter.events().await?;

    let deadline = Instant::now() + timeout;
    let mut seen: HashSet<String> = HashSet::new();
    let mut out = Vec::new();
    while let Ok(Some(event)) = tokio::time::timeout_at(deadline, events.next()).await {
        let (CentralEvent::DeviceDiscovered(id) | CentralEvent::DeviceUpdated(id)) = event else {
            continue;
        };
        let Ok(peripheral) = adapter.peripheral(&id).await else {
            continue;
        };
        let Ok(Some(props)) = peripheral.properties().await else {
            continue;
        };
        let ble_id = id.to_string();
        if let Some(device) = parse_peripheral(ble_id.clone(), &props, props.rssi)
            && seen.insert(ble_id)
        {
            out.push(device);
        }
    }
    adapter.stop_scan().await.ok();
    Ok(out)
}

/// [`scan`] on the first adapter, for a caller that holds none; one that
/// scans for long should keep its own adapter.
pub async fn scan_with_default_adapter(
    timeout: Duration,
) -> Result<Vec<DiscoveredBleDevice>, Error> {
    let adapter = default_adapter().await?;
    scan(&adapter, timeout).await
}

pub(crate) async fn default_adapter() -> Result<Adapter, Error> {
    Manager::new()
        .await?
        .adapters()
        .await?
        .into_iter()
        .next()
        .ok_or(Error::NoBleAdapter)
}
