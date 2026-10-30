//! FrameLink devices over BLE: a one-shot scan, the GATT UUIDs and, with
//! `wifi-prov`, Wi-Fi provisioning.

#[cfg(any(feature = "wifi-prov", feature = "smp"))]
pub(crate) mod notify_dispatcher;
mod scan;
mod uuids;

#[cfg(feature = "wifi-prov")]
pub mod wifi_prov;

#[cfg(feature = "discovery")]
pub(crate) use scan::default_adapter;
pub use scan::{DiscoveredBleDevice, parse_peripheral, scan, scan_with_default_adapter};
pub use uuids::{
    FRAMELINK_BLE_INFO_CHAR_UUID, FRAMELINK_BLE_SERVICE_UUID, SMP_SERVICE_UUID,
    WIFI_PROV_SERVICE_UUID,
};
