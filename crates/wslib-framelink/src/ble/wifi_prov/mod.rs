//! Wi-Fi provisioning over BLE: credentials written to a device's
//! provisioning GATT service before it is on any network. Open a session with
//! [`Discovery::open_wifi_prov`](crate::Discovery::open_wifi_prov); dropping
//! it releases the link.

mod session;
mod types;
mod uuids;

pub use session::WifiProvSession;
pub(crate) use session::open_session;
pub use types::{ProvisioningEvent, ProvisioningStatus, WifiCredentials, WifiSecurity, WifiStatus};
