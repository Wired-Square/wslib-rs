//! The provisioning service's characteristics, all under
//! [`WIFI_PROV_SERVICE_UUID`](crate::ble::WIFI_PROV_SERVICE_UUID).

use uuid::Uuid;

/// Read and write: the stored SSID, or the one staged for
/// [`CONTROL_SAVE_CONNECT`].
pub const CHAR_SSID_UUID: Uuid = Uuid::from_u128(0x14387801_130c_49e7_b877_2881c89cb258);

/// Write only; not written for an open network.
pub const CHAR_PASSPHRASE_UUID: Uuid = Uuid::from_u128(0x14387802_130c_49e7_b877_2881c89cb258);

/// One byte, a [`WifiSecurity`](super::WifiSecurity).
pub const CHAR_SECURITY_UUID: Uuid = Uuid::from_u128(0x14387803_130c_49e7_b877_2881c89cb258);

/// Write only, one of the `CONTROL_*` bytes.
pub const CHAR_CONTROL_UUID: Uuid = Uuid::from_u128(0x14387804_130c_49e7_b877_2881c89cb258);

/// Read and notify, one byte: a [`WifiStatus`](super::WifiStatus).
pub const CHAR_STATUS_UUID: Uuid = Uuid::from_u128(0x14387805_130c_49e7_b877_2881c89cb258);

/// Read and notify: four IPv4 octets, all zero for none yet.
pub const CHAR_IP_ADDR_UUID: Uuid = Uuid::from_u128(0x14387806_130c_49e7_b877_2881c89cb258);

/// Save the staged credentials and connect.
pub const CONTROL_SAVE_CONNECT: u8 = 0x01;
/// Forget every stored credential.
pub const CONTROL_DELETE_ALL: u8 = 0x02;
/// Leave the network, keeping its credentials.
pub const CONTROL_DISCONNECT: u8 = 0x03;
