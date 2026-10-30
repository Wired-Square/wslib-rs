//! The firmware's `ble.h` carries the same UUIDs; `tests/ble_constants.rs`
//! pins their bytes.

use uuid::Uuid;

/// Every FrameLink device advertises this service.
pub const FRAMELINK_BLE_SERVICE_UUID: Uuid =
    Uuid::from_u128(0x14387a00_130c_49e7_b877_2881c89cb258);

/// Reads back the advertised manufacturer data over a connection, for a
/// caller that does not trust an unauthenticated advertisement.
pub const FRAMELINK_BLE_INFO_CHAR_UUID: Uuid =
    Uuid::from_u128(0x14387a01_130c_49e7_b877_2881c89cb258);

pub const WIFI_PROV_SERVICE_UUID: Uuid = Uuid::from_u128(0x14387800_130c_49e7_b877_2881c89cb258);

/// The standard SMP firmware-upgrade service.
pub const SMP_SERVICE_UUID: Uuid = Uuid::from_u128(0x8d53dc1d_1db7_4cd3_868b_8a527460aa84);
