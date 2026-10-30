//! The BLE identifiers' bytes, pinned: the firmware's `ble.h` carries the
//! same.

use wslib_framelink::CapabilitySet;
use wslib_framelink_protocol::manufacturer_data::CapabilityFlagsBuilder;

#[cfg(feature = "ble")]
#[test]
fn the_framelink_service_uuid_is_pinned() {
    assert_eq!(
        wslib_framelink::ble::FRAMELINK_BLE_SERVICE_UUID.as_bytes(),
        &[
            0x14, 0x38, 0x7a, 0x00, 0x13, 0x0c, 0x49, 0xe7, 0xb8, 0x77, 0x28, 0x81, 0xc8, 0x9c,
            0xb2, 0x58
        ]
    );
}

#[cfg(feature = "ble")]
#[test]
fn the_info_characteristic_uuid_is_pinned() {
    assert_eq!(
        wslib_framelink::ble::FRAMELINK_BLE_INFO_CHAR_UUID.as_bytes(),
        &[
            0x14, 0x38, 0x7a, 0x01, 0x13, 0x0c, 0x49, 0xe7, 0xb8, 0x77, 0x28, 0x81, 0xc8, 0x9c,
            0xb2, 0x58
        ]
    );
}

#[test]
fn each_capability_is_the_manufacturer_datas_bit() {
    let flags = CapabilityFlagsBuilder::new;
    for (set, built) in [
        (CapabilitySet::WIFI_PROV, flags().wifi_prov(true)),
        (CapabilitySet::SMP, flags().smp(true)),
        (CapabilitySet::FRAMELINK_BLE, flags().framelink_ble(true)),
        (CapabilitySet::CAPS, flags().caps(true)),
        (
            CapabilitySet::PAIRING_REQUIRED,
            flags().pairing_required(true),
        ),
    ] {
        assert_eq!(set, CapabilitySet::from(built.build()), "{set}");
    }
}
