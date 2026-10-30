//! The manufacturer data's bytes, pinned: the firmware's `ble.h` and its
//! advertiser carry the same layout.

use wslib_framelink_protocol::manufacturer_data::{
    COMPANY_ID, CapabilityFlagsBuilder, ManufacturerPayload, PAYLOAD_LEN, SCHEMA_VERSION_V1,
};

#[test]
fn company_id_is_the_test_range() {
    assert_eq!(COMPANY_ID, 0xFFFF);
}

#[test]
fn a_v1_payload_is_six_bytes() {
    assert_eq!(PAYLOAD_LEN, 6);
    assert_eq!(SCHEMA_VERSION_V1, 0x01);
}

#[test]
fn the_ble_transport_flag_is_bit_2() {
    let flags = CapabilityFlagsBuilder::new().framelink_ble(true).build();
    assert_eq!(flags.bits(), 1 << 2);
    assert!(flags.has_framelink_ble());
}

#[test]
fn a_release_builds_payload_matches_its_golden_vector() {
    let caps = CapabilityFlagsBuilder::new()
        .wifi_prov(true)
        .smp(true)
        .caps(true)
        .pairing_required(true)
        .build();
    let payload = ManufacturerPayload::new_v1(caps, 0x10, 0, 1);
    assert_eq!(payload.encode(), [0x01, 0x1B, 0x00, 0x10, 0x00, 0x01]);
}
