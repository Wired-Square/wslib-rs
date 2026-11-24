use wslib_uds::{Detail, Identity, Nrc, identify, sid};

fn label(request: &[u8]) -> String {
    identify(request).unwrap().to_string()
}

#[test]
fn service_ids_carry_their_standard_names() {
    assert_eq!(sid::name(0x10), Some("DiagnosticSessionControl"));
    assert_eq!(sid::name(0x22), Some("ReadDataByIdentifier"));
    assert_eq!(sid::name(0x85), Some("ControlDTCSetting"));
    assert_eq!(sid::name(0xBA), None);
}

#[test]
fn the_iso_service_list_is_ascending_and_named() {
    let ids: Vec<u8> = sid::iso().collect();
    assert!(ids.windows(2).all(|w| w[0] < w[1]));
    assert!(ids.iter().all(|id| sid::name(*id).is_some()));
    assert_eq!(ids.len(), 27);
}

#[test]
fn negative_response_codes_carry_their_standard_names() {
    assert_eq!(Nrc(0x11).name(), Some("serviceNotSupported"));
    assert_eq!(
        Nrc::RESPONSE_PENDING.name(),
        Some("requestCorrectlyReceivedResponsePending")
    );
    assert_eq!(
        Nrc(0xF3).name(),
        Some("vehicleManufacturerSpecificConditionsNotCorrect")
    );
    assert_eq!(Nrc(0x95).name(), None);
    assert_eq!(Nrc(0x31).to_string(), "requestOutOfRange (0x31)");
    assert_eq!(Nrc(0x95).to_string(), "0x95");
}

#[test]
fn a_request_prefix_names_its_did_routine_or_session() {
    assert_eq!(
        label(&[0x22, 0xF1, 0x90]),
        "ReadDataByIdentifier DID 0xF190"
    );
    assert_eq!(
        label(&[0x22, 0xF1, 0x90, 0xF1, 0x8C, 0xF1]),
        "ReadDataByIdentifier DIDs 0xF190, 0xF18C"
    );
    assert_eq!(
        label(&[0x31, 0x01, 0x02, 0x03, 0xFF]),
        "RoutineControl routine 0x0203 start"
    );
    assert_eq!(
        label(&[0x31, 0x83, 0x02, 0x03]),
        "RoutineControl routine 0x0203 results"
    );
    assert_eq!(
        label(&[0x10, 0x03]),
        "DiagnosticSessionControl session 0x03"
    );
    assert_eq!(
        label(&[0x10, 0x83]),
        "DiagnosticSessionControl session 0x03"
    );
    assert_eq!(
        label(&[0x2E, 0xF1, 0x90, 0x00]),
        "WriteDataByIdentifier DID 0xF190"
    );
    assert_eq!(label(&[0x27, 0x01]), "SecurityAccess seed 0x01");
    assert_eq!(label(&[0x27, 0x02, 0xAA]), "SecurityAccess key 0x02");
    assert_eq!(
        label(&[0x14, 0xFF, 0xFF, 0xFF]),
        "ClearDiagnosticInformation group 0xFFFFFF"
    );
    assert_eq!(label(&[0x19, 0x02, 0xFF]), "ReadDTCInformation report 0x02");
    assert_eq!(
        label(&[0x23, 0x12, 0x10, 0x00, 0x40]),
        "ReadMemoryByAddress address 0x1000 size 0x40"
    );
    assert_eq!(
        label(&[0x34, 0x00, 0x12, 0x10, 0x00, 0x40]),
        "RequestDownload address 0x1000 size 0x40"
    );
    assert_eq!(label(&[0x36, 0x05, 0x00]), "TransferData block 0x05");
    assert_eq!(
        label(&[0x28, 0x03, 0x01]),
        "CommunicationControl control 0x03"
    );
    assert_eq!(label(&[0x85, 0x02]), "ControlDTCSetting setting 0x02");
    assert_eq!(label(&[0x11, 0x01]), "ECUReset reset 0x01");
}

#[test]
fn a_prefix_too_short_for_its_detail_names_only_the_service() {
    assert_eq!(label(&[0x22, 0xF1]), "ReadDataByIdentifier");
    assert_eq!(label(&[0x31, 0x01, 0x02]), "RoutineControl");
    assert_eq!(label(&[0x3E, 0x00]), "TesterPresent");
    assert_eq!(label(&[0xBA, 0x01]), "service 0xBA");
    assert_eq!(identify(&[]), None);
    assert_eq!(
        identify(&[0x10, 0x02]),
        Some(Identity {
            service: 0x10,
            detail: Some(Detail::Session { session: 0x02 })
        })
    );
}

#[test]
fn a_bare_download_or_upload_id_names_the_service_with_no_detail() {
    for service in [0x34, 0x35] {
        assert_eq!(
            identify(&[service]),
            Some(Identity {
                service,
                detail: None
            })
        );
    }
    assert_eq!(label(&[0x34, 0x00]), "RequestDownload");
}

#[test]
fn the_table_knows_which_services_carry_a_sub_function() {
    let with: Vec<u8> = sid::iso().filter(|s| sid::has_sub_function(*s)).collect();
    assert_eq!(
        with,
        [
            0x10, 0x11, 0x19, 0x27, 0x28, 0x29, 0x2C, 0x31, 0x3E, 0x83, 0x85, 0x86, 0x87
        ]
    );
    assert!(!sid::has_sub_function(0xBA));
}
