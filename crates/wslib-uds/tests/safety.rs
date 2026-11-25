use wslib_uds::Safety::{Destructive, ReadOnly, StateChanging};
use wslib_uds::{NonEmpty, ReadOnly as ReadOnlyRequest, Request, Safety, SubFunction, sid};

#[test]
fn safety_is_ordered_read_only_state_changing_destructive() {
    assert!(ReadOnly < StateChanging);
    assert!(StateChanging < Destructive);
}

#[test]
fn reading_dtcs_and_data_is_read_only() {
    assert_eq!(Safety::of(&[0x19, 0x02, 0xFF]), ReadOnly);
    assert_eq!(Safety::of(&[0x22, 0xF1, 0x90]), ReadOnly);
}

#[test]
fn reading_memory_is_state_changing_for_its_side_effects() {
    assert_eq!(Safety::of(&[0x23, 0x11, 0x10, 0x01]), StateChanging);
}

#[test]
fn tester_present_is_read_only() {
    assert_eq!(Safety::of(&[0x3E, 0x00]), ReadOnly);
    assert_eq!(Safety::of(&[0x3E, 0x80]), ReadOnly);
}

#[test]
fn session_control_is_state_changing() {
    assert_eq!(Safety::of(&[0x10, 0x01]), StateChanging);
    assert_eq!(Safety::of(&[0x10, 0x83]), StateChanging);
}

#[test]
fn entering_the_programming_session_is_destructive() {
    assert_eq!(Safety::of(&[0x10, 0x02]), Destructive);
    assert_eq!(Safety::of(&[0x10, 0x82]), Destructive);
    let programming = Request::DiagnosticSessionControl {
        sub_function: SubFunction::new(0x02),
    };
    assert_eq!(programming.safety(), Destructive);
}

#[test]
fn ecu_reset_is_state_changing() {
    assert_eq!(Safety::of(&[0x11, 0x01]), StateChanging);
}

#[test]
fn security_access_is_state_changing() {
    assert_eq!(Safety::of(&[0x27, 0x01]), StateChanging);
    assert_eq!(Safety::of(&[0x27, 0x02, 0x12, 0x34]), StateChanging);
}

#[test]
fn communication_control_is_state_changing() {
    assert_eq!(Safety::of(&[0x28, 0x03, 0x01]), StateChanging);
}

#[test]
fn control_dtc_setting_is_state_changing() {
    assert_eq!(Safety::of(&[0x85, 0x02]), StateChanging);
}

#[test]
fn clearing_dtcs_is_destructive() {
    assert_eq!(Safety::of(&[0x14, 0xFF, 0xFF, 0xFF]), Destructive);
}

#[test]
fn writing_data_is_destructive() {
    assert_eq!(Safety::of(&[0x2E, 0xF1, 0x90, 0x00]), Destructive);
}

#[test]
fn input_output_control_is_destructive() {
    assert_eq!(Safety::of(&[0x2F, 0x01, 0x23, 0x03]), Destructive);
}

#[test]
fn routine_start_and_stop_are_destructive_and_its_results_read_only() {
    assert_eq!(Safety::of(&[0x31, 0x01, 0x02, 0x03]), Destructive);
    assert_eq!(Safety::of(&[0x31, 0x02, 0x02, 0x03]), Destructive);
    assert_eq!(Safety::of(&[0x31, 0x03, 0x02, 0x03]), ReadOnly);
    assert_eq!(Safety::of(&[0x31, 0x83, 0x02, 0x03]), ReadOnly);
    assert_eq!(Safety::of(&[0x31, 0x04, 0x02, 0x03]), Destructive);
}

#[test]
fn download_upload_and_transfer_are_destructive() {
    assert_eq!(Safety::of(&[0x34, 0x00, 0x11, 0x00, 0x10]), Destructive);
    assert_eq!(Safety::of(&[0x35, 0x00, 0x11, 0x00, 0x10]), Destructive);
    assert_eq!(Safety::of(&[0x36, 0x01, 0xAA]), Destructive);
    assert_eq!(Safety::of(&[0x37]), Destructive);
}

#[test]
fn other_iso_services_vendor_services_and_an_empty_message_are_destructive() {
    assert_eq!(Safety::of(&[0x24, 0xF1, 0x90]), Destructive);
    assert_eq!(Safety::of(&[0x3D, 0x11, 0x10, 0x01, 0xFF]), Destructive);
    assert_eq!(Safety::of(&[0xBA, 0x01]), Destructive);
    assert_eq!(Safety::of(&[0xBA]), Destructive);
    assert_eq!(Safety::of(&[]), Destructive);
}

#[test]
fn a_bare_service_id_has_its_services_class_with_the_sub_function_unknown() {
    for service in sid::iso() {
        let expected = match service {
            0x19 | 0x22 | 0x3E => ReadOnly,
            0x10 | 0x11 | 0x23 | 0x27 | 0x28 | 0x85 => StateChanging,
            _ => Destructive,
        };
        assert_eq!(Safety::of(&[service]), expected, "0x{service:02X}");
    }
    assert_eq!(Safety::of(&[0xBA]), Destructive);
}

#[test]
fn a_typed_request_has_the_class_of_its_bytes() {
    let reset = Request::EcuReset {
        sub_function: SubFunction::new(0x01),
    };
    assert_eq!(reset.safety(), StateChanging);
    let results = Request::RoutineControl {
        sub_function: SubFunction::new(0x03),
        routine: 0x0203,
        data: vec![],
    };
    assert_eq!(results.safety(), ReadOnly);
}

#[test]
fn the_read_only_wrapper_refuses_any_other_class() {
    let read = Request::ReadDataByIdentifier {
        dids: NonEmpty::one(0xF190),
    };
    assert_eq!(ReadOnlyRequest::new(read.clone()).unwrap().request(), &read);
    let write = Request::WriteDataByIdentifier {
        did: 0xF190,
        data: NonEmpty::one(0),
    };
    let refused = ReadOnlyRequest::new(write.clone()).unwrap_err();
    assert_eq!(refused.safety, Destructive);
    assert_eq!(refused.request, write);
    let session = Request::DiagnosticSessionControl {
        sub_function: SubFunction::new(0x03),
    };
    assert_eq!(
        ReadOnlyRequest::try_from(session).unwrap_err().safety,
        StateChanging
    );
}
