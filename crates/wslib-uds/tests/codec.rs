use wslib_uds::{
    BlockLength, DecodeError, DtcRequest, DtcResponse, DtcStatus, InvalidWidth, MemoryRange, Nrc,
    Request, Response, SessionTiming, SubFunction, sid,
};

fn request_round_trips(bytes: &[u8], expected: Request) {
    let decoded = Request::decode(bytes).unwrap();
    assert_eq!(decoded, expected);
    assert_eq!(decoded.encode(), bytes);
}

fn response_round_trips(bytes: &[u8], expected: Response) {
    let decoded = Response::decode(bytes).unwrap();
    assert_eq!(decoded, expected);
    assert_eq!(decoded.encode(), bytes);
}

#[test]
fn session_control_keeps_the_suppress_bit_apart_from_the_session() {
    request_round_trips(
        &[0x10, 0x83],
        Request::DiagnosticSessionControl {
            sub_function: SubFunction::suppressed(0x03),
        },
    );
    response_round_trips(
        &[0x50, 0x03, 0x00, 0x32, 0x01, 0xF4],
        Response::DiagnosticSessionControl {
            session: 0x03,
            timing: Some(SessionTiming {
                p2_server_max_ms: 50,
                p2_star_server_max_10ms: 500,
            }),
        },
    );
    response_round_trips(
        &[0x50, 0x01],
        Response::DiagnosticSessionControl {
            session: 0x01,
            timing: None,
        },
    );
}

#[test]
fn session_timing_reads_p2_in_milliseconds_and_p2_star_in_tens_of_milliseconds() {
    let timing = SessionTiming {
        p2_server_max_ms: 50,
        p2_star_server_max_10ms: 500,
    };
    assert_eq!(timing.p2().as_millis(), 50);
    assert_eq!(timing.p2_star().as_millis(), 5000);
}

#[test]
fn ecu_reset_round_trips() {
    request_round_trips(
        &[0x11, 0x01],
        Request::EcuReset {
            sub_function: SubFunction::new(0x01),
        },
    );
    response_round_trips(
        &[0x51, 0x04, 0x0A],
        Response::EcuReset {
            reset_type: 0x04,
            power_down_time: Some(0x0A),
        },
    );
}

#[test]
fn clear_diagnostic_information_takes_a_24_bit_group_and_an_optional_memory_selection() {
    request_round_trips(
        &[0x14, 0xFF, 0xFF, 0xFF],
        Request::ClearDiagnosticInformation {
            group: 0xFF_FFFF,
            memory_selection: None,
        },
    );
    request_round_trips(
        &[0x14, 0x12, 0x34, 0x56, 0x01],
        Request::ClearDiagnosticInformation {
            group: 0x12_3456,
            memory_selection: Some(0x01),
        },
    );
    response_round_trips(&[0x54], Response::ClearDiagnosticInformation);
}

#[test]
fn read_dtc_information_types_the_common_report_types() {
    request_round_trips(
        &[0x19, 0x02, 0x08],
        Request::ReadDtcInformation {
            report: DtcRequest::ByStatusMask { status_mask: 0x08 },
            suppress_positive_response: false,
        },
    );
    request_round_trips(
        &[0x19, 0x01, 0xFF],
        Request::ReadDtcInformation {
            report: DtcRequest::NumberByStatusMask { status_mask: 0xFF },
            suppress_positive_response: false,
        },
    );
    request_round_trips(
        &[0x19, 0x04, 0x12, 0x34, 0x56, 0xFF],
        Request::ReadDtcInformation {
            report: DtcRequest::SnapshotRecordByDtc {
                dtc: 0x12_3456,
                record: 0xFF,
            },
            suppress_positive_response: false,
        },
    );
    request_round_trips(
        &[0x19, 0x06, 0x12, 0x34, 0x56, 0x01],
        Request::ReadDtcInformation {
            report: DtcRequest::ExtendedDataRecordByDtc {
                dtc: 0x12_3456,
                record: 0x01,
            },
            suppress_positive_response: false,
        },
    );
    request_round_trips(
        &[0x19, 0x8A],
        Request::ReadDtcInformation {
            report: DtcRequest::SupportedDtcs,
            suppress_positive_response: true,
        },
    );
    request_round_trips(
        &[0x19, 0x42, 0x33, 0x01],
        Request::ReadDtcInformation {
            report: DtcRequest::Other {
                report_type: 0x42,
                data: vec![0x33, 0x01],
            },
            suppress_positive_response: false,
        },
    );
    response_round_trips(
        &[0x59, 0x01, 0xFF, 0x01, 0x00, 0x02],
        Response::ReadDtcInformation {
            report: DtcResponse::NumberByStatusMask {
                availability_mask: 0xFF,
                format: 0x01,
                count: 2,
            },
        },
    );
    response_round_trips(
        &[
            0x59, 0x02, 0xFF, 0x12, 0x34, 0x56, 0x09, 0xAB, 0xCD, 0xEF, 0x08,
        ],
        Response::ReadDtcInformation {
            report: DtcResponse::ByStatusMask {
                availability_mask: 0xFF,
                dtcs: vec![
                    DtcStatus {
                        dtc: 0x12_3456,
                        status: 0x09,
                    },
                    DtcStatus {
                        dtc: 0xAB_CDEF,
                        status: 0x08,
                    },
                ],
            },
        },
    );
    response_round_trips(
        &[0x59, 0x0A, 0xFF],
        Response::ReadDtcInformation {
            report: DtcResponse::SupportedDtcs {
                availability_mask: 0xFF,
                dtcs: vec![],
            },
        },
    );
    response_round_trips(
        &[0x59, 0x04, 0x12, 0x34, 0x56, 0x09, 0x01],
        Response::ReadDtcInformation {
            report: DtcResponse::Other {
                report_type: 0x04,
                data: vec![0x12, 0x34, 0x56, 0x09, 0x01],
            },
        },
    );
}

#[test]
fn a_dtc_record_list_must_be_whole_records() {
    assert_eq!(
        Response::decode(&[0x59, 0x02, 0xFF, 0x12, 0x34]),
        Err(DecodeError::Length(0x59))
    );
}

#[test]
fn read_data_by_identifier_takes_several_dids_in_one_request() {
    request_round_trips(
        &[0x22, 0xF1, 0x90, 0xF1, 0x8C],
        Request::ReadDataByIdentifier {
            dids: vec![0xF190, 0xF18C],
        },
    );
    response_round_trips(
        &[0x62, 0xF1, 0x90, b'A', b'B'],
        Response::ReadDataByIdentifier {
            did: 0xF190,
            data: b"AB".to_vec(),
        },
    );
}

#[test]
fn read_data_by_identifier_refuses_no_did_or_half_a_did() {
    assert_eq!(Request::decode(&[0x22]), Err(DecodeError::Length(0x22)));
    assert_eq!(
        Request::decode(&[0x22, 0xF1, 0x90, 0xF1]),
        Err(DecodeError::Length(0x22))
    );
}

#[test]
fn the_address_and_length_format_identifier_sets_each_fields_width() {
    request_round_trips(
        &[0x23, 0x24, 0x00, 0x00, 0x10, 0x00, 0x00, 0x40],
        Request::ReadMemoryByAddress {
            range: MemoryRange::new(0x1000, 4, 0x40, 2).unwrap(),
        },
    );
    response_round_trips(
        &[0x63, 0xDE, 0xAD],
        Response::ReadMemoryByAddress {
            data: vec![0xDE, 0xAD],
        },
    );
}

#[test]
fn a_zero_or_over_eight_byte_width_is_refused() {
    assert_eq!(
        Request::decode(&[0x23, 0x10, 0x00]),
        Err(DecodeError::Format(0x23))
    );
    assert_eq!(
        Request::decode(&[0x23, 0x91, 0x00]),
        Err(DecodeError::Format(0x23))
    );
}

#[test]
fn security_access_round_trips_seed_and_key() {
    request_round_trips(
        &[0x27, 0x01],
        Request::SecurityAccess {
            sub_function: SubFunction::new(0x01),
            data: vec![],
        },
    );
    request_round_trips(
        &[0x27, 0x02, 0x11, 0x22],
        Request::SecurityAccess {
            sub_function: SubFunction::new(0x02),
            data: vec![0x11, 0x22],
        },
    );
    response_round_trips(
        &[0x67, 0x01, 0xA5, 0x5A],
        Response::SecurityAccess {
            sub_function: 0x01,
            data: vec![0xA5, 0x5A],
        },
    );
}

#[test]
fn communication_control_carries_a_node_id_only_when_present() {
    request_round_trips(
        &[0x28, 0x03, 0x01],
        Request::CommunicationControl {
            sub_function: SubFunction::new(0x03),
            communication_type: 0x01,
            node: None,
        },
    );
    request_round_trips(
        &[0x28, 0x04, 0x01, 0x00, 0x0A],
        Request::CommunicationControl {
            sub_function: SubFunction::new(0x04),
            communication_type: 0x01,
            node: Some(0x000A),
        },
    );
    response_round_trips(
        &[0x68, 0x03],
        Response::CommunicationControl { control_type: 0x03 },
    );
}

#[test]
fn write_data_by_identifier_needs_data() {
    request_round_trips(
        &[0x2E, 0xF1, 0x90, 0x01],
        Request::WriteDataByIdentifier {
            did: 0xF190,
            data: vec![0x01],
        },
    );
    assert_eq!(
        Request::decode(&[0x2E, 0xF1, 0x90]),
        Err(DecodeError::Length(0x2E))
    );
    response_round_trips(
        &[0x6E, 0xF1, 0x90],
        Response::WriteDataByIdentifier { did: 0xF190 },
    );
}

#[test]
fn input_output_control_round_trips() {
    request_round_trips(
        &[0x2F, 0x01, 0x23, 0x03, 0x7F],
        Request::InputOutputControlByIdentifier {
            did: 0x0123,
            data: vec![0x03, 0x7F],
        },
    );
    response_round_trips(
        &[0x6F, 0x01, 0x23, 0x03, 0x7F],
        Response::InputOutputControlByIdentifier {
            did: 0x0123,
            data: vec![0x03, 0x7F],
        },
    );
}

#[test]
fn routine_control_round_trips() {
    request_round_trips(
        &[0x31, 0x01, 0x02, 0x03, 0xAA],
        Request::RoutineControl {
            sub_function: SubFunction::new(0x01),
            routine: 0x0203,
            data: vec![0xAA],
        },
    );
    response_round_trips(
        &[0x71, 0x03, 0x02, 0x03, 0x00],
        Response::RoutineControl {
            sub_function: 0x03,
            routine: 0x0203,
            data: vec![0x00],
        },
    );
}

#[test]
fn request_download_and_upload_round_trip() {
    let range = MemoryRange::new(0x0800_0000, 4, 0x1_0000, 3).unwrap();
    request_round_trips(
        &[0x34, 0x00, 0x34, 0x08, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00],
        Request::RequestDownload {
            data_format: 0x00,
            range,
        },
    );
    request_round_trips(
        &[0x35, 0x11, 0x34, 0x08, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00],
        Request::RequestUpload {
            data_format: 0x11,
            range,
        },
    );
    response_round_trips(
        &[0x74, 0x20, 0x0F, 0xFF],
        Response::RequestDownload {
            max_block_length: BlockLength::new(0x0FFF, 2).unwrap(),
        },
    );
    response_round_trips(
        &[0x75, 0x10, 0x82],
        Response::RequestUpload {
            max_block_length: BlockLength::new(0x82, 1).unwrap(),
        },
    );
}

#[test]
fn a_memory_range_or_block_length_cannot_hold_a_width_or_value_it_cannot_encode() {
    assert_eq!(MemoryRange::new(0x1_0000, 2, 0x10, 1), Err(InvalidWidth));
    assert_eq!(MemoryRange::new(0x10, 0, 0x10, 1), Err(InvalidWidth));
    assert_eq!(MemoryRange::new(0x10, 9, 0x10, 1), Err(InvalidWidth));
    assert_eq!(MemoryRange::new(0x10, 1, 0x100, 1), Err(InvalidWidth));
    assert!(MemoryRange::new(u64::MAX, 8, 0xFF, 1).is_ok());
    assert_eq!(BlockLength::new(0x100, 1), Err(InvalidWidth));
    assert_eq!(BlockLength::new(1, 0), Err(InvalidWidth));
    let range: Result<MemoryRange, _> =
        serde_json::from_str(r#"{"address":65536,"addressWidth":2,"size":16,"sizeWidth":1}"#);
    assert!(range.is_err());
    let length: Result<BlockLength, _> = serde_json::from_str(r#"{"value":256,"width":1}"#);
    assert!(length.is_err());
}

#[test]
fn a_sub_function_cannot_hold_a_value_over_0x7f() {
    assert_eq!(SubFunction::new(0x83).value(), 0x03);
    assert!(!SubFunction::new(0x83).suppress_positive_response());
    assert_eq!(SubFunction::suppressed(0x83).byte(), 0x83);
    let parsed: Result<SubFunction, _> =
        serde_json::from_str(r#"{"value":131,"suppressPositiveResponse":false}"#);
    assert!(parsed.is_err());
    let parsed: SubFunction =
        serde_json::from_str(r#"{"value":3,"suppressPositiveResponse":true}"#).unwrap();
    assert_eq!(parsed.byte(), 0x83);
}

#[test]
fn fields_and_variants_serialise_camel_case() {
    let request = Request::RoutineControl {
        sub_function: SubFunction::suppressed(0x01),
        routine: 0xFF00,
        data: vec![],
    };
    let json = serde_json::json!({
        "kind": "routineControl",
        "subFunction": { "value": 1, "suppressPositiveResponse": true },
        "routine": 0xFF00,
        "data": [],
    });
    assert_eq!(serde_json::to_value(&request).unwrap(), json);
    assert_eq!(serde_json::from_value::<Request>(json).unwrap(), request);

    let response = Response::RequestDownload {
        max_block_length: BlockLength::new(0x0FFF, 2).unwrap(),
    };
    let json = serde_json::json!({
        "kind": "requestDownload",
        "maxBlockLength": { "value": 0x0FFF, "width": 2 },
    });
    assert_eq!(serde_json::to_value(&response).unwrap(), json);
    assert_eq!(serde_json::from_value::<Response>(json).unwrap(), response);
}

#[test]
fn the_suppress_bit_is_recognised_for_every_iso_service_with_a_sub_function() {
    assert!(
        Request::decode(&[0x29, 0x81])
            .unwrap()
            .suppress_positive_response()
    );
    assert!(
        Request::decode(&[0x86, 0x80])
            .unwrap()
            .suppress_positive_response()
    );
    assert!(
        !Request::decode(&[0x2A, 0x81, 0x01])
            .unwrap()
            .suppress_positive_response()
    );
    assert!(
        !Request::decode(&[0xBA, 0x81])
            .unwrap()
            .suppress_positive_response()
    );
    for service in sid::iso() {
        let suppressed = Request::Other {
            service,
            data: vec![0x81],
        };
        assert_eq!(
            suppressed.suppress_positive_response(),
            sid::has_sub_function(service),
            "0x{service:02X}"
        );
    }
}

#[test]
fn a_block_length_format_with_its_reserved_nibble_set_is_refused() {
    assert_eq!(
        Response::decode(&[0x74, 0x21, 0x0F, 0xFF]),
        Err(DecodeError::Format(0x74))
    );
}

#[test]
fn transfer_data_and_exit_round_trip() {
    request_round_trips(
        &[0x36, 0x01, 0xDE, 0xAD],
        Request::TransferData {
            sequence: 0x01,
            data: vec![0xDE, 0xAD],
        },
    );
    response_round_trips(
        &[0x76, 0x01],
        Response::TransferData {
            sequence: 0x01,
            data: vec![],
        },
    );
    request_round_trips(&[0x37], Request::RequestTransferExit { data: vec![] });
    response_round_trips(
        &[0x77, 0x12, 0x34],
        Response::RequestTransferExit {
            data: vec![0x12, 0x34],
        },
    );
}

#[test]
fn tester_present_round_trips_with_and_without_suppression() {
    request_round_trips(
        &[0x3E, 0x80],
        Request::TesterPresent {
            sub_function: SubFunction::suppressed(0x00),
        },
    );
    response_round_trips(&[0x7E, 0x00], Response::TesterPresent { sub_function: 0 });
}

#[test]
fn control_dtc_setting_round_trips() {
    request_round_trips(
        &[0x85, 0x02],
        Request::ControlDtcSetting {
            sub_function: SubFunction::new(0x02),
            data: vec![],
        },
    );
    response_round_trips(&[0xC5, 0x02], Response::ControlDtcSetting { setting: 0x02 });
}

#[test]
fn any_other_service_is_kept_byte_for_byte() {
    request_round_trips(
        &[0x3D, 0x14, 0x10, 0x01, 0xFF],
        Request::Other {
            service: 0x3D,
            data: vec![0x14, 0x10, 0x01, 0xFF],
        },
    );
    request_round_trips(
        &[0xBA, 0x01],
        Request::Other {
            service: 0xBA,
            data: vec![0x01],
        },
    );
    let vendor = Response::decode(&[0xFA, 0x01]).unwrap();
    assert_eq!(
        vendor,
        Response::Other {
            service: 0xFA,
            data: vec![0x01]
        }
    );
    assert_eq!(vendor.answers(), 0xBA);
    assert_eq!(vendor.encode(), [0xFA, 0x01]);
}

#[test]
fn a_negative_response_is_three_bytes() {
    response_round_trips(
        &[0x7F, 0x22, 0x31],
        Response::Negative {
            service: 0x22,
            code: Nrc::REQUEST_OUT_OF_RANGE,
        },
    );
    assert_eq!(
        Response::decode(&[0x7F, 0x22]),
        Err(DecodeError::Length(0x7F))
    );
    assert_eq!(
        Response::decode(&[0x7F, 0x22, 0x31, 0x00]),
        Err(DecodeError::Length(0x7F))
    );
}

#[test]
fn response_pending_is_a_negative_response_with_code_0x78() {
    let pending = Response::decode(&[0x7F, 0x31, 0x78]).unwrap();
    assert!(pending.is_pending());
    assert_eq!(pending.answers(), 0x31);
    assert!(!Response::decode(&[0x7F, 0x31, 0x31]).unwrap().is_pending());
}

#[test]
fn trailing_bytes_after_a_fixed_layout_are_refused() {
    assert_eq!(
        Request::decode(&[0x10, 0x03, 0x00]),
        Err(DecodeError::Length(0x10))
    );
    assert_eq!(Request::decode(&[0x10]), Err(DecodeError::Length(0x10)));
    assert_eq!(Request::decode(&[]), Err(DecodeError::Empty));
    assert_eq!(Response::decode(&[]), Err(DecodeError::Empty));
}

#[test]
fn a_response_names_the_service_it_answers() {
    assert_eq!(Response::decode(&[0x50, 0x01]).unwrap().answers(), 0x10);
    assert_eq!(Response::decode(&[0xC5, 0x01]).unwrap().answers(), 0x85);
    assert_eq!(
        Response::decode(&[0x7F, 0x2E, 0x33]).unwrap().answers(),
        0x2E
    );
}

fn assert_round_trips_or_refuses(message: &[u8]) {
    if let Ok(request) = Request::decode(message) {
        assert_eq!(request.encode(), message, "request {message:02X?}");
    }
    if let Ok(response) = Response::decode(message) {
        assert_eq!(response.encode(), message, "response {message:02X?}");
    }
}

#[test]
fn every_two_byte_message_decodes_without_panic_and_re_encodes_exactly() {
    assert_round_trips_or_refuses(&[]);
    for first in 0..=u8::MAX {
        assert_round_trips_or_refuses(&[first]);
        for second in 0..=u8::MAX {
            assert_round_trips_or_refuses(&[first, second]);
        }
    }
}

#[test]
fn every_three_byte_message_of_a_modelled_service_re_encodes_exactly() {
    let modelled = [
        0x10u8, 0x11, 0x14, 0x19, 0x22, 0x23, 0x27, 0x28, 0x2E, 0x2F, 0x31, 0x34, 0x35, 0x36, 0x37,
        0x3E, 0x85,
    ];
    for service in modelled {
        for first in [service, service + 0x40, 0x7F] {
            for a in 0..=u8::MAX {
                for b in 0..=u8::MAX {
                    assert_round_trips_or_refuses(&[first, a, b]);
                }
            }
        }
    }
}

#[test]
fn arbitrary_messages_decode_without_panic_and_re_encode_exactly() {
    let mut state = 0x9E37_79B9_7F4A_7C15u64;
    let mut next = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    let firsts = [
        0x10u8, 0x11, 0x14, 0x19, 0x22, 0x23, 0x27, 0x28, 0x2E, 0x2F, 0x31, 0x34, 0x35, 0x36, 0x37,
        0x3E, 0x85, 0x50, 0x51, 0x54, 0x59, 0x62, 0x63, 0x67, 0x68, 0x6E, 0x6F, 0x71, 0x74, 0x75,
        0x76, 0x77, 0x7E, 0xC5, 0x7F,
    ];
    for _ in 0..200_000 {
        let r = next();
        let len = (r % 24) as usize;
        let mut message: Vec<u8> = (0..len).map(|_| next() as u8).collect();
        if let Some(first) = message.first_mut()
            && r & 0x100 != 0
        {
            *first = firsts[(r >> 16) as usize % firsts.len()];
        }
        if len > 1 && r & 0x200 != 0 {
            message[1] =
                [0x01, 0x02, 0x04, 0x06, 0x0A, 0x12, 0x24, 0x44, 0x88][(r >> 24) as usize % 9];
        }
        assert_round_trips_or_refuses(&message);
    }
}
