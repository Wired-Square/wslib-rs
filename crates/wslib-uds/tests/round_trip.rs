use wslib_uds::{
    BlockLength, Dtc, DtcRequest, DtcResponse, DtcStatus, MemoryRange, Nrc, OtherReportType,
    Request, Response, SessionTiming, SubFunction,
};

/// xorshift64: the same values every run.
struct Values(u64);

impl Values {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }

    fn u8(&mut self) -> u8 {
        self.next() as u8
    }

    fn u16(&mut self) -> u16 {
        self.next() as u16
    }

    fn flag(&mut self) -> bool {
        self.next() & 1 == 1
    }

    fn maybe<T>(&mut self, make: impl FnOnce(&mut Self) -> T) -> Option<T> {
        self.flag().then(|| make(self))
    }

    fn bytes(&mut self, at_least: u64) -> Vec<u8> {
        (0..at_least + self.below(6)).map(|_| self.u8()).collect()
    }

    fn width(&mut self) -> u8 {
        1 + self.below(8) as u8
    }

    fn fitting(&mut self, width: u8) -> u64 {
        self.next() >> (64 - 8 * u32::from(width))
    }

    fn sub_function(&mut self) -> SubFunction {
        SubFunction::from_byte(self.u8())
    }

    fn dtc(&mut self) -> Dtc {
        Dtc::new(self.next() as u32 & 0xFF_FFFF).unwrap()
    }

    fn range(&mut self) -> MemoryRange {
        let (address_width, size_width) = (self.width(), self.width());
        let address = self.fitting(address_width);
        MemoryRange::new(address, address_width, self.fitting(size_width), size_width).unwrap()
    }

    fn block_length(&mut self) -> BlockLength {
        let width = self.width();
        BlockLength::new(self.fitting(width), width).unwrap()
    }

    fn dtcs(&mut self) -> Vec<DtcStatus> {
        (0..self.below(4))
            .map(|_| DtcStatus {
                dtc: self.dtc(),
                status: self.u8(),
            })
            .collect()
    }

    fn other_report_type(&mut self) -> OtherReportType {
        loop {
            if let Ok(report_type) = OtherReportType::new(self.u8()) {
                return report_type;
            }
        }
    }

    fn dtc_request(&mut self) -> DtcRequest {
        match self.below(6) {
            0 => DtcRequest::NumberByStatusMask {
                status_mask: self.u8(),
            },
            1 => DtcRequest::ByStatusMask {
                status_mask: self.u8(),
            },
            2 => DtcRequest::SnapshotRecordByDtc {
                dtc: self.dtc(),
                record: self.u8(),
            },
            3 => DtcRequest::ExtendedDataRecordByDtc {
                dtc: self.dtc(),
                record: self.u8(),
            },
            4 => DtcRequest::SupportedDtcs,
            _ => DtcRequest::Other {
                report_type: self.other_report_type(),
                data: self.bytes(0),
            },
        }
    }

    fn request(&mut self) -> Request {
        match self.below(17) {
            0 => Request::DiagnosticSessionControl {
                sub_function: self.sub_function(),
            },
            1 => Request::EcuReset {
                sub_function: self.sub_function(),
            },
            2 => Request::ClearDiagnosticInformation {
                group: self.dtc(),
                memory_selection: self.maybe(Self::u8),
            },
            3 => Request::ReadDtcInformation {
                report: self.dtc_request(),
                suppress_positive_response: self.flag(),
            },
            4 => Request::ReadDataByIdentifier {
                dids: (0..1 + self.below(4)).map(|_| self.u16()).collect(),
            },
            5 => Request::ReadMemoryByAddress {
                range: self.range(),
            },
            6 => Request::SecurityAccess {
                sub_function: self.sub_function(),
                data: self.bytes(0),
            },
            7 => Request::CommunicationControl {
                sub_function: self.sub_function(),
                communication_type: self.u8(),
                node: self.maybe(Self::u16),
            },
            8 => Request::WriteDataByIdentifier {
                did: self.u16(),
                data: self.bytes(1),
            },
            9 => Request::InputOutputControlByIdentifier {
                did: self.u16(),
                data: self.bytes(1),
            },
            10 => Request::RoutineControl {
                sub_function: self.sub_function(),
                routine: self.u16(),
                data: self.bytes(0),
            },
            11 => Request::RequestDownload {
                data_format: self.u8(),
                range: self.range(),
            },
            12 => Request::RequestUpload {
                data_format: self.u8(),
                range: self.range(),
            },
            13 => Request::TransferData {
                sequence: self.u8(),
                data: self.bytes(0),
            },
            14 => Request::RequestTransferExit {
                data: self.bytes(0),
            },
            15 => Request::TesterPresent {
                sub_function: self.sub_function(),
            },
            _ => Request::ControlDtcSetting {
                sub_function: self.sub_function(),
                data: self.bytes(0),
            },
        }
    }

    fn dtc_response(&mut self) -> DtcResponse {
        match self.below(4) {
            0 => DtcResponse::NumberByStatusMask {
                availability_mask: self.u8(),
                format: self.u8(),
                count: self.u16(),
            },
            1 => DtcResponse::ByStatusMask {
                availability_mask: self.u8(),
                dtcs: self.dtcs(),
            },
            2 => DtcResponse::SupportedDtcs {
                availability_mask: self.u8(),
                dtcs: self.dtcs(),
            },
            _ => DtcResponse::Other {
                report_type: [0x04, 0x06, 0x42][self.below(3) as usize],
                data: self.bytes(0),
            },
        }
    }

    fn response(&mut self) -> Response {
        match self.below(18) {
            0 => Response::Negative {
                service: self.u8(),
                code: Nrc(self.u8()),
            },
            1 => Response::DiagnosticSessionControl {
                session: self.u8(),
                timing: self.maybe(|v| SessionTiming {
                    p2_server_max_ms: v.u16(),
                    p2_star_server_max_10ms: v.u16(),
                }),
            },
            2 => Response::EcuReset {
                reset_type: self.u8(),
                power_down_time: self.maybe(Self::u8),
            },
            3 => Response::ClearDiagnosticInformation,
            4 => Response::ReadDtcInformation {
                report: self.dtc_response(),
            },
            5 => Response::ReadDataByIdentifier {
                did: self.u16(),
                data: self.bytes(0),
            },
            6 => Response::ReadMemoryByAddress {
                data: self.bytes(0),
            },
            7 => Response::SecurityAccess {
                sub_function: self.u8(),
                data: self.bytes(0),
            },
            8 => Response::CommunicationControl {
                control_type: self.u8(),
            },
            9 => Response::WriteDataByIdentifier { did: self.u16() },
            10 => Response::InputOutputControlByIdentifier {
                did: self.u16(),
                data: self.bytes(0),
            },
            11 => Response::RoutineControl {
                sub_function: self.u8(),
                routine: self.u16(),
                data: self.bytes(0),
            },
            12 => Response::RequestDownload {
                max_block_length: self.block_length(),
            },
            13 => Response::RequestUpload {
                max_block_length: self.block_length(),
            },
            14 => Response::TransferData {
                sequence: self.u8(),
                data: self.bytes(0),
            },
            15 => Response::RequestTransferExit {
                data: self.bytes(0),
            },
            16 => Response::TesterPresent {
                sub_function: self.u8(),
            },
            _ => Response::ControlDtcSetting { setting: self.u8() },
        }
    }
}

#[test]
fn every_typed_request_and_response_decodes_back_from_its_encoding() {
    let mut values = Values(0x9E37_79B9_7F4A_7C15);
    for _ in 0..5_000 {
        let request = values.request();
        assert_eq!(Request::decode(&request.encode()), Ok(request));
        let response = values.response();
        assert_eq!(Response::decode(&response.encode()), Ok(response));
    }
}
