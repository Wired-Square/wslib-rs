use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::answer::suppresses_positive_response;
use crate::{Nrc, Safety, sid};

pub const DEFAULT_SESSION: u8 = 0x01;
pub const PROGRAMMING_SESSION: u8 = 0x02;
pub const EXTENDED_SESSION: u8 = 0x03;

const SUPPRESS_POSITIVE_RESPONSE: u8 = 0x80;

/// Why a message is not a well-formed UDS message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DecodeError {
    #[error("empty message")]
    Empty,
    #[error("service 0x{0:02X}: wrong length")]
    Length(u8),
    #[error("service 0x{0:02X}: a length format outside 1 to 8 bytes, or a reserved bit set")]
    Format(u8),
}

/// A sub-function byte: a value of at most 0x7F and the
/// suppress-positive-response bit apart.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(rename = "UdsSubFunction"))]
#[serde(try_from = "SubFunctionFields", rename_all = "camelCase")]
pub struct SubFunction {
    value: u8,
    suppress_positive_response: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SubFunctionFields {
    value: u8,
    suppress_positive_response: bool,
}

impl TryFrom<SubFunctionFields> for SubFunction {
    type Error = &'static str;

    fn try_from(fields: SubFunctionFields) -> Result<Self, Self::Error> {
        if fields.value & SUPPRESS_POSITIVE_RESPONSE != 0 {
            return Err("a sub-function value over 0x7F");
        }
        Ok(Self {
            value: fields.value,
            suppress_positive_response: fields.suppress_positive_response,
        })
    }
}

impl SubFunction {
    /// `value`'s top bit is dropped.
    pub const fn new(value: u8) -> Self {
        Self::from_byte(value & !SUPPRESS_POSITIVE_RESPONSE)
    }

    /// `value`'s top bit is dropped.
    pub const fn suppressed(value: u8) -> Self {
        Self::from_byte(value | SUPPRESS_POSITIVE_RESPONSE)
    }

    pub const fn from_byte(byte: u8) -> Self {
        Self {
            value: byte & !SUPPRESS_POSITIVE_RESPONSE,
            suppress_positive_response: byte & SUPPRESS_POSITIVE_RESPONSE != 0,
        }
    }

    pub const fn value(self) -> u8 {
        self.value
    }

    pub const fn suppress_positive_response(self) -> bool {
        self.suppress_positive_response
    }

    pub const fn byte(self) -> u8 {
        if self.suppress_positive_response {
            self.value | SUPPRESS_POSITIVE_RESPONSE
        } else {
            self.value
        }
    }
}

/// A width outside 1 to 8 bytes, or a value that does not fit its width.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("a width outside 1 to 8 bytes, or a value wider than its width")]
pub struct InvalidWidth;

fn fits(value: u64, width: u8) -> bool {
    (1..=8).contains(&width) && (width == 8 || value >> (8 * u32::from(width)) == 0)
}

/// An address and a size, each big-endian over 1 to 8 bytes, as an
/// addressAndLengthFormatIdentifier lays them out.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(rename = "UdsMemoryRange"))]
#[serde(try_from = "MemoryRangeFields", rename_all = "camelCase")]
pub struct MemoryRange {
    address: u64,
    address_width: u8,
    size: u64,
    size_width: u8,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct MemoryRangeFields {
    address: u64,
    address_width: u8,
    size: u64,
    size_width: u8,
}

impl TryFrom<MemoryRangeFields> for MemoryRange {
    type Error = InvalidWidth;

    fn try_from(f: MemoryRangeFields) -> Result<Self, InvalidWidth> {
        Self::new(f.address, f.address_width, f.size, f.size_width)
    }
}

impl MemoryRange {
    pub fn new(
        address: u64,
        address_width: u8,
        size: u64,
        size_width: u8,
    ) -> Result<Self, InvalidWidth> {
        if !fits(address, address_width) || !fits(size, size_width) {
            return Err(InvalidWidth);
        }
        Ok(Self {
            address,
            address_width,
            size,
            size_width,
        })
    }

    pub fn address(&self) -> u64 {
        self.address
    }

    pub fn address_width(&self) -> u8 {
        self.address_width
    }

    pub fn size(&self) -> u64 {
        self.size
    }

    pub fn size_width(&self) -> u8 {
        self.size_width
    }

    pub(crate) fn read(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let format = r.u8()?;
        let (size_width, address_width) = (format >> 4, format & 0x0F);
        if !(1..=8).contains(&size_width) || !(1..=8).contains(&address_width) {
            return Err(DecodeError::Format(r.service));
        }
        Ok(Self {
            address: r.uint(address_width)?,
            address_width,
            size: r.uint(size_width)?,
            size_width,
        })
    }

    fn write(&self, out: &mut Vec<u8>) {
        out.push(self.size_width << 4 | self.address_width);
        put_uint(out, self.address, self.address_width);
        put_uint(out, self.size, self.size_width);
    }
}

/// A RequestDownload or RequestUpload response's maxNumberOfBlockLength and
/// its width of 1 to 8 bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(rename = "UdsBlockLength"))]
#[serde(try_from = "BlockLengthFields", rename_all = "camelCase")]
pub struct BlockLength {
    value: u64,
    width: u8,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct BlockLengthFields {
    value: u64,
    width: u8,
}

impl TryFrom<BlockLengthFields> for BlockLength {
    type Error = InvalidWidth;

    fn try_from(f: BlockLengthFields) -> Result<Self, InvalidWidth> {
        Self::new(f.value, f.width)
    }
}

impl BlockLength {
    pub fn new(value: u64, width: u8) -> Result<Self, InvalidWidth> {
        if !fits(value, width) {
            return Err(InvalidWidth);
        }
        Ok(Self { value, width })
    }

    pub fn value(&self) -> u64 {
        self.value
    }

    pub fn width(&self) -> u8 {
        self.width
    }
}

/// The P2 and P2* a server reports in its positive session-control response.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(rename = "UdsSessionTiming"))]
#[serde(rename_all = "camelCase")]
pub struct SessionTiming {
    pub p2_server_max_ms: u16,
    pub p2_star_server_max_10ms: u16,
}

impl SessionTiming {
    pub fn p2(self) -> Duration {
        Duration::from_millis(self.p2_server_max_ms.into())
    }

    pub fn p2_star(self) -> Duration {
        Duration::from_millis(u64::from(self.p2_star_server_max_10ms) * 10)
    }
}

/// A DTC and its status byte; the DTC is the low 24 bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(rename = "UdsDtcStatus"))]
#[serde(rename_all = "camelCase")]
pub struct DtcStatus {
    pub dtc: u32,
    pub status: u8,
}

/// A ReadDTCInformation request by its report type; the common ones typed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(rename = "UdsDtcRequest"))]
#[serde(tag = "kind", rename_all = "camelCase")]
#[serde(rename_all_fields = "camelCase")]
pub enum DtcRequest {
    NumberByStatusMask { status_mask: u8 },
    ByStatusMask { status_mask: u8 },
    SnapshotRecordByDtc { dtc: u32, record: u8 },
    ExtendedDataRecordByDtc { dtc: u32, record: u8 },
    SupportedDtcs,
    Other { report_type: u8, data: Vec<u8> },
}

impl DtcRequest {
    pub fn report_type(&self) -> u8 {
        match self {
            Self::NumberByStatusMask { .. } => 0x01,
            Self::ByStatusMask { .. } => 0x02,
            Self::SnapshotRecordByDtc { .. } => 0x04,
            Self::ExtendedDataRecordByDtc { .. } => 0x06,
            Self::SupportedDtcs => 0x0A,
            Self::Other { report_type, .. } => *report_type,
        }
    }

    fn read(report_type: u8, r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        Ok(match report_type {
            0x01 => Self::NumberByStatusMask {
                status_mask: r.u8()?,
            },
            0x02 => Self::ByStatusMask {
                status_mask: r.u8()?,
            },
            0x04 => Self::SnapshotRecordByDtc {
                dtc: r.u24()?,
                record: r.u8()?,
            },
            0x06 => Self::ExtendedDataRecordByDtc {
                dtc: r.u24()?,
                record: r.u8()?,
            },
            0x0A => Self::SupportedDtcs,
            _ => Self::Other {
                report_type,
                data: r.rest(),
            },
        })
    }

    fn write(&self, out: &mut Vec<u8>) {
        match self {
            Self::NumberByStatusMask { status_mask } | Self::ByStatusMask { status_mask } => {
                out.push(*status_mask)
            }
            Self::SnapshotRecordByDtc { dtc, record }
            | Self::ExtendedDataRecordByDtc { dtc, record } => {
                put_uint(out, (*dtc).into(), 3);
                out.push(*record);
            }
            Self::SupportedDtcs => {}
            Self::Other { data, .. } => out.extend(data),
        }
    }
}

/// A ReadDTCInformation positive response by its report type; the common ones typed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(rename = "UdsDtcResponse"))]
#[serde(tag = "kind", rename_all = "camelCase")]
#[serde(rename_all_fields = "camelCase")]
pub enum DtcResponse {
    NumberByStatusMask {
        availability_mask: u8,
        format: u8,
        count: u16,
    },
    ByStatusMask {
        availability_mask: u8,
        dtcs: Vec<DtcStatus>,
    },
    SupportedDtcs {
        availability_mask: u8,
        dtcs: Vec<DtcStatus>,
    },
    Other {
        report_type: u8,
        data: Vec<u8>,
    },
}

impl DtcResponse {
    pub fn report_type(&self) -> u8 {
        match self {
            Self::NumberByStatusMask { .. } => 0x01,
            Self::ByStatusMask { .. } => 0x02,
            Self::SupportedDtcs { .. } => 0x0A,
            Self::Other { report_type, .. } => *report_type,
        }
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let report_type = r.u8()?;
        Ok(match report_type {
            0x01 => Self::NumberByStatusMask {
                availability_mask: r.u8()?,
                format: r.u8()?,
                count: r.u16()?,
            },
            0x02 => Self::ByStatusMask {
                availability_mask: r.u8()?,
                dtcs: r.dtcs()?,
            },
            0x0A => Self::SupportedDtcs {
                availability_mask: r.u8()?,
                dtcs: r.dtcs()?,
            },
            _ => Self::Other {
                report_type,
                data: r.rest(),
            },
        })
    }

    fn write(&self, out: &mut Vec<u8>) {
        out.push(self.report_type());
        match self {
            Self::NumberByStatusMask {
                availability_mask,
                format,
                count,
            } => {
                out.extend([*availability_mask, *format]);
                out.extend(count.to_be_bytes());
            }
            Self::ByStatusMask {
                availability_mask,
                dtcs,
            }
            | Self::SupportedDtcs {
                availability_mask,
                dtcs,
            } => {
                out.push(*availability_mask);
                for d in dtcs {
                    put_uint(out, d.dtc.into(), 3);
                    out.push(d.status);
                }
            }
            Self::Other { data, .. } => out.extend(data),
        }
    }
}

/// A request, typed for the services this crate models and opaque for the rest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(rename = "UdsRequest"))]
#[serde(tag = "kind", rename_all = "camelCase")]
#[serde(rename_all_fields = "camelCase")]
pub enum Request {
    DiagnosticSessionControl {
        sub_function: SubFunction,
    },
    EcuReset {
        sub_function: SubFunction,
    },
    ClearDiagnosticInformation {
        group: u32,
        memory_selection: Option<u8>,
    },
    ReadDtcInformation {
        report: DtcRequest,
        suppress_positive_response: bool,
    },
    ReadDataByIdentifier {
        dids: Vec<u16>,
    },
    ReadMemoryByAddress {
        range: MemoryRange,
    },
    SecurityAccess {
        sub_function: SubFunction,
        data: Vec<u8>,
    },
    CommunicationControl {
        sub_function: SubFunction,
        communication_type: u8,
        node: Option<u16>,
    },
    WriteDataByIdentifier {
        did: u16,
        data: Vec<u8>,
    },
    InputOutputControlByIdentifier {
        did: u16,
        data: Vec<u8>,
    },
    RoutineControl {
        sub_function: SubFunction,
        routine: u16,
        data: Vec<u8>,
    },
    RequestDownload {
        data_format: u8,
        range: MemoryRange,
    },
    RequestUpload {
        data_format: u8,
        range: MemoryRange,
    },
    TransferData {
        sequence: u8,
        data: Vec<u8>,
    },
    RequestTransferExit {
        data: Vec<u8>,
    },
    TesterPresent {
        sub_function: SubFunction,
    },
    ControlDtcSetting {
        sub_function: SubFunction,
        data: Vec<u8>,
    },
    Other {
        service: u8,
        data: Vec<u8>,
    },
}

impl Request {
    pub fn decode(message: &[u8]) -> Result<Self, DecodeError> {
        let (&service, rest) = message.split_first().ok_or(DecodeError::Empty)?;
        let mut r = Reader { service, rest };
        let request = match service {
            sid::DIAGNOSTIC_SESSION_CONTROL => Self::DiagnosticSessionControl {
                sub_function: r.sub_function()?,
            },
            sid::ECU_RESET => Self::EcuReset {
                sub_function: r.sub_function()?,
            },
            sid::CLEAR_DIAGNOSTIC_INFORMATION => Self::ClearDiagnosticInformation {
                group: r.u24()?,
                memory_selection: r.optional(1)?.map(|b| b[0]),
            },
            sid::READ_DTC_INFORMATION => {
                let sub = r.sub_function()?;
                Self::ReadDtcInformation {
                    report: DtcRequest::read(sub.value, &mut r)?,
                    suppress_positive_response: sub.suppress_positive_response,
                }
            }
            sid::READ_DATA_BY_IDENTIFIER => {
                let (dids, []) = std::mem::take(&mut r.rest).as_chunks::<2>() else {
                    return Err(DecodeError::Length(service));
                };
                if dids.is_empty() {
                    return Err(DecodeError::Length(service));
                }
                Self::ReadDataByIdentifier {
                    dids: dids.iter().map(|d| u16::from_be_bytes(*d)).collect(),
                }
            }
            sid::READ_MEMORY_BY_ADDRESS => Self::ReadMemoryByAddress {
                range: MemoryRange::read(&mut r)?,
            },
            sid::SECURITY_ACCESS => Self::SecurityAccess {
                sub_function: r.sub_function()?,
                data: r.rest(),
            },
            sid::COMMUNICATION_CONTROL => Self::CommunicationControl {
                sub_function: r.sub_function()?,
                communication_type: r.u8()?,
                node: r.optional(2)?.map(|b| u16::from_be_bytes([b[0], b[1]])),
            },
            sid::WRITE_DATA_BY_IDENTIFIER => Self::WriteDataByIdentifier {
                did: r.u16()?,
                data: r.non_empty_rest()?,
            },
            sid::INPUT_OUTPUT_CONTROL_BY_IDENTIFIER => Self::InputOutputControlByIdentifier {
                did: r.u16()?,
                data: r.non_empty_rest()?,
            },
            sid::ROUTINE_CONTROL => Self::RoutineControl {
                sub_function: r.sub_function()?,
                routine: r.u16()?,
                data: r.rest(),
            },
            sid::REQUEST_DOWNLOAD => Self::RequestDownload {
                data_format: r.u8()?,
                range: MemoryRange::read(&mut r)?,
            },
            sid::REQUEST_UPLOAD => Self::RequestUpload {
                data_format: r.u8()?,
                range: MemoryRange::read(&mut r)?,
            },
            sid::TRANSFER_DATA => Self::TransferData {
                sequence: r.u8()?,
                data: r.rest(),
            },
            sid::REQUEST_TRANSFER_EXIT => Self::RequestTransferExit { data: r.rest() },
            sid::TESTER_PRESENT => Self::TesterPresent {
                sub_function: r.sub_function()?,
            },
            sid::CONTROL_DTC_SETTING => Self::ControlDtcSetting {
                sub_function: r.sub_function()?,
                data: r.rest(),
            },
            _ => Self::Other {
                service,
                data: r.rest(),
            },
        };
        r.end()?;
        Ok(request)
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = vec![self.service()];
        match self {
            Self::DiagnosticSessionControl { sub_function }
            | Self::EcuReset { sub_function }
            | Self::TesterPresent { sub_function } => out.push(sub_function.byte()),
            Self::ClearDiagnosticInformation {
                group,
                memory_selection,
            } => {
                put_uint(&mut out, (*group).into(), 3);
                out.extend(memory_selection);
            }
            Self::ReadDtcInformation {
                report,
                suppress_positive_response,
            } => {
                let sub = SubFunction {
                    value: report.report_type(),
                    suppress_positive_response: *suppress_positive_response,
                };
                out.push(sub.byte());
                report.write(&mut out);
            }
            Self::ReadDataByIdentifier { dids } => {
                dids.iter().for_each(|d| out.extend(d.to_be_bytes()))
            }
            Self::ReadMemoryByAddress { range } => range.write(&mut out),
            Self::SecurityAccess { sub_function, data }
            | Self::ControlDtcSetting { sub_function, data } => {
                out.push(sub_function.byte());
                out.extend(data);
            }
            Self::CommunicationControl {
                sub_function,
                communication_type,
                node,
            } => {
                out.extend([sub_function.byte(), *communication_type]);
                if let Some(node) = node {
                    out.extend(node.to_be_bytes());
                }
            }
            Self::WriteDataByIdentifier { did, data }
            | Self::InputOutputControlByIdentifier { did, data } => {
                out.extend(did.to_be_bytes());
                out.extend(data);
            }
            Self::RoutineControl {
                sub_function,
                routine,
                data,
            } => {
                out.push(sub_function.byte());
                out.extend(routine.to_be_bytes());
                out.extend(data);
            }
            Self::RequestDownload { data_format, range }
            | Self::RequestUpload { data_format, range } => {
                out.push(*data_format);
                range.write(&mut out);
            }
            Self::TransferData { sequence, data } => {
                out.push(*sequence);
                out.extend(data);
            }
            Self::RequestTransferExit { data } | Self::Other { data, .. } => out.extend(data),
        }
        out
    }

    pub fn service(&self) -> u8 {
        match self {
            Self::DiagnosticSessionControl { .. } => sid::DIAGNOSTIC_SESSION_CONTROL,
            Self::EcuReset { .. } => sid::ECU_RESET,
            Self::ClearDiagnosticInformation { .. } => sid::CLEAR_DIAGNOSTIC_INFORMATION,
            Self::ReadDtcInformation { .. } => sid::READ_DTC_INFORMATION,
            Self::ReadDataByIdentifier { .. } => sid::READ_DATA_BY_IDENTIFIER,
            Self::ReadMemoryByAddress { .. } => sid::READ_MEMORY_BY_ADDRESS,
            Self::SecurityAccess { .. } => sid::SECURITY_ACCESS,
            Self::CommunicationControl { .. } => sid::COMMUNICATION_CONTROL,
            Self::WriteDataByIdentifier { .. } => sid::WRITE_DATA_BY_IDENTIFIER,
            Self::InputOutputControlByIdentifier { .. } => sid::INPUT_OUTPUT_CONTROL_BY_IDENTIFIER,
            Self::RoutineControl { .. } => sid::ROUTINE_CONTROL,
            Self::RequestDownload { .. } => sid::REQUEST_DOWNLOAD,
            Self::RequestUpload { .. } => sid::REQUEST_UPLOAD,
            Self::TransferData { .. } => sid::TRANSFER_DATA,
            Self::RequestTransferExit { .. } => sid::REQUEST_TRANSFER_EXIT,
            Self::TesterPresent { .. } => sid::TESTER_PRESENT,
            Self::ControlDtcSetting { .. } => sid::CONTROL_DTC_SETTING,
            Self::Other { service, .. } => *service,
        }
    }

    /// Set for any ISO service with a sub-function, modelled or not.
    pub fn suppress_positive_response(&self) -> bool {
        suppresses_positive_response(&self.encode())
    }

    pub fn safety(&self) -> Safety {
        Safety::of(&self.encode())
    }
}

/// A response: negative, typed positive for the services this crate models,
/// or opaque.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(rename = "UdsResponse"))]
#[serde(tag = "kind", rename_all = "camelCase")]
#[serde(rename_all_fields = "camelCase")]
pub enum Response {
    Negative {
        service: u8,
        code: Nrc,
    },
    DiagnosticSessionControl {
        session: u8,
        timing: Option<SessionTiming>,
    },
    EcuReset {
        reset_type: u8,
        power_down_time: Option<u8>,
    },
    ClearDiagnosticInformation,
    ReadDtcInformation {
        report: DtcResponse,
    },
    /// With several DIDs requested, `data` runs on into the later records,
    /// which only the DIDs' lengths can split.
    ReadDataByIdentifier {
        did: u16,
        data: Vec<u8>,
    },
    ReadMemoryByAddress {
        data: Vec<u8>,
    },
    SecurityAccess {
        sub_function: u8,
        data: Vec<u8>,
    },
    CommunicationControl {
        control_type: u8,
    },
    WriteDataByIdentifier {
        did: u16,
    },
    InputOutputControlByIdentifier {
        did: u16,
        data: Vec<u8>,
    },
    RoutineControl {
        sub_function: u8,
        routine: u16,
        data: Vec<u8>,
    },
    RequestDownload {
        max_block_length: BlockLength,
    },
    RequestUpload {
        max_block_length: BlockLength,
    },
    TransferData {
        sequence: u8,
        data: Vec<u8>,
    },
    RequestTransferExit {
        data: Vec<u8>,
    },
    TesterPresent {
        sub_function: u8,
    },
    ControlDtcSetting {
        setting: u8,
    },
    /// `service` is the response's own first byte.
    Other {
        service: u8,
        data: Vec<u8>,
    },
}

impl Response {
    pub fn decode(message: &[u8]) -> Result<Self, DecodeError> {
        let (&first, rest) = message.split_first().ok_or(DecodeError::Empty)?;
        let mut r = Reader {
            service: first,
            rest,
        };
        let response = match first.wrapping_sub(sid::POSITIVE_OFFSET) {
            _ if first == sid::NEGATIVE_RESPONSE => Self::Negative {
                service: r.u8()?,
                code: Nrc(r.u8()?),
            },
            sid::DIAGNOSTIC_SESSION_CONTROL => Self::DiagnosticSessionControl {
                session: r.u8()?,
                timing: r.optional(4)?.map(|b| SessionTiming {
                    p2_server_max_ms: u16::from_be_bytes([b[0], b[1]]),
                    p2_star_server_max_10ms: u16::from_be_bytes([b[2], b[3]]),
                }),
            },
            sid::ECU_RESET => Self::EcuReset {
                reset_type: r.u8()?,
                power_down_time: r.optional(1)?.map(|b| b[0]),
            },
            sid::CLEAR_DIAGNOSTIC_INFORMATION => Self::ClearDiagnosticInformation,
            sid::READ_DTC_INFORMATION => Self::ReadDtcInformation {
                report: DtcResponse::read(&mut r)?,
            },
            sid::READ_DATA_BY_IDENTIFIER => Self::ReadDataByIdentifier {
                did: r.u16()?,
                data: r.rest(),
            },
            sid::READ_MEMORY_BY_ADDRESS => Self::ReadMemoryByAddress { data: r.rest() },
            sid::SECURITY_ACCESS => Self::SecurityAccess {
                sub_function: r.u8()?,
                data: r.rest(),
            },
            sid::COMMUNICATION_CONTROL => Self::CommunicationControl {
                control_type: r.u8()?,
            },
            sid::WRITE_DATA_BY_IDENTIFIER => Self::WriteDataByIdentifier { did: r.u16()? },
            sid::INPUT_OUTPUT_CONTROL_BY_IDENTIFIER => Self::InputOutputControlByIdentifier {
                did: r.u16()?,
                data: r.rest(),
            },
            sid::ROUTINE_CONTROL => Self::RoutineControl {
                sub_function: r.u8()?,
                routine: r.u16()?,
                data: r.rest(),
            },
            sid::REQUEST_DOWNLOAD => Self::RequestDownload {
                max_block_length: r.block_length()?,
            },
            sid::REQUEST_UPLOAD => Self::RequestUpload {
                max_block_length: r.block_length()?,
            },
            sid::TRANSFER_DATA => Self::TransferData {
                sequence: r.u8()?,
                data: r.rest(),
            },
            sid::REQUEST_TRANSFER_EXIT => Self::RequestTransferExit { data: r.rest() },
            sid::TESTER_PRESENT => Self::TesterPresent {
                sub_function: r.u8()?,
            },
            sid::CONTROL_DTC_SETTING => Self::ControlDtcSetting { setting: r.u8()? },
            _ => Self::Other {
                service: first,
                data: r.rest(),
            },
        };
        r.end()?;
        Ok(response)
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = vec![match self {
            Self::Negative { .. } => sid::NEGATIVE_RESPONSE,
            Self::Other { service, .. } => *service,
            _ => self.answers().wrapping_add(sid::POSITIVE_OFFSET),
        }];
        match self {
            Self::Negative { service, code } => out.extend([*service, code.0]),
            Self::DiagnosticSessionControl { session, timing } => {
                out.push(*session);
                if let Some(t) = timing {
                    out.extend(t.p2_server_max_ms.to_be_bytes());
                    out.extend(t.p2_star_server_max_10ms.to_be_bytes());
                }
            }
            Self::EcuReset {
                reset_type,
                power_down_time,
            } => {
                out.push(*reset_type);
                out.extend(power_down_time);
            }
            Self::ClearDiagnosticInformation => {}
            Self::ReadDtcInformation { report } => report.write(&mut out),
            Self::ReadDataByIdentifier { did, data }
            | Self::InputOutputControlByIdentifier { did, data } => {
                out.extend(did.to_be_bytes());
                out.extend(data);
            }
            Self::SecurityAccess { sub_function, data } => {
                out.push(*sub_function);
                out.extend(data);
            }
            Self::CommunicationControl { control_type: b }
            | Self::TesterPresent { sub_function: b }
            | Self::ControlDtcSetting { setting: b } => out.push(*b),
            Self::WriteDataByIdentifier { did } => out.extend(did.to_be_bytes()),
            Self::RoutineControl {
                sub_function,
                routine,
                data,
            } => {
                out.push(*sub_function);
                out.extend(routine.to_be_bytes());
                out.extend(data);
            }
            Self::RequestDownload { max_block_length }
            | Self::RequestUpload { max_block_length } => {
                out.push(max_block_length.width << 4);
                put_uint(&mut out, max_block_length.value, max_block_length.width);
            }
            Self::TransferData { sequence, data } => {
                out.push(*sequence);
                out.extend(data);
            }
            Self::ReadMemoryByAddress { data }
            | Self::RequestTransferExit { data }
            | Self::Other { data, .. } => out.extend(data),
        }
        out
    }

    /// The request service id this answers.
    pub fn answers(&self) -> u8 {
        match self {
            Self::Negative { service, .. } => *service,
            Self::DiagnosticSessionControl { .. } => sid::DIAGNOSTIC_SESSION_CONTROL,
            Self::EcuReset { .. } => sid::ECU_RESET,
            Self::ClearDiagnosticInformation => sid::CLEAR_DIAGNOSTIC_INFORMATION,
            Self::ReadDtcInformation { .. } => sid::READ_DTC_INFORMATION,
            Self::ReadDataByIdentifier { .. } => sid::READ_DATA_BY_IDENTIFIER,
            Self::ReadMemoryByAddress { .. } => sid::READ_MEMORY_BY_ADDRESS,
            Self::SecurityAccess { .. } => sid::SECURITY_ACCESS,
            Self::CommunicationControl { .. } => sid::COMMUNICATION_CONTROL,
            Self::WriteDataByIdentifier { .. } => sid::WRITE_DATA_BY_IDENTIFIER,
            Self::InputOutputControlByIdentifier { .. } => sid::INPUT_OUTPUT_CONTROL_BY_IDENTIFIER,
            Self::RoutineControl { .. } => sid::ROUTINE_CONTROL,
            Self::RequestDownload { .. } => sid::REQUEST_DOWNLOAD,
            Self::RequestUpload { .. } => sid::REQUEST_UPLOAD,
            Self::TransferData { .. } => sid::TRANSFER_DATA,
            Self::RequestTransferExit { .. } => sid::REQUEST_TRANSFER_EXIT,
            Self::TesterPresent { .. } => sid::TESTER_PRESENT,
            Self::ControlDtcSetting { .. } => sid::CONTROL_DTC_SETTING,
            Self::Other { service, .. } => service.wrapping_sub(sid::POSITIVE_OFFSET),
        }
    }

    /// A negative response with requestCorrectlyReceivedResponsePending.
    pub fn is_pending(&self) -> bool {
        matches!(self, Self::Negative { code, .. } if *code == Nrc::RESPONSE_PENDING)
    }
}

pub(crate) struct Reader<'a> {
    pub(crate) service: u8,
    pub(crate) rest: &'a [u8],
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], DecodeError> {
        if self.rest.len() < n {
            return Err(DecodeError::Length(self.service));
        }
        let (head, tail) = self.rest.split_at(n);
        self.rest = tail;
        Ok(head)
    }

    fn u8(&mut self) -> Result<u8, DecodeError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, DecodeError> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    fn u24(&mut self) -> Result<u32, DecodeError> {
        let b = self.take(3)?;
        Ok(u32::from_be_bytes([0, b[0], b[1], b[2]]))
    }

    fn uint(&mut self, width: u8) -> Result<u64, DecodeError> {
        let bytes = self.take(width.into())?;
        Ok(bytes.iter().fold(0, |acc, b| acc << 8 | u64::from(*b)))
    }

    fn sub_function(&mut self) -> Result<SubFunction, DecodeError> {
        self.u8().map(SubFunction::from_byte)
    }

    fn optional(&mut self, n: usize) -> Result<Option<&'a [u8]>, DecodeError> {
        if self.rest.is_empty() {
            return Ok(None);
        }
        self.take(n).map(Some)
    }

    fn block_length(&mut self) -> Result<BlockLength, DecodeError> {
        let format = self.u8()?;
        let width = format >> 4;
        if format & 0x0F != 0 || !(1..=8).contains(&width) {
            return Err(DecodeError::Format(self.service));
        }
        Ok(BlockLength {
            value: self.uint(width)?,
            width,
        })
    }

    fn dtcs(&mut self) -> Result<Vec<DtcStatus>, DecodeError> {
        let (records, []) = std::mem::take(&mut self.rest).as_chunks::<4>() else {
            return Err(DecodeError::Length(self.service));
        };
        Ok(records
            .iter()
            .map(|d| DtcStatus {
                dtc: u32::from_be_bytes([0, d[0], d[1], d[2]]),
                status: d[3],
            })
            .collect())
    }

    fn rest(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.rest).to_vec()
    }

    fn non_empty_rest(&mut self) -> Result<Vec<u8>, DecodeError> {
        if self.rest.is_empty() {
            return Err(DecodeError::Length(self.service));
        }
        Ok(self.rest())
    }

    fn end(&self) -> Result<(), DecodeError> {
        if self.rest.is_empty() {
            Ok(())
        } else {
            Err(DecodeError::Length(self.service))
        }
    }
}

fn put_uint(out: &mut Vec<u8>, value: u64, width: u8) {
    out.extend_from_slice(&value.to_be_bytes()[8 - usize::from(width)..]);
}
