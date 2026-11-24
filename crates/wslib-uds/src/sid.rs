//! Service ids and their names in ISO 14229-1.

pub const DIAGNOSTIC_SESSION_CONTROL: u8 = 0x10;
pub const ECU_RESET: u8 = 0x11;
pub const CLEAR_DIAGNOSTIC_INFORMATION: u8 = 0x14;
pub const READ_DTC_INFORMATION: u8 = 0x19;
pub const READ_DATA_BY_IDENTIFIER: u8 = 0x22;
pub const READ_MEMORY_BY_ADDRESS: u8 = 0x23;
pub const SECURITY_ACCESS: u8 = 0x27;
pub const COMMUNICATION_CONTROL: u8 = 0x28;
pub const WRITE_DATA_BY_IDENTIFIER: u8 = 0x2E;
pub const INPUT_OUTPUT_CONTROL_BY_IDENTIFIER: u8 = 0x2F;
pub const ROUTINE_CONTROL: u8 = 0x31;
pub const REQUEST_DOWNLOAD: u8 = 0x34;
pub const REQUEST_UPLOAD: u8 = 0x35;
pub const TRANSFER_DATA: u8 = 0x36;
pub const REQUEST_TRANSFER_EXIT: u8 = 0x37;
pub const TESTER_PRESENT: u8 = 0x3E;
pub const CONTROL_DTC_SETTING: u8 = 0x85;

/// The first byte of every negative response.
pub const NEGATIVE_RESPONSE: u8 = 0x7F;
/// Added to a request's service id to make its positive response's.
pub const POSITIVE_OFFSET: u8 = 0x40;

struct Service {
    id: u8,
    name: &'static str,
    sub_function: bool,
}

const fn service(id: u8, name: &'static str, sub_function: bool) -> Service {
    Service {
        id,
        name,
        sub_function,
    }
}

const SERVICES: &[Service] = &[
    service(0x10, "DiagnosticSessionControl", true),
    service(0x11, "ECUReset", true),
    service(0x14, "ClearDiagnosticInformation", false),
    service(0x19, "ReadDTCInformation", true),
    service(0x22, "ReadDataByIdentifier", false),
    service(0x23, "ReadMemoryByAddress", false),
    service(0x24, "ReadScalingDataByIdentifier", false),
    service(0x27, "SecurityAccess", true),
    service(0x28, "CommunicationControl", true),
    service(0x29, "Authentication", true),
    service(0x2A, "ReadDataByPeriodicIdentifier", false),
    service(0x2C, "DynamicallyDefineDataIdentifier", true),
    service(0x2E, "WriteDataByIdentifier", false),
    service(0x2F, "InputOutputControlByIdentifier", false),
    service(0x31, "RoutineControl", true),
    service(0x34, "RequestDownload", false),
    service(0x35, "RequestUpload", false),
    service(0x36, "TransferData", false),
    service(0x37, "RequestTransferExit", false),
    service(0x38, "RequestFileTransfer", false),
    service(0x3D, "WriteMemoryByAddress", false),
    service(0x3E, "TesterPresent", true),
    service(0x83, "AccessTimingParameter", true),
    service(0x84, "SecuredDataTransmission", false),
    service(0x85, "ControlDTCSetting", true),
    service(0x86, "ResponseOnEvent", true),
    service(0x87, "LinkControl", true),
];

fn find(id: u8) -> Option<&'static Service> {
    SERVICES.iter().find(|s| s.id == id)
}

/// The standard name of a request service id.
pub fn name(service: u8) -> Option<&'static str> {
    find(service).map(|s| s.name)
}

/// Whether an ISO service's second byte is a sub-function, with its
/// suppress-positive-response bit.
pub fn has_sub_function(service: u8) -> bool {
    find(service).is_some_and(|s| s.sub_function)
}

/// Every request service id ISO 14229-1 defines, ascending.
pub fn iso() -> impl Iterator<Item = u8> {
    SERVICES.iter().map(|s| s.id)
}
