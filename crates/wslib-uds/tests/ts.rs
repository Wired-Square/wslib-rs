//! Each exported type, doc comments and the generator's banner aside, against
//! its pinned declaration.

use ts_rs::{Config, TS};

use wslib_uds::{
    Answer, BlockLength, Detail, DidFinding, DidVerdict, DtcRequest, DtcResponse, DtcStatus,
    Identity, MemoryRange, Nrc, Observed, Outcome, Request, Response, Safety, ScanProgress, Sender,
    ServiceFinding, ServiceVerdict, SessionTiming, SubFunction, Transaction,
};

#[test]
fn answer() {
    assert_eq!(
        exported::<Answer>(),
        r#"import type { UdsNrc } from "./UdsNrc"; export type UdsAnswer = { "kind": "positive" } | { "kind": "negative", code: UdsNrc, };"#
    );
}

#[test]
fn block_length() {
    assert_eq!(
        exported::<BlockLength>(),
        "export type UdsBlockLength = { value: number, width: number, };"
    );
}

fn exported<T: TS + 'static>() -> String {
    let ts = T::export_to_string(&Config::new().with_large_int("number")).unwrap();
    let mut out = String::new();
    let mut rest = ts.as_str();
    while let Some(start) = rest.find("/**") {
        out.push_str(&rest[..start]);
        rest = &rest[start + rest[start..].find("*/").unwrap() + 2..];
    }
    out.push_str(rest);
    out.lines()
        .filter(|line| !line.starts_with("// "))
        .collect::<Vec<_>>()
        .join(" ")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

#[test]
fn request() {
    assert_eq!(
        exported::<Request>(),
        r#"import type { UdsDtcRequest } from "./UdsDtcRequest"; import type { UdsMemoryRange } from "./UdsMemoryRange"; import type { UdsSubFunction } from "./UdsSubFunction"; export type UdsRequest = { "kind": "diagnostic_session_control", subFunction: UdsSubFunction, } | { "kind": "ecu_reset", subFunction: UdsSubFunction, } | { "kind": "clear_diagnostic_information", group: number, memorySelection: number | null, } | { "kind": "read_dtc_information", report: UdsDtcRequest, suppressPositiveResponse: boolean, } | { "kind": "read_data_by_identifier", dids: Array<number>, } | { "kind": "read_memory_by_address", range: UdsMemoryRange, } | { "kind": "security_access", subFunction: UdsSubFunction, data: Array<number>, } | { "kind": "communication_control", subFunction: UdsSubFunction, communicationType: number, node: number | null, } | { "kind": "write_data_by_identifier", did: number, data: Array<number>, } | { "kind": "input_output_control_by_identifier", did: number, data: Array<number>, } | { "kind": "routine_control", subFunction: UdsSubFunction, routine: number, data: Array<number>, } | { "kind": "request_download", dataFormat: number, range: UdsMemoryRange, } | { "kind": "request_upload", dataFormat: number, range: UdsMemoryRange, } | { "kind": "transfer_data", sequence: number, data: Array<number>, } | { "kind": "request_transfer_exit", data: Array<number>, } | { "kind": "tester_present", subFunction: UdsSubFunction, } | { "kind": "control_dtc_setting", subFunction: UdsSubFunction, data: Array<number>, } | { "kind": "other", service: number, data: Array<number>, };"#
    );
}

#[test]
fn response() {
    assert_eq!(
        exported::<Response>(),
        r#"import type { UdsBlockLength } from "./UdsBlockLength"; import type { UdsDtcResponse } from "./UdsDtcResponse"; import type { UdsNrc } from "./UdsNrc"; import type { UdsSessionTiming } from "./UdsSessionTiming"; export type UdsResponse = { "kind": "negative", service: number, code: UdsNrc, } | { "kind": "diagnostic_session_control", session: number, timing: UdsSessionTiming | null, } | { "kind": "ecu_reset", resetType: number, powerDownTime: number | null, } | { "kind": "clear_diagnostic_information" } | { "kind": "read_dtc_information", report: UdsDtcResponse, } | { "kind": "read_data_by_identifier", did: number, data: Array<number>, } | { "kind": "read_memory_by_address", data: Array<number>, } | { "kind": "security_access", subFunction: number, data: Array<number>, } | { "kind": "communication_control", controlType: number, } | { "kind": "write_data_by_identifier", did: number, } | { "kind": "input_output_control_by_identifier", did: number, data: Array<number>, } | { "kind": "routine_control", subFunction: number, routine: number, data: Array<number>, } | { "kind": "request_download", maxBlockLength: UdsBlockLength, } | { "kind": "request_upload", maxBlockLength: UdsBlockLength, } | { "kind": "transfer_data", sequence: number, data: Array<number>, } | { "kind": "request_transfer_exit", data: Array<number>, } | { "kind": "tester_present", subFunction: number, } | { "kind": "control_dtc_setting", setting: number, } | { "kind": "other", service: number, data: Array<number>, };"#
    );
}

#[test]
fn sub_function() {
    assert_eq!(
        exported::<SubFunction>(),
        "export type UdsSubFunction = { value: number, suppressPositiveResponse: boolean, };"
    );
}

#[test]
fn memory_range() {
    assert_eq!(
        exported::<MemoryRange>(),
        "export type UdsMemoryRange = { address: number, addressWidth: number, size: number, sizeWidth: number, };"
    );
}

#[test]
fn session_timing() {
    assert_eq!(
        exported::<SessionTiming>(),
        "export type UdsSessionTiming = { p2ServerMaxMs: number, p2StarServerMax10ms: number, };"
    );
}

#[test]
fn dtc_status() {
    assert_eq!(
        exported::<DtcStatus>(),
        "export type UdsDtcStatus = { dtc: number, status: number, };"
    );
}

#[test]
fn dtc_request() {
    assert_eq!(
        exported::<DtcRequest>(),
        r#"export type UdsDtcRequest = { "kind": "number_by_status_mask", statusMask: number, } | { "kind": "by_status_mask", statusMask: number, } | { "kind": "snapshot_record_by_dtc", dtc: number, record: number, } | { "kind": "extended_data_record_by_dtc", dtc: number, record: number, } | { "kind": "supported_dtcs" } | { "kind": "other", reportType: number, data: Array<number>, };"#
    );
}

#[test]
fn dtc_response() {
    assert_eq!(
        exported::<DtcResponse>(),
        r#"import type { UdsDtcStatus } from "./UdsDtcStatus"; export type UdsDtcResponse = { "kind": "number_by_status_mask", availabilityMask: number, format: number, count: number, } | { "kind": "by_status_mask", availabilityMask: number, dtcs: Array<UdsDtcStatus>, } | { "kind": "supported_dtcs", availabilityMask: number, dtcs: Array<UdsDtcStatus>, } | { "kind": "other", reportType: number, data: Array<number>, };"#
    );
}

#[test]
fn nrc() {
    assert_eq!(exported::<Nrc>(), "export type UdsNrc = number;");
}

#[test]
fn safety() {
    assert_eq!(
        exported::<Safety>(),
        r#"export type UdsSafety = "read_only" | "state_changing" | "destructive";"#
    );
}

#[test]
fn identity() {
    assert_eq!(
        exported::<Identity>(),
        r#"import type { UdsDetail } from "./UdsDetail"; export type UdsIdentity = { service: number, detail: UdsDetail | null, };"#
    );
}

#[test]
fn detail() {
    assert_eq!(
        exported::<Detail>(),
        r#"export type UdsDetail = { "kind": "session", session: number, } | { "kind": "reset", resetType: number, } | { "kind": "dtc_group", group: number, } | { "kind": "dtc_report", reportType: number, } | { "kind": "dids", dids: Array<number>, } | { "kind": "memory", address: number, size: number, } | { "kind": "security_access", subFunction: number, } | { "kind": "communication", controlType: number, } | { "kind": "routine", routine: number, subFunction: number, } | { "kind": "block", sequence: number, } | { "kind": "dtc_setting", setting: number, };"#
    );
}

#[test]
fn sender() {
    assert_eq!(
        exported::<Sender>(),
        r#"export type UdsSender = "tester" | "ecu";"#
    );
}

#[test]
fn transaction() {
    assert_eq!(
        exported::<Transaction>(),
        r#"import type { UdsOutcome } from "./UdsOutcome"; export type UdsTransaction = { request: Array<number>, requestedAtUs: number, pendingResponses: number, outcome: UdsOutcome, };"#
    );
}

#[test]
fn outcome() {
    assert_eq!(
        exported::<Outcome>(),
        r#"export type UdsOutcome = { "kind": "answered", response: Array<number>, latencyUs: number, } | { "kind": "malformed", response: Array<number>, latencyUs: number, } | { "kind": "suppressed" } | { "kind": "superseded" } | { "kind": "timed_out" } | { "kind": "unfinished" };"#
    );
}

#[test]
fn observed() {
    assert_eq!(
        exported::<Observed>(),
        r#"import type { UdsTransaction } from "./UdsTransaction"; export type UdsObserved = { "kind": "transaction" } & UdsTransaction | { "kind": "unsolicited", response: Array<number>, atUs: number, };"#
    );
}

#[test]
fn scan_progress() {
    assert_eq!(
        exported::<ScanProgress>(),
        "export type UdsScanProgress = { done: number, total: number, found: number, stoppedEarly: boolean, };"
    );
}

#[test]
fn service_verdict() {
    assert_eq!(
        exported::<ServiceVerdict>(),
        r#"import type { UdsNrc } from "./UdsNrc"; export type UdsServiceVerdict = { "kind": "present", code: UdsNrc, } | { "kind": "absent" } | { "kind": "not_in_session" } | { "kind": "busy" } | { "kind": "executed" } | { "kind": "inconclusive" };"#
    );
}

#[test]
fn service_finding() {
    assert_eq!(
        exported::<ServiceFinding>(),
        r#"import type { UdsServiceVerdict } from "./UdsServiceVerdict"; export type UdsServiceFinding = { service: number, verdict: UdsServiceVerdict, };"#
    );
}

#[test]
fn did_verdict() {
    assert_eq!(
        exported::<DidVerdict>(),
        r#"import type { UdsNrc } from "./UdsNrc"; export type UdsDidVerdict = { "kind": "present", length: number, } | { "kind": "absent" } | { "kind": "locked" } | { "kind": "not_in_session" } | { "kind": "busy" } | { "kind": "inconclusive", code: UdsNrc | null, };"#
    );
}

#[test]
fn did_finding() {
    assert_eq!(
        exported::<DidFinding>(),
        r#"import type { UdsDidVerdict } from "./UdsDidVerdict"; export type UdsDidFinding = { did: number, verdict: UdsDidVerdict, };"#
    );
}

#[cfg(feature = "write")]
#[test]
fn session_verdict() {
    assert_eq!(
        exported::<wslib_uds::SessionVerdict>(),
        r#"import type { UdsNrc } from "./UdsNrc"; import type { UdsSessionTiming } from "./UdsSessionTiming"; export type UdsSessionVerdict = { "kind": "supported", timing: UdsSessionTiming | null, } | { "kind": "unsupported" } | { "kind": "not_from_this_session" } | { "kind": "conditions_not_correct" } | { "kind": "locked" } | { "kind": "busy" } | { "kind": "inconclusive", code: UdsNrc | null, } | { "kind": "not_restored", code: UdsNrc | null, };"#
    );
}

#[cfg(feature = "write")]
#[test]
fn session_finding() {
    assert_eq!(
        exported::<wslib_uds::SessionFinding>(),
        r#"import type { UdsSessionVerdict } from "./UdsSessionVerdict"; export type UdsSessionFinding = { session: number, verdict: UdsSessionVerdict, };"#
    );
}
