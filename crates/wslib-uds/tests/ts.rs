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
        r#"import type { UdsDtcRequest } from "./UdsDtcRequest"; import type { UdsMemoryRange } from "./UdsMemoryRange"; import type { UdsSubFunction } from "./UdsSubFunction"; export type UdsRequest = { "kind": "diagnosticSessionControl", subFunction: UdsSubFunction, } | { "kind": "ecuReset", subFunction: UdsSubFunction, } | { "kind": "clearDiagnosticInformation", group: number, memorySelection: number | null, } | { "kind": "readDtcInformation", report: UdsDtcRequest, suppressPositiveResponse: boolean, } | { "kind": "readDataByIdentifier", dids: Array<number>, } | { "kind": "readMemoryByAddress", range: UdsMemoryRange, } | { "kind": "securityAccess", subFunction: UdsSubFunction, data: Array<number>, } | { "kind": "communicationControl", subFunction: UdsSubFunction, communicationType: number, node: number | null, } | { "kind": "writeDataByIdentifier", did: number, data: Array<number>, } | { "kind": "inputOutputControlByIdentifier", did: number, data: Array<number>, } | { "kind": "routineControl", subFunction: UdsSubFunction, routine: number, data: Array<number>, } | { "kind": "requestDownload", dataFormat: number, range: UdsMemoryRange, } | { "kind": "requestUpload", dataFormat: number, range: UdsMemoryRange, } | { "kind": "transferData", sequence: number, data: Array<number>, } | { "kind": "requestTransferExit", data: Array<number>, } | { "kind": "testerPresent", subFunction: UdsSubFunction, } | { "kind": "controlDtcSetting", subFunction: UdsSubFunction, data: Array<number>, } | { "kind": "other", service: number, data: Array<number>, };"#
    );
}

#[test]
fn response() {
    assert_eq!(
        exported::<Response>(),
        r#"import type { UdsBlockLength } from "./UdsBlockLength"; import type { UdsDtcResponse } from "./UdsDtcResponse"; import type { UdsNrc } from "./UdsNrc"; import type { UdsSessionTiming } from "./UdsSessionTiming"; export type UdsResponse = { "kind": "negative", service: number, code: UdsNrc, } | { "kind": "diagnosticSessionControl", session: number, timing: UdsSessionTiming | null, } | { "kind": "ecuReset", resetType: number, powerDownTime: number | null, } | { "kind": "clearDiagnosticInformation" } | { "kind": "readDtcInformation", report: UdsDtcResponse, } | { "kind": "readDataByIdentifier", did: number, data: Array<number>, } | { "kind": "readMemoryByAddress", data: Array<number>, } | { "kind": "securityAccess", subFunction: number, data: Array<number>, } | { "kind": "communicationControl", controlType: number, } | { "kind": "writeDataByIdentifier", did: number, } | { "kind": "inputOutputControlByIdentifier", did: number, data: Array<number>, } | { "kind": "routineControl", subFunction: number, routine: number, data: Array<number>, } | { "kind": "requestDownload", maxBlockLength: UdsBlockLength, } | { "kind": "requestUpload", maxBlockLength: UdsBlockLength, } | { "kind": "transferData", sequence: number, data: Array<number>, } | { "kind": "requestTransferExit", data: Array<number>, } | { "kind": "testerPresent", subFunction: number, } | { "kind": "controlDtcSetting", setting: number, } | { "kind": "other", service: number, data: Array<number>, };"#
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
        r#"export type UdsDtcRequest = { "kind": "numberByStatusMask", statusMask: number, } | { "kind": "byStatusMask", statusMask: number, } | { "kind": "snapshotRecordByDtc", dtc: number, record: number, } | { "kind": "extendedDataRecordByDtc", dtc: number, record: number, } | { "kind": "supportedDtcs" } | { "kind": "other", reportType: number, data: Array<number>, };"#
    );
}

#[test]
fn dtc_response() {
    assert_eq!(
        exported::<DtcResponse>(),
        r#"import type { UdsDtcStatus } from "./UdsDtcStatus"; export type UdsDtcResponse = { "kind": "numberByStatusMask", availabilityMask: number, format: number, count: number, } | { "kind": "byStatusMask", availabilityMask: number, dtcs: Array<UdsDtcStatus>, } | { "kind": "supportedDtcs", availabilityMask: number, dtcs: Array<UdsDtcStatus>, } | { "kind": "other", reportType: number, data: Array<number>, };"#
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
        r#"export type UdsSafety = "readOnly" | "stateChanging" | "destructive";"#
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
        r#"export type UdsDetail = { "kind": "session", session: number, } | { "kind": "reset", resetType: number, } | { "kind": "dtcGroup", group: number, } | { "kind": "dtcReport", reportType: number, } | { "kind": "dids", dids: Array<number>, } | { "kind": "memory", address: number, size: number, } | { "kind": "securityAccess", subFunction: number, } | { "kind": "communication", controlType: number, } | { "kind": "routine", routine: number, subFunction: number, } | { "kind": "block", sequence: number, } | { "kind": "dtcSetting", setting: number, };"#
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
        r#"export type UdsOutcome = { "kind": "answered", response: Array<number>, latencyUs: number, } | { "kind": "malformed", response: Array<number>, latencyUs: number, } | { "kind": "suppressed" } | { "kind": "superseded" } | { "kind": "timedOut" } | { "kind": "unfinished" };"#
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
        r#"import type { UdsNrc } from "./UdsNrc"; export type UdsServiceVerdict = { "kind": "present", code: UdsNrc, } | { "kind": "absent" } | { "kind": "notInSession" } | { "kind": "busy" } | { "kind": "executed" } | { "kind": "inconclusive" };"#
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
        r#"import type { UdsNrc } from "./UdsNrc"; export type UdsDidVerdict = { "kind": "present", length: number, } | { "kind": "absent" } | { "kind": "locked" } | { "kind": "notInSession" } | { "kind": "busy" } | { "kind": "inconclusive", code: UdsNrc | null, };"#
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
        r#"import type { UdsNrc } from "./UdsNrc"; import type { UdsSessionTiming } from "./UdsSessionTiming"; export type UdsSessionVerdict = { "kind": "supported", timing: UdsSessionTiming | null, } | { "kind": "unsupported" } | { "kind": "notFromThisSession" } | { "kind": "conditionsNotCorrect" } | { "kind": "locked" } | { "kind": "busy" } | { "kind": "inconclusive", code: UdsNrc | null, } | { "kind": "notRestored", code: UdsNrc | null, };"#
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
