//! Each exported type, doc comments and the generator's banner aside, against
//! its pinned declaration.

use ts_rs::{Config, TS};

use wslib_isotp::{
    Addressing, Detection, FdLength, FlowControl, FlowStatus, FrameFormat, Framing, IdEvidence,
    KindCounts, NoticeKind, Pair, Side, StMin, TapEvent, TapMessage, TapNotice, TimedFrame,
};

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
fn addressing() {
    assert_eq!(
        exported::<Addressing>(),
        r#"export type IsoTpAddressing = "Normal" | { "Extended": { tx: number, rx: number, } } | { "Mixed": { tx: number, rx: number, } };"#
    );
}

#[test]
fn fd_length() {
    assert_eq!(
        exported::<FdLength>(),
        r#"export type IsoTpFdLength = number;"#
    );
}

#[test]
fn frame_format() {
    assert_eq!(
        exported::<FrameFormat>(),
        r#"import type { IsoTpFdLength } from "./IsoTpFdLength"; export type IsoTpFrameFormat = "Classic" | { "Fd": IsoTpFdLength };"#
    );
}

#[test]
fn framing() {
    assert_eq!(
        exported::<Framing>(),
        r#"import type { IsoTpAddressing } from "./IsoTpAddressing"; import type { IsoTpFrameFormat } from "./IsoTpFrameFormat"; export type IsoTpFraming = { addressing: IsoTpAddressing, format: IsoTpFrameFormat, padding: number | null, max_message: number, };"#
    );
}

#[test]
fn flow_control() {
    assert_eq!(
        exported::<FlowControl>(),
        r#"import type { IsoTpFlowStatus } from "./IsoTpFlowStatus"; import type { IsoTpStMin } from "./IsoTpStMin"; export type IsoTpFlowControl = { status: IsoTpFlowStatus, block_size: number, st_min: IsoTpStMin, };"#
    );
    assert_eq!(
        exported::<FlowStatus>(),
        r#"export type IsoTpFlowStatus = "ContinueToSend" | "Wait" | "Overflow";"#
    );
    assert_eq!(exported::<StMin>(), r#"export type IsoTpStMin = number;"#);
}

#[test]
fn timed_frame() {
    assert_eq!(
        exported::<TimedFrame>(),
        r#"export type IsoTpTimedFrame = { id: number, extended: boolean, data: Array<number>, at_us: number, };"#
    );
}

#[test]
fn tap_event() {
    assert_eq!(exported::<Side>(), r#"export type IsoTpSide = "A" | "B";"#);
    assert_eq!(
        exported::<TapMessage>(),
        r#"import type { IsoTpFlowControl } from "./IsoTpFlowControl"; import type { IsoTpSide } from "./IsoTpSide"; export type IsoTpTapMessage = { from: IsoTpSide, data: Array<number>, frames: number, first_at_us: number, last_at_us: number, flow_controls: Array<IsoTpFlowControl>, flow_control_count: number, };"#
    );
    assert_eq!(
        exported::<TapNotice>(),
        r#"import type { IsoTpNoticeKind } from "./IsoTpNoticeKind"; import type { IsoTpSide } from "./IsoTpSide"; export type IsoTpTapNotice = { side: IsoTpSide, at_us: number, kind: IsoTpNoticeKind, };"#
    );
    assert_eq!(
        exported::<NoticeKind>(),
        r#"export type IsoTpNoticeKind = { "OutOfSequence": { expected: number, received: number, } } | { "Truncated": { needed: number, carried: number, } } | "Superseded" | { "TimedOut": { gap_us: number, } } | "Overflow" | "Wait" | "TooManyWaits" | { "ReservedFlowStatus": { status: number, } } | { "TooLong": { len: number, } } | { "Resynchronised": { skipped: number, } };"#
    );
    assert_eq!(
        exported::<TapEvent>(),
        r#"import type { IsoTpTapMessage } from "./IsoTpTapMessage"; import type { IsoTpTapNotice } from "./IsoTpTapNotice"; export type IsoTpTapEvent = { "Message": IsoTpTapMessage } | { "Notice": IsoTpTapNotice };"#
    );
}

#[test]
fn detection() {
    assert_eq!(
        exported::<KindCounts>(),
        r#"export type IsoTpKindCounts = { single: number, first: number, consecutive: number, flow_control: number, undecodable: number, bad_length: number, sequence_breaks: number, };"#
    );
    assert_eq!(
        exported::<IdEvidence>(),
        r#"import type { IsoTpKindCounts } from "./IsoTpKindCounts"; export type IsoTpIdEvidence = { id: number, extended: boolean, frames: number, counts: IsoTpKindCounts, address_byte: number | null, fd: boolean, exchanges: number, ambiguous: number, iso_tp: boolean, };"#
    );
    assert_eq!(
        exported::<Pair>(),
        r#"import type { IsoTpAddressing } from "./IsoTpAddressing"; export type IsoTpPair = { a_id: number, b_id: number, extended: boolean, addressing: IsoTpAddressing, fd: boolean, from_a: number, from_b: number, };"#
    );
    assert_eq!(
        exported::<Detection>(),
        r#"import type { IsoTpIdEvidence } from "./IsoTpIdEvidence"; import type { IsoTpPair } from "./IsoTpPair"; export type IsoTpDetection = { ids: Array<IsoTpIdEvidence>, pairs: Array<IsoTpPair>, };"#
    );
}

#[test]
fn serde_writes_times_as_microseconds_and_fd_lengths_as_numbers() {
    let frame = TimedFrame {
        id: 0x7E8,
        extended: false,
        data: vec![0x02, 0x50, 0x01],
        at: std::time::UNIX_EPOCH + std::time::Duration::from_micros(1_700_000_000_123_456),
    };
    let json = serde_json::to_string(&frame).unwrap();
    assert_eq!(
        json,
        r#"{"id":2024,"extended":false,"data":[2,80,1],"at_us":1700000000123456}"#
    );
    assert_eq!(serde_json::from_str::<TimedFrame>(&json).unwrap(), frame);
    let format = FrameFormat::Fd(FdLength::MAX);
    assert_eq!(serde_json::to_string(&format).unwrap(), r#"{"Fd":64}"#);
    assert!(serde_json::from_str::<FrameFormat>(r#"{"Fd":13}"#).is_err());
}
