//! Each exported type, doc comments and the generator's banner aside, against
//! its pinned declaration.

use ts_rs::{Config, TS};

use wslib_isotp::{
    Addressing, Detection, FdLength, FlowControl, FlowStatus, FrameFormat, Framing, IdEvidence,
    KindCounts, NoticeKind, Pair, Side, StMin, TapEvent, TapMessage, TapNotice, TimedFrame,
};

fn exported<T: TS + 'static>() -> String {
    let ts = T::export_to_string(&Config::default()).unwrap();
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
        r#"export type IsoTpAddressing = { "kind": "normal" } | { "kind": "extended", tx: number, rx: number, } | { "kind": "mixed", tx: number, rx: number, };"#
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
        r#"import type { IsoTpFdLength } from "./IsoTpFdLength"; export type IsoTpFrameFormat = { "kind": "classic" } | { "kind": "fd", length: IsoTpFdLength, };"#
    );
}

#[test]
fn framing() {
    assert_eq!(
        exported::<Framing>(),
        r#"import type { IsoTpAddressing } from "./IsoTpAddressing"; import type { IsoTpFrameFormat } from "./IsoTpFrameFormat"; export type IsoTpFraming = { addressing: IsoTpAddressing, format: IsoTpFrameFormat, padding: number | null, maxMessage: number, };"#
    );
}

#[test]
fn flow_control() {
    assert_eq!(
        exported::<FlowControl>(),
        r#"import type { IsoTpFlowStatus } from "./IsoTpFlowStatus"; import type { IsoTpStMin } from "./IsoTpStMin"; export type IsoTpFlowControl = { status: IsoTpFlowStatus, blockSize: number, stMin: IsoTpStMin, };"#
    );
    assert_eq!(
        exported::<FlowStatus>(),
        r#"export type IsoTpFlowStatus = "continueToSend" | "wait" | "overflow";"#
    );
    assert_eq!(exported::<StMin>(), r#"export type IsoTpStMin = number;"#);
}

#[test]
fn timed_frame() {
    assert_eq!(
        exported::<TimedFrame>(),
        r#"export type IsoTpTimedFrame = { id: number, extended: boolean, data: Array<number>, atUs: number, };"#
    );
}

#[test]
fn tap_event() {
    assert_eq!(exported::<Side>(), r#"export type IsoTpSide = "a" | "b";"#);
    assert_eq!(
        exported::<TapMessage>(),
        r#"import type { IsoTpFlowControl } from "./IsoTpFlowControl"; import type { IsoTpSide } from "./IsoTpSide"; export type IsoTpTapMessage = { from: IsoTpSide, data: Array<number>, frames: number, firstAtUs: number, lastAtUs: number, flowControls: Array<IsoTpFlowControl>, flowControlCount: number, };"#
    );
    assert_eq!(
        exported::<TapNotice>(),
        r#"import type { IsoTpNoticeKind } from "./IsoTpNoticeKind"; import type { IsoTpSide } from "./IsoTpSide"; export type IsoTpTapNotice = { side: IsoTpSide, atUs: number, notice: IsoTpNoticeKind, };"#
    );
    assert_eq!(
        exported::<NoticeKind>(),
        r#"export type IsoTpNoticeKind = { "kind": "outOfSequence", expected: number, received: number, } | { "kind": "truncated", needed: number, carried: number, } | { "kind": "superseded" } | { "kind": "timedOut", gapUs: number, } | { "kind": "overflow" } | { "kind": "wait" } | { "kind": "tooManyWaits" } | { "kind": "reservedFlowStatus", status: number, } | { "kind": "tooLong", len: number, } | { "kind": "resynchronised", skipped: number, };"#
    );
    assert_eq!(
        exported::<TapEvent>(),
        r#"import type { IsoTpTapMessage } from "./IsoTpTapMessage"; import type { IsoTpTapNotice } from "./IsoTpTapNotice"; export type IsoTpTapEvent = { "kind": "message" } & IsoTpTapMessage | { "kind": "notice" } & IsoTpTapNotice;"#
    );
}

#[test]
fn detection() {
    assert_eq!(
        exported::<KindCounts>(),
        r#"export type IsoTpKindCounts = { single: number, first: number, consecutive: number, flowControl: number, undecodable: number, badLength: number, sequenceBreaks: number, };"#
    );
    assert_eq!(
        exported::<IdEvidence>(),
        r#"import type { IsoTpKindCounts } from "./IsoTpKindCounts"; export type IsoTpIdEvidence = { id: number, extended: boolean, frames: number, counts: IsoTpKindCounts, addressByte: number | null, fd: boolean, exchanges: number, ambiguous: number, isoTp: boolean, };"#
    );
    assert_eq!(
        exported::<Pair>(),
        r#"import type { IsoTpAddressing } from "./IsoTpAddressing"; export type IsoTpPair = { aId: number, bId: number, extended: boolean, addressing: IsoTpAddressing, fd: boolean, fromA: number, fromB: number, };"#
    );
    assert_eq!(
        exported::<Detection>(),
        r#"import type { IsoTpIdEvidence } from "./IsoTpIdEvidence"; import type { IsoTpPair } from "./IsoTpPair"; export type IsoTpDetection = { ids: Array<IsoTpIdEvidence>, pairs: Array<IsoTpPair>, };"#
    );
}

fn round_trips<T>(value: T, json: &str)
where
    T: serde::Serialize + serde::de::DeserializeOwned + PartialEq + std::fmt::Debug,
{
    assert_eq!(serde_json::to_string(&value).unwrap(), json);
    assert_eq!(serde_json::from_str::<T>(json).unwrap(), value);
}

#[test]
fn serde_writes_camel_case_fields_and_variants_and_fd_lengths_as_numbers() {
    round_trips(
        TimedFrame {
            id: 0x7E8,
            extended: false,
            data: vec![0x02, 0x50, 0x01],
            at_us: 1_700_000_000_123_456,
        },
        r#"{"id":2024,"extended":false,"data":[2,80,1],"atUs":1700000000123456}"#,
    );
    round_trips(
        TapEvent::Notice(TapNotice {
            side: Side::B,
            at_us: 7,
            kind: NoticeKind::TimedOut { gap_us: 1_000_000 },
        }),
        r#"{"kind":"notice","side":"b","atUs":7,"notice":{"kind":"timedOut","gapUs":1000000}}"#,
    );
    round_trips(
        TapEvent::Message(TapMessage {
            from: Side::A,
            data: vec![0x3E, 0x00],
            frames: 1,
            first_at_us: 5,
            last_at_us: 5,
            flow_controls: vec![],
            flow_control_count: 0,
        }),
        r#"{"kind":"message","from":"a","data":[62,0],"frames":1,"firstAtUs":5,"lastAtUs":5,"flowControls":[],"flowControlCount":0}"#,
    );
    round_trips(NoticeKind::Superseded, r#"{"kind":"superseded"}"#);
    round_trips(
        FlowControl {
            status: FlowStatus::ContinueToSend,
            block_size: 8,
            st_min: StMin(0xF1),
        },
        r#"{"status":"continueToSend","blockSize":8,"stMin":241}"#,
    );
    round_trips(
        Addressing::Extended { tx: 0x10, rx: 0xF1 },
        r#"{"kind":"extended","tx":16,"rx":241}"#,
    );
    round_trips(Addressing::Normal, r#"{"kind":"normal"}"#);
    round_trips(
        FrameFormat::Fd {
            length: FdLength::MAX,
        },
        r#"{"kind":"fd","length":64}"#,
    );
    round_trips(FrameFormat::Classic, r#"{"kind":"classic"}"#);
    assert!(serde_json::from_str::<FrameFormat>(r#"{"kind":"fd","length":13}"#).is_err());
}
