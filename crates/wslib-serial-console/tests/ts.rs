#![cfg(feature = "ts")]
//! Each exported type, doc comments and the generator's banner aside, against
//! the declaration a browser's TypeScript is generated from.

use ts_rs::{Config, TS};
use wslib_serial_console::{
    ConsoleAction, ConsoleEvent, EndReason, Finished, MonitorState, Participant, RefusalReason,
    Span,
};

fn exported<T: TS + 'static>() -> String {
    let ts = T::export_to_string(&Config::new()).unwrap();
    let mut out = String::new();
    let mut rest = ts.as_str();
    while let Some(start) = rest.find("/**") {
        out.push_str(&rest[..start]);
        rest = &rest[start + rest[start..].find("*/").unwrap() + 2..];
    }
    out.push_str(rest);
    out.lines()
        .filter(|line| !line.starts_with("// ") && !line.starts_with("import "))
        .collect::<Vec<_>>()
        .join(" ")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

#[test]
fn console_event() {
    assert_eq!(
        exported::<ConsoleEvent>(),
        r#"export type ConsoleEvent = { "type": "attached", name: string, writes: boolean, baud?: number, } | { "type": "state", state: MonitorState, label: string, message?: string, } | { "type": "spans", spans: Array<Span>, } | { "type": "input", by: string, colour: number, marker: string, } | { "type": "participants", participants: Array<Participant>, } | { "type": "refused", reason: RefusalReason, detail?: string, } | { "type": "error", message: string, };"#
    );
}

#[test]
fn monitor_state() {
    assert_eq!(
        exported::<MonitorState>(),
        r#"export type MonitorState = "resolving" | "opening" | "reading" | "backoff" | "tty_missing" | "paused";"#
    );
}

#[test]
fn span() {
    assert_eq!(
        exported::<Span>(),
        r#"export type Span = { start: number, len: number, by: string, colour: number, };"#
    );
}

#[test]
fn participant() {
    assert_eq!(
        exported::<Participant>(),
        r#"export type Participant = { name: string, via: string, colour: number, };"#
    );
}

#[test]
fn refusal_reason() {
    assert_eq!(
        exported::<RefusalReason>(),
        r#"export type RefusalReason = "paused" | "no_active_reader" | "not_permitted";"#
    );
}

#[test]
fn console_action() {
    assert_eq!(
        exported::<ConsoleAction>(),
        r#"export type ConsoleAction = { "action": "reset" };"#
    );
}

#[test]
fn finished() {
    assert_eq!(
        exported::<Finished>(),
        r#"export type Finished = { reason: EndReason, };"#
    );
}

#[test]
fn end_reason() {
    assert_eq!(
        exported::<EndReason>(),
        r#"export type EndReason = "pattern" | "lines" | "duration" | "timeout" | "closed" | "released";"#
    );
}
