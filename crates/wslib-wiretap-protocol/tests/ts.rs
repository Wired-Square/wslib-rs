#![cfg(feature = "ts")]
//! Each exported type, doc comments and the generator's banner aside, against the
//! declaration it must keep, under the same name.

use ts_rs::{Config, TS};
use wslib_wiretap_protocol::{FrameKey, InventoryRow, Protocol, ProtocolFrames};

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
fn protocol_frames() {
    assert_eq!(
        exported::<ProtocolFrames>(),
        "export type ProtocolFrames = { protocol: string, frame_ids: Array<number>, all_ids: boolean, };"
    );
}

#[test]
fn inventory_row() {
    assert_eq!(
        exported::<InventoryRow>(),
        "export type InventoryRow = { protocol: string, frame_id: number, frame_id_hex: string, \
         is_extended: boolean, count: number, first_us: number, last_us: number, max_dlc: number, };"
    );
}

#[test]
fn frame_key() {
    assert_eq!(
        exported::<FrameKey>(),
        "export type FrameKey = { frameId: number, isExtended: boolean, };"
    );
}

#[test]
fn archive_protocol() {
    assert_eq!(
        exported::<Protocol>(),
        r#"export type ArchiveProtocol = "can" | "modbus" | "serial";"#
    );
}
