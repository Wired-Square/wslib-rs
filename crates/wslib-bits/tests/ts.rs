#![cfg(feature = "ts")]
//! Each exported type, doc comments and the generator's banner aside, against
//! its pinned declaration.

use ts_rs::{Config, TS};

#[cfg(feature = "display")]
use wslib_bits::DisplayHint;
use wslib_bits::Endianness;
use wslib_bits::PayloadField;
use wslib_bits::ScaledField;
use wslib_bits::SignalFormat;
use wslib_bits::frame_id::MatchedRange;
use wslib_bits::groups::Group;
use wslib_bits::groups::GroupMode;
use wslib_bits::groups::GroupOrder;
use wslib_bits::register::RegisterPairView;
use wslib_bits::register::RegisterView;

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
fn endianness() {
    assert_eq!(
        exported::<Endianness>(),
        r#"export type Endianness = "big" | "little";"#
    );
}

#[test]
fn payload_field() {
    assert_eq!(
        exported::<PayloadField>(),
        r#"import type { Endianness } from "./Endianness"; export type PayloadField = { startBit: number, bitLength: number, endianness: Endianness, signed: boolean, };"#
    );
}

#[test]
fn scaled_field() {
    assert_eq!(
        exported::<ScaledField>(),
        r#"import type { Endianness } from "./Endianness"; export type ScaledField = { factor: number, offset: number, startBit: number, bitLength: number, endianness: Endianness, signed: boolean, };"#
    );
}

#[test]
fn matched_range() {
    assert_eq!(
        exported::<MatchedRange>(),
        "export type MatchedRange = { lo: number, hi: number, };"
    );
}

#[test]
fn group_order() {
    assert_eq!(
        exported::<GroupOrder>(),
        r#"export type GroupOrder = "big" | "little" | "mid-big" | "mid-little";"#
    );
}

#[test]
fn group_mode() {
    assert_eq!(
        exported::<GroupMode>(),
        r#"export type GroupMode = "1B" | "2B" | "4B" | "8B" | { "custom": Array<number> };"#
    );
}

#[test]
fn group() {
    assert_eq!(
        exported::<Group>(),
        "export type GroupedValue = { index: number, bits: number, hex: string, unsigned: string, signedTwos: string, signedOnes: string, signedMag: string, text: string, binary: string, displayHex: string, bitOffset: number, startByteIndex: number, usedBitStart: number, usedBitEnd: number, };"
    );
}

#[test]
fn register_view() {
    assert_eq!(
        exported::<RegisterView>(),
        "export type RegisterView = { hex: string, u16: number, s16: number, ascii: string, };"
    );
}

#[test]
fn register_pair_view() {
    assert_eq!(
        exported::<RegisterPairView>(),
        r#"export type RegisterPairView = { u32: number, s32: number, f32: number | "NaN" | "Infinity" | "-Infinity", };"#
    );
}

#[test]
fn signal_format() {
    assert_eq!(
        exported::<SignalFormat>(),
        r#"export type SignalFormat = "ascii" | "utf8" | "hex" | "enum" | "unix_time" | "other";"#
    );
}

#[cfg(feature = "display")]
#[test]
fn display_hint() {
    assert_eq!(
        exported::<DisplayHint>(),
        "export type DisplayHint = { widget: string, [option: string]: unknown };"
    );
}
