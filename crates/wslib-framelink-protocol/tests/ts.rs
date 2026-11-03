#![cfg(feature = "ts")]
//! Each exported type, doc comments and the generator's banner aside, against
//! its pinned declaration.

use ts_rs::{Config, TS};

use wslib_framelink_protocol::bridge::{
    BridgeDefaultAction, BridgeFilter, BridgeFilterIde, BridgeFilterType, BridgeInfo,
};
use wslib_framelink_protocol::capabilities::{
    Capabilities, Interface, Meta, MetaValue, Peripheral,
};
use wslib_framelink_protocol::counter::CounterInfo;
use wslib_framelink_protocol::dsig::{SignalInfo, SignalKey};
use wslib_framelink_protocol::frame_def::{FrameDefInfo, FrameHeader, FrameSignalDef};
use wslib_framelink_protocol::generator::GeneratorInfo;
use wslib_framelink_protocol::stream::{FrameMetadata, StreamFrame};
use wslib_framelink_protocol::xform::{
    FunctionParams, GateOp, SignalMapping, TransformParams, TransformerInfo, XformFunction,
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
        .filter(|line| !line.starts_with("// ") && !line.starts_with("import "))
        .collect::<Vec<_>>()
        .join(" ")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

#[test]
fn signal_key() {
    assert_eq!(
        exported::<SignalKey>(),
        r#"export type SignalKey = { target_type: number, target_index: number, role: number, quantity: number, aspect: number, channel: number, };"#
    );
}

#[test]
fn signal_info() {
    assert_eq!(
        exported::<SignalInfo>(),
        r#"export type SignalInfo = { signal_id: number, target: string, target_index: number, role: string, quantity: string, aspect: string, channel: number | null, writable: boolean, persistable: boolean, rule_destination: boolean, frame_destination: boolean, value_type: string, value_len: number, scale: number, offset: number, bounds: [number, number] | null, };"#
    );
}

#[test]
fn meta_value() {
    assert_eq!(
        exported::<MetaValue>(),
        r#"export type MetaValue = number | string;"#
    );
}

#[test]
fn meta() {
    assert_eq!(
        exported::<Meta>(),
        r#"export type Meta = { name: string, value: number | string | Array<string> };"#
    );
}

#[test]
fn interface() {
    assert_eq!(
        exported::<Interface>(),
        r#"export type Interface = { index: number, type: string, meta: Array<Meta>, };"#
    );
}

#[test]
fn peripheral() {
    assert_eq!(
        exported::<Peripheral>(),
        r#"export type Peripheral = { index: number, kind: string, meta: Array<Meta>, };"#
    );
}

#[test]
fn capabilities() {
    assert_eq!(
        exported::<Capabilities>(),
        r#"export type Capabilities = { device_meta: Array<Meta>, interfaces: Array<Interface>, peripherals: Array<Peripheral>, };"#
    );
}

#[test]
fn frame_signal_def() {
    assert_eq!(
        exported::<FrameSignalDef>(),
        r#"export type FrameSignalDef = { signal_id: number, start_bit: number, bit_length: number, byte_order: string, value_type: string, quantity: string, scale: number, offset: number, };"#
    );
}

#[test]
fn frame_header() {
    assert_eq!(
        exported::<FrameHeader>(),
        r#"export type FrameHeader = { "kind": "can", can_id: number, dlc: number, flags: number, } | { "kind": "rs485", framing_mode: number, };"#
    );
}

#[test]
fn frame_def_info() {
    assert_eq!(
        exported::<FrameDefInfo>(),
        r#"export type FrameDefInfo = { frame_def_id: number, interface_type: string, header: FrameHeader, signals: Array<FrameSignalDef>, };"#
    );
}

#[test]
fn bridge_filter_type() {
    assert_eq!(
        exported::<BridgeFilterType>(),
        r#"export type BridgeFilterType = "mask" | "range";"#
    );
}

#[test]
fn bridge_filter_ide() {
    assert_eq!(
        exported::<BridgeFilterIde>(),
        r#"export type BridgeFilterIde = "any" | "std" | "ext";"#
    );
}

#[test]
fn bridge_default_action() {
    assert_eq!(
        exported::<BridgeDefaultAction>(),
        r#"export type BridgeDefaultAction = "pass" | "block";"#
    );
}

#[test]
fn bridge_filter() {
    assert_eq!(
        exported::<BridgeFilter>(),
        r#"export type BridgeFilter = { kind: BridgeFilterType, ide: BridgeFilterIde, a: number, b: number, };"#
    );
}

#[test]
fn bridge_info() {
    assert_eq!(
        exported::<BridgeInfo>(),
        r#"export type BridgeInfo = { bridge_id: number, source_interface: number, dest_interface: number, interface_type: string, enabled: boolean, default_action: BridgeDefaultAction, filters: Array<BridgeFilter>, };"#
    );
}

#[test]
fn transform_params() {
    assert_eq!(
        exported::<TransformParams>(),
        r#"export type TransformParams = { "kind": "direct" } | { "kind": "scale", scale: number, offset: number, } | { "kind": "invert" } | { "kind": "mask", mask: number, };"#
    );
}

#[test]
fn signal_mapping() {
    assert_eq!(
        exported::<SignalMapping>(),
        r#"export type SignalMapping = { source_signal_id: number, dest_signal_id: number, transform: TransformParams, };"#
    );
}

#[test]
fn gate_op() {
    assert_eq!(
        exported::<GateOp>(),
        r#"export type GateOp = "!=" | "==" | ">" | "<" | ">=" | "<=";"#
    );
}

#[test]
fn function_params() {
    assert_eq!(
        exported::<FunctionParams>(),
        r#"export type FunctionParams = { "kind": "palette", palette_signal_start: number, signal_max: number, } | { "kind": "clamp", min: number, max: number, } | { "kind": "threshold", threshold: number, value_above: number, value_below: number, } | { "kind": "gate", guard_signal_id: number, compare_op: GateOp, compare_value: number, fail_value: number, };"#
    );
}

#[test]
fn xform_function() {
    assert_eq!(
        exported::<XformFunction>(),
        r#"export type XformFunction = { function: string, source_signal_id: number, dest_signal_id: number, params: FunctionParams, };"#
    );
}

#[test]
fn transformer_info() {
    assert_eq!(
        exported::<TransformerInfo>(),
        r#"export type TransformerInfo = { transformer_id: number, source_frame_def_id: number, source_interface: number, dest_frame_def_id: number, dest_interface: number, enabled: boolean, mappings: Array<SignalMapping>, functions: Array<XformFunction>, };"#
    );
}

#[test]
fn generator_info() {
    assert_eq!(
        exported::<GeneratorInfo>(),
        r#"export type GeneratorInfo = { generator_id: number, frame_def_id: number, interface_index: number, period_ms: number, trigger: string, enabled: boolean, mappings: Array<SignalMapping>, };"#
    );
}

#[test]
fn counter_info() {
    assert_eq!(
        exported::<CounterInfo>(),
        r#"export type CounterInfo = { counter_id: number, modulo: number, init_value: number, value: number, };"#
    );
}

#[test]
fn frame_metadata() {
    assert_eq!(
        exported::<FrameMetadata>(),
        r#"export type FrameMetadata = { "kind": "can", can_id: number, dlc: number, flags: number, } | { "kind": "rs485", framing_mode: number, } | { "kind": "unknown", meta_len: number, raw: Array<number>, };"#
    );
}

#[test]
fn stream_frame() {
    assert_eq!(
        exported::<StreamFrame>(),
        r#"export type StreamFrame = { timestamp_us: number, iface_index: number, metadata: FrameMetadata, data: Array<number>, };"#
    );
}
