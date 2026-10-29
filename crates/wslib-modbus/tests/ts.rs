//! Each exported type, doc comments and the generator's banner aside, against
//! its pinned declaration.

use ts_rs::{Config, TS};

use wslib_modbus::Finding;
use wslib_modbus::ModbusFrame;
use wslib_modbus::ModbusManifest;
use wslib_modbus::ModbusMeta;
use wslib_modbus::ModbusSignal;
use wslib_modbus::ModbusWrite;
use wslib_modbus::RegisterType;
use wslib_modbus::WriteBank;

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
fn modbus_signal() {
    assert_eq!(
        exported::<ModbusSignal>(),
        r#"import type { DisplayHint } from "./DisplayHint"; import type { Endianness } from "./Endianness"; import type { SignalFormat } from "./SignalFormat"; export type ModbusSignal = { name: string, start_bit: number, bit_length: number, factor: number | null, offset: number | null, unit: string | null, signed: boolean, format: SignalFormat | null, byte_order: Endianness | null, word_order: Endianness | null, enum: { [key in string]: string } | null, display?: DisplayHint | null, };"#
    );
}

#[test]
fn modbus_frame() {
    assert_eq!(
        exported::<ModbusFrame>(),
        r#"import type { ModbusSignal } from "./ModbusSignal"; import type { RegisterType } from "./RegisterType"; export type ModbusFrame = { name: string, register_number: number, register_type: RegisterType, length: number, interval_ms: number, disabled: boolean, node: string | null, device_address: number, signals: Array<ModbusSignal>, };"#
    );
}

#[test]
fn modbus_meta() {
    assert_eq!(
        exported::<ModbusMeta>(),
        r#"import type { Endianness } from "./Endianness"; export type ModbusMeta = { device_address: number, register_base: number, default_interval: number | null, default_byte_order: Endianness | null, default_word_order: Endianness | null, };"#
    );
}

#[test]
fn modbus_manifest() {
    assert_eq!(
        exported::<ModbusManifest>(),
        r#"import type { ModbusFrame } from "./ModbusFrame"; import type { ModbusMeta } from "./ModbusMeta"; export type ModbusManifest = { meta: ModbusMeta, frames: Array<ModbusFrame>, };"#
    );
}

#[test]
fn modbus_write() {
    assert_eq!(
        exported::<ModbusWrite>(),
        r#"import type { WriteBank } from "./WriteBank"; export type ModbusWrite = { bank: WriteBank, address: number, value: number, mask: number, };"#
    );
}

#[test]
fn register_type() {
    assert_eq!(
        exported::<RegisterType>(),
        r#"export type RegisterType = "input" | "holding" | "coil" | "discrete";"#
    );
}

#[test]
fn write_bank() {
    assert_eq!(
        exported::<WriteBank>(),
        r#"export type WriteBank = "holding" | "coil";"#
    );
}

#[test]
fn finding() {
    assert_eq!(
        exported::<Finding>(),
        "export type ValidationError = { field: string, message: string, };"
    );
}
