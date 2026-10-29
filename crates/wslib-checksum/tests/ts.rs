#![cfg(feature = "ts")]
//! Each exported type, doc comments and the generator's banner aside, against
//! its pinned declaration.

use ts_rs::{Config, TS};

use wslib_checksum::AdditiveOp;
use wslib_checksum::AlgorithmWidth;
use wslib_checksum::CalcRange;
use wslib_checksum::ChecksumAlgorithm;
use wslib_checksum::ChecksumCandidate;
use wslib_checksum::ChecksumDetectionOptions;
use wslib_checksum::ChecksumDetectionResult;
use wslib_checksum::ChecksumNote;
use wslib_checksum::ChecksumSpec;
use wslib_checksum::ChecksumSpecResult;
use wslib_checksum::ChecksumSpecification;
use wslib_checksum::ChecksumValidationResult;
use wslib_checksum::ColumnStats;
use wslib_checksum::CrcAlternative;
use wslib_checksum::CrcParameters;
use wslib_checksum::NoteValue;
use wslib_checksum::SolveTarget;
use wslib_checksum::SolvedChecksum;

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
fn checksum_algorithm() {
    assert_eq!(
        exported::<ChecksumAlgorithm>(),
        r#"export type ChecksumAlgorithm = "xor" | "sum8" | "crc8" | "crc8_sae_j1850" | "crc8_autosar" | "crc8_maxim" | "crc8_cdma2000" | "crc8_dvb_s2" | "crc8_nissan" | "crc16_modbus" | "crc16_ccitt";"#
    );
}

#[test]
fn column_stats() {
    assert_eq!(
        exported::<ColumnStats>(),
        "export type ColumnStats = { position: number, distinctValues: number, min: number, max: number, constantValue: number | null, changes: number, transitions: number, entropyBits: number, sampleCount: number, };"
    );
}

#[test]
fn checksum_detection_options() {
    assert_eq!(
        exported::<ChecksumDetectionOptions>(),
        "export type ChecksumDetectionOptions = { positions?: Array<number>, lengths?: Array<number>, headerBoundaries?: Array<number>, minMatchRate?: number, minConfidence?: number, };"
    );
}

#[test]
fn calc_range() {
    assert_eq!(
        exported::<CalcRange>(),
        "export type CalcRange = { calcStartByte: number, calcEndByte: number, };"
    );
}

#[test]
fn checksum_candidate() {
    assert_eq!(
        exported::<ChecksumCandidate>(),
        r#"import type { CalcRange } from "./CalcRange"; import type { ChecksumAlgorithm } from "./ChecksumAlgorithm"; import type { ChecksumNote } from "./ChecksumNote"; export type ChecksumCandidate = { algorithm: ChecksumAlgorithm, position: number, length: number, bigEndian: boolean, calcStartByte: number, calcEndByte: number, matchCount: number, totalCount: number, matchRate: number, confidence: number, notes: Array<ChecksumNote>, equivalentRanges: Array<CalcRange>, };"#
    );
}

#[test]
fn checksum_detection_result() {
    assert_eq!(
        exported::<ChecksumDetectionResult>(),
        r#"import type { ChecksumCandidate } from "./ChecksumCandidate"; import type { ChecksumNote } from "./ChecksumNote"; import type { ColumnStats } from "./ColumnStats"; export type ChecksumDetectionResult = { candidates: Array<ChecksumCandidate>, bestCandidate: ChecksumCandidate | null, tailColumns: Array<ColumnStats>, notes: Array<ChecksumNote>, };"#
    );
}

#[test]
fn checksum_validation_result() {
    assert_eq!(
        exported::<ChecksumValidationResult>(),
        "export type ChecksumValidationResult = { extracted: number, calculated: number, valid: boolean, };"
    );
}

#[test]
fn checksum_note() {
    assert_eq!(
        exported::<ChecksumNote>(),
        "export type ChecksumNote = { code: string, values: { [key in string]: unknown }, };"
    );
}

#[test]
fn algorithm_width() {
    assert_eq!(
        exported::<AlgorithmWidth>(),
        "export type AlgorithmWidth = { id: string, outputBytes: number | null, };"
    );
}

#[test]
fn solve_target() {
    assert_eq!(
        exported::<SolveTarget>(),
        "export type SolveTarget = { position: number, byteLength: number, bigEndian: boolean, calcStartByte: number, calcEndByte: number, };"
    );
}

#[test]
fn additive_op() {
    assert_eq!(
        exported::<AdditiveOp>(),
        r#"export type AdditiveOp = "xor" | "sum" | "negatedSum";"#
    );
}

#[test]
fn crc_alternative() {
    assert_eq!(
        exported::<CrcAlternative>(),
        "export type CrcAlternative = { init: number, xorOut: number, };"
    );
}

#[test]
fn crc_parameters() {
    assert_eq!(
        exported::<CrcParameters>(),
        r#"import type { CrcAlternative } from "./CrcAlternative"; export type CrcParameters = { width: number, polynomial: number, reflectIn: boolean, reflectOut: boolean, init: number, xorOut: number, wellKnown: boolean, alternatives: Array<CrcAlternative>, };"#
    );
}

#[test]
fn checksum_specification() {
    assert_eq!(
        exported::<ChecksumSpecification>(),
        r#"import type { AdditiveOp } from "./AdditiveOp"; import type { ChecksumAlgorithm } from "./ChecksumAlgorithm"; import type { CrcParameters } from "./CrcParameters"; export type ChecksumSpecification = { "kind": "named", algorithm: ChecksumAlgorithm, } | { "kind": "additive", op: AdditiveOp, offset: number, } | { "kind": "crc" } & CrcParameters;"#
    );
}

#[test]
fn solved_checksum() {
    assert_eq!(
        exported::<SolvedChecksum>(),
        r#"import type { AdditiveOp } from "./AdditiveOp"; import type { CalcRange } from "./CalcRange"; import type { ChecksumAlgorithm } from "./ChecksumAlgorithm"; import type { CrcParameters } from "./CrcParameters"; import type { SolveTarget } from "./SolveTarget"; export type SolvedChecksum = { target: SolveTarget, sampleCount: number, excludedCount: number, equivalentRanges: Array<CalcRange>, } & ({ "kind": "named", algorithm: ChecksumAlgorithm, } | { "kind": "additive", op: AdditiveOp, offset: number, } | { "kind": "crc" } & CrcParameters);"#
    );
}

#[test]
fn checksum_spec() {
    assert_eq!(
        exported::<ChecksumSpec>(),
        r#"import type { ChecksumAlgorithm } from "./ChecksumAlgorithm"; export type ChecksumSpec = { algorithm: ChecksumAlgorithm, position: number, byteLength: number, bigEndian: boolean, calcStartByte: number, calcEndByte: number, };"#
    );
}

#[test]
fn checksum_spec_result() {
    assert_eq!(
        exported::<ChecksumSpecResult>(),
        "export type ChecksumSpecResult = { specIndex: number, matchCount: number, totalCount: number, };"
    );
}

#[test]
fn note_value() {
    assert_eq!(
        exported::<NoteValue>(),
        "export type NoteValue = number | string;"
    );
}
