//! Checksum algorithms, and an engine that finds or solves the checksum a set of
//! frames carries. Offsets are end-relative throughout: a negative index counts
//! from the end, the only way frames of different lengths on one link line up.

pub mod algorithms;
pub mod columns;
mod crc32;
pub mod detect;
pub mod frame;
pub mod notes;
pub mod sampling;
pub mod solve;
pub mod spec;

#[cfg(test)]
mod testing;

pub use algorithms::{
    ALL_ALGORITHMS, ChecksumAlgorithm, calculate_checksum_simple, crc8_parameterised,
    crc16_parameterised,
};
pub use columns::{Anchor, ColumnStats, analyse_columns, analyse_columns_from};
pub use crc32::crc32;
pub use detect::{
    CalcRange, ChecksumCandidate, ChecksumDetectionOptions, ChecksumDetectionResult, MAX_SAMPLES,
    MIN_CONFIDENCE, STRONG_MATCH_RATE, build_checksum_specs, calc_ranges, detect_checksum,
    detect_checksum_with_columns, volume_bonus,
};
pub use frame::{
    ChecksumValidationResult, calculate_checksum, calculated_range, extract_checksum,
    resolve_byte_index, validate_checksum,
};
pub use notes::{ALL_NOTES, ChecksumNote, NoteSpec, NoteValue};
pub use sampling::{deduplicate, diverse_samples, strided_samples};
pub use solve::{
    AdditiveOp, CRC_CUSTOM, ChecksumSpecification, CrcAlternative, CrcParameters, CrcSolveOptions,
    SUM8_NEGATED, SolveTarget, SolvedChecksum, all_algorithm_ids, solve_additive, solve_all,
    solve_crc,
};
pub use solve::{AlgorithmWidth, algorithm_widths};
pub use spec::{ChecksumSpec, ChecksumSpecResult, sweep_specs};
