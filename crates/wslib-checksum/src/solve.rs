//! Solving a checksum rather than searching for one: an additive offset in one
//! pass, and a CRC with `init` and `xorOut` folded into one residue.

use serde::{Deserialize, Serialize};

use crate::algorithms::{
    ALL_ALGORITHMS, ChecksumAlgorithm, calculate_checksum_simple, crc8_parameterised,
    crc16_parameterised,
};
use crate::detect::CalcRange;
use crate::frame::{calculated_range, extract_checksum};

/// Well-known polynomials, preferred when several fit equally well.
const KNOWN_CRC8_POLYNOMIALS: [u16; 7] = [0x07, 0x1D, 0x2F, 0x31, 0x9B, 0xD5, 0x85];

const KNOWN_CRC16_POLYNOMIALS: [u16; 8] = [
    0x8005, 0x1021, 0x3D65, 0x8BB7, 0xC867, 0x0589, 0x080D, 0x1DCF,
];

/// The id a recovered CRC is stored under; its parameters travel with it.
pub const CRC_CUSTOM: &str = "crc_custom";

/// The id for a sum negated into two's complement.
pub const SUM8_NEGATED: &str = "sum8_negated";

/// Every algorithm id a stored checksum may use: the eleven named ones and the
/// two the solver recovers.
pub fn all_algorithm_ids() -> Vec<&'static str> {
    ALL_ALGORITHMS
        .iter()
        .map(|a| a.as_str())
        .chain([CRC_CUSTOM, SUM8_NEGATED])
        .collect()
}

/// One stored algorithm id and how many bytes its checksum occupies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(rename_all = "camelCase")]
pub struct AlgorithmWidth {
    pub id: &'static str,
    /// `None` for [`CRC_CUSTOM`] and [`SUM8_NEGATED`], which carry their own.
    pub output_bytes: Option<usize>,
}

/// [`all_algorithm_ids`], in the same order, each with its fixed width.
pub fn algorithm_widths() -> Vec<AlgorithmWidth> {
    all_algorithm_ids()
        .into_iter()
        .map(|id| AlgorithmWidth {
            id,
            output_bytes: id
                .parse::<ChecksumAlgorithm>()
                .ok()
                .map(|a| a.output_bytes()),
        })
        .collect()
}

/// Conventional initial values reported as alternatives.
const CONVENTIONAL_INITS: [u16; 2] = [0x0000, 0xFFFF];

/// Samples needed before a solution means anything.
const MIN_SAMPLES: usize = 3;

/// How many samples the screening pass uses before a full verification.
const SCREEN_SAMPLES: usize = 3;

/// Where the checksum sits and what it is calculated over; the caller chooses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(rename_all = "camelCase")]
pub struct SolveTarget {
    /// Byte offset of the checksum; negative counts from the end.
    pub position: i32,
    pub byte_length: usize,
    pub big_endian: bool,
    pub calc_start_byte: i32,
    pub calc_end_byte: i32,
}

/// The additive families, in the order they are tried.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(rename_all = "camelCase")]
pub enum AdditiveOp {
    /// `observed = XOR(range) ⊕ offset`
    Xor,
    /// `observed = SUM(range) + offset`
    Sum,
    /// `observed = offset − SUM(range)` — the two's-complement shape.
    NegatedSum,
}

/// One conventional `init` and the `xorOut` it implies for this residue.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(rename_all = "camelCase")]
pub struct CrcAlternative {
    pub init: u16,
    pub xor_out: u16,
}

/// A recovered CRC: `init` and `xor_out` are exact but one pair of several that
/// fit; see [`alternatives`](Self::alternatives).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(rename_all = "camelCase")]
pub struct CrcParameters {
    /// 8 or 16.
    pub width: u8,
    pub polynomial: u16,
    pub reflect_in: bool,
    pub reflect_out: bool,
    /// Canonically 0.
    pub init: u16,
    /// The residue `observed ⊕ CRC(m, 0, 0)`, constant across the samples.
    pub xor_out: u16,
    /// True when `polynomial` is a recognised standard.
    pub well_known: bool,
    /// Other `(init, xorOut)` pairs that fit; non-empty means `init` is not
    /// determined by this data.
    pub alternatives: Vec<CrcAlternative>,
}

/// How a checksum is computed: a named algorithm from the sweep, or a family
/// [`solve_additive`] or [`solve_crc`] recovered with its parameters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(rename_all = "camelCase", tag = "kind")]
pub enum ChecksumSpecification {
    Named { algorithm: ChecksumAlgorithm },
    Additive { op: AdditiveOp, offset: u8 },
    Crc(CrcParameters),
}

/// A specification's identity, ignoring the offset or residue a constant range
/// absorbs. Built by an exhaustive match, so a new family can't skip the fold.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum ChecksumFamily {
    Named(ChecksumAlgorithm),
    Additive(AdditiveOp),
    /// Width, polynomial and reflections, without the residue a range moves.
    Crc {
        width: u8,
        polynomial: u16,
        reflect_in: bool,
        reflect_out: bool,
    },
}

impl ChecksumSpecification {
    pub(crate) fn family(&self) -> ChecksumFamily {
        match self {
            Self::Named { algorithm } => ChecksumFamily::Named(*algorithm),
            Self::Additive { op, .. } => ChecksumFamily::Additive(*op),
            Self::Crc(crc) => ChecksumFamily::Crc {
                width: crc.width,
                polynomial: crc.polynomial,
                reflect_in: crc.reflect_in,
                reflect_out: crc.reflect_out,
            },
        }
    }
}

impl ChecksumSpecification {
    /// The algorithm id this serialises as.
    pub fn algorithm_id(&self) -> &'static str {
        match self {
            Self::Named { algorithm } => algorithm.as_str(),
            Self::Additive { op, .. } => match op {
                AdditiveOp::Xor => ChecksumAlgorithm::Xor.as_str(),
                AdditiveOp::Sum => ChecksumAlgorithm::Sum8.as_str(),
                AdditiveOp::NegatedSum => SUM8_NEGATED,
            },
            Self::Crc(_) => CRC_CUSTOM,
        }
    }

    /// This configuration applied to the bytes it is calculated over; an offset
    /// sum stored as `sum8` is only reproduced with its parameters.
    pub fn calculate(&self, data: &[u8]) -> u16 {
        match self {
            Self::Named { algorithm } => calculate_checksum_simple(*algorithm, data),
            Self::Additive { op, offset } => {
                let value = match op {
                    AdditiveOp::Xor => data.iter().fold(0u8, |a, b| a ^ b) ^ *offset,
                    AdditiveOp::Sum => data
                        .iter()
                        .fold(0u8, |a, b| a.wrapping_add(*b))
                        .wrapping_add(*offset),
                    AdditiveOp::NegatedSum => {
                        offset.wrapping_sub(data.iter().fold(0u8, |a, b| a.wrapping_add(*b)))
                    }
                };
                value as u16
            }
            Self::Crc(crc) => {
                if crc.width == 8 {
                    crc8_parameterised(
                        data,
                        crc.polynomial as u8,
                        crc.init as u8,
                        crc.xor_out as u8,
                        crc.reflect_in,
                    ) as u16
                } else {
                    crc16_parameterised(
                        data,
                        crc.polynomial,
                        crc.init,
                        crc.xor_out,
                        crc.reflect_in,
                        crc.reflect_out,
                    )
                }
            }
        }
    }

    /// Whether one of the eleven named algorithms already expresses this.
    pub fn is_expressible_by_sweep(&self) -> bool {
        match self {
            Self::Named { .. } => true,
            Self::Additive { op, offset } => {
                *offset == 0 && matches!(op, AdditiveOp::Xor | AdditiveOp::Sum)
            }
            Self::Crc(_) => false,
        }
    }
}

/// A configuration that reproduces every sample it was solved against.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(rename_all = "camelCase")]
pub struct SolvedChecksum {
    pub target: SolveTarget,
    #[serde(flatten)]
    pub specification: ChecksumSpecification,
    /// Samples the solution was verified against; it reproduces all of them.
    pub sample_count: usize,
    /// Samples excluded for a calculation range of another length.
    pub excluded_count: usize,
    /// Ranges that explain the samples equally well, the bytes between them
    /// never changing.
    pub equivalent_ranges: Vec<CalcRange>,
}

#[derive(Debug, Clone)]
pub struct CrcSolveOptions {
    /// Test only the recognised standards.
    pub known_polynomials_only: bool,
    /// Cap on returned solutions.
    pub max_solutions: usize,
}

impl Default for CrcSolveOptions {
    fn default() -> Self {
        Self {
            known_polynomials_only: false,
            max_solutions: 8,
        }
    }
}

/// One sample: the bytes under the calculation range, and the stored checksum.
struct Observation {
    data: Vec<u8>,
    observed: u16,
}

fn observations(frames: &[Vec<u8>], target: &SolveTarget) -> Vec<Observation> {
    frames
        .iter()
        .filter_map(|frame| {
            let range = calculated_range(
                frame.len(),
                target.position,
                target.byte_length,
                target.calc_start_byte,
                target.calc_end_byte,
            )?;
            Some(Observation {
                data: frame[range].to_vec(),
                observed: extract_checksum(
                    frame,
                    target.position,
                    target.byte_length,
                    target.big_endian,
                )?,
            })
        })
        .collect()
}

/// The additive or XOR checksum that fits, if one does, in one pass per family.
pub fn solve_additive(frames: &[Vec<u8>], target: &SolveTarget) -> Option<SolvedChecksum> {
    if target.byte_length != 1 {
        return None;
    }

    let samples = observations(frames, target);
    if samples.len() < MIN_SAMPLES {
        return None;
    }

    let residue = |op: AdditiveOp, sample: &Observation| -> u8 {
        let observed = sample.observed as u8;
        match op {
            AdditiveOp::Xor => observed ^ sample.data.iter().fold(0u8, |a, b| a ^ b),
            AdditiveOp::Sum => {
                observed.wrapping_sub(sample.data.iter().fold(0u8, |a, b| a.wrapping_add(*b)))
            }
            AdditiveOp::NegatedSum => {
                observed.wrapping_add(sample.data.iter().fold(0u8, |a, b| a.wrapping_add(*b)))
            }
        }
    };

    [AdditiveOp::Xor, AdditiveOp::Sum, AdditiveOp::NegatedSum]
        .into_iter()
        .find_map(|op| {
            let offset = residue(op, &samples[0]);
            samples[1..]
                .iter()
                .all(|s| residue(op, s) == offset)
                .then_some(SolvedChecksum {
                    target: *target,
                    specification: ChecksumSpecification::Additive { op, offset },
                    sample_count: samples.len(),
                    excluded_count: 0,
                    equivalent_ranges: Vec::new(),
                })
        })
}

/// `CRC(data, init = 0, xorOut = 0)`, the linear part.
fn crc_zeroed(data: &[u8], width: u8, polynomial: u16, reflect_in: bool, reflect_out: bool) -> u16 {
    if width == 8 {
        crc8_parameterised(data, polynomial as u8, 0, 0, reflect_in) as u16
    } else {
        crc16_parameterised(data, polynomial, 0, 0, reflect_in, reflect_out)
    }
}

/// The reflection combinations worth testing: CRC-8 couples input and output.
fn reflection_combinations(width: u8) -> Vec<(bool, bool)> {
    if width == 8 {
        vec![(false, false), (true, true)]
    } else {
        vec![(false, false), (true, true), (true, false), (false, true)]
    }
}

/// The residue shared by every sample, or `None` if the polynomial is wrong.
fn shared_residue(
    samples: &[&Observation],
    width: u8,
    polynomial: u16,
    reflect_in: bool,
    reflect_out: bool,
) -> Option<u16> {
    let mut residue = None;
    for sample in samples {
        let k =
            sample.observed ^ crc_zeroed(&sample.data, width, polynomial, reflect_in, reflect_out);
        match residue {
            None => residue = Some(k),
            Some(existing) if existing == k => {}
            Some(_) => return None,
        }
    }
    residue
}

/// Recover a CRC's polynomial by residue agreement, over the largest group of
/// samples with one range length; the rest are `excluded_count`.
pub fn solve_crc(
    frames: &[Vec<u8>],
    target: &SolveTarget,
    options: &CrcSolveOptions,
) -> Vec<SolvedChecksum> {
    let width = match target.byte_length {
        1 => 8u8,
        2 => 16u8,
        _ => return Vec::new(),
    };

    let all = observations(frames, target);
    let Some(length) = largest_length_group(&all) else {
        return Vec::new();
    };
    let samples: Vec<&Observation> = all.iter().filter(|s| s.data.len() == length).collect();
    if samples.len() < MIN_SAMPLES {
        return Vec::new();
    }

    let known: &[u16] = if width == 8 {
        &KNOWN_CRC8_POLYNOMIALS
    } else {
        &KNOWN_CRC16_POLYNOMIALS
    };
    let polynomials: Vec<u16> = if options.known_polynomials_only {
        known.to_vec()
    } else {
        let last = if width == 8 { 0xFF } else { 0xFFFF };
        (1..=last).collect()
    };

    // A wrong polynomial disagrees on the second sample with probability 1 − 2⁻ʷ.
    let screen = &samples[..samples.len().min(SCREEN_SAMPLES)];
    let samples = &samples[..];

    let mut solutions: Vec<CrcParameters> = parallel_flat_map(&polynomials, |&polynomial| {
        reflection_combinations(width)
            .into_iter()
            .filter_map(move |(reflect_in, reflect_out)| {
                shared_residue(screen, width, polynomial, reflect_in, reflect_out)?;
                let residue = shared_residue(samples, width, polynomial, reflect_in, reflect_out)?;
                Some(CrcParameters {
                    width,
                    polynomial,
                    reflect_in,
                    reflect_out,
                    init: 0,
                    xor_out: residue,
                    well_known: known.contains(&polynomial),
                    alternatives: conventional_alternatives(
                        width,
                        polynomial,
                        reflect_in,
                        reflect_out,
                        length,
                        residue,
                    ),
                })
            })
            .collect()
    });

    solutions.sort_by_key(|s| (!s.well_known, s.polynomial, s.reflect_in, s.reflect_out));
    solutions.truncate(options.max_solutions);

    solutions
        .into_iter()
        .map(|crc| SolvedChecksum {
            target: *target,
            specification: ChecksumSpecification::Crc(crc),
            sample_count: samples.len(),
            excluded_count: all.len() - samples.len(),
            equivalent_ranges: Vec::new(),
        })
        .collect()
}

/// Solve every target, folding the spellings of one answer that ranges
/// differing only in constant bytes produce. The entry point to use.
pub fn solve_all(
    frames: &[Vec<u8>],
    targets: &[SolveTarget],
    options: &CrcSolveOptions,
) -> Vec<SolvedChecksum> {
    let solutions = targets
        .iter()
        .flat_map(|target| {
            solve_additive(frames, target)
                .into_iter()
                .chain(solve_crc(frames, target, options))
        })
        .collect();
    collapse_solved(solutions)
}

/// Fold solutions that differ only in a range the data cannot tell apart; the
/// widest range wins.
fn collapse_solved(mut solutions: Vec<SolvedChecksum>) -> Vec<SolvedChecksum> {
    solutions.sort_by(|a, b| {
        a.target
            .calc_start_byte
            .cmp(&b.target.calc_start_byte)
            .then_with(|| b.target.calc_end_byte.cmp(&a.target.calc_end_byte))
    });

    let mut kept: Vec<SolvedChecksum> = Vec::new();
    for solution in solutions {
        let same = |k: &SolvedChecksum| {
            k.target.position == solution.target.position
                && k.target.byte_length == solution.target.byte_length
                && k.target.big_endian == solution.target.big_endian
                && k.specification.family() == solution.specification.family()
        };
        match kept.iter_mut().find(|k| same(k)) {
            Some(winner) => winner.equivalent_ranges.push(CalcRange {
                calc_start_byte: solution.target.calc_start_byte,
                calc_end_byte: solution.target.calc_end_byte,
            }),
            None => kept.push(solution),
        }
    }
    kept
}

fn largest_length_group(samples: &[Observation]) -> Option<usize> {
    let mut counts: std::collections::HashMap<usize, usize> = std::collections::HashMap::new();
    for sample in samples {
        *counts.entry(sample.data.len()).or_default() += 1;
    }
    counts
        .into_iter()
        .max_by_key(|(length, count)| (*count, *length))
        .map(|(length, _)| length)
}

/// `xorOut` for each conventional `init`: `K ⊕ CRC(zeros_L, init, 0)`.
fn conventional_alternatives(
    width: u8,
    polynomial: u16,
    reflect_in: bool,
    reflect_out: bool,
    length: usize,
    residue: u16,
) -> Vec<CrcAlternative> {
    let zeros = vec![0u8; length];
    let mask = if width == 8 { 0x00FF } else { 0xFFFF };

    CONVENTIONAL_INITS
        .iter()
        .map(|init| init & mask)
        .filter(|init| *init != 0)
        .map(|init| {
            let carried = if width == 8 {
                crc8_parameterised(&zeros, polynomial as u8, init as u8, 0, reflect_in) as u16
            } else {
                crc16_parameterised(&zeros, polynomial, init, 0, reflect_in, reflect_out)
            };
            CrcAlternative {
                init,
                xor_out: residue ^ carried,
            }
        })
        .collect()
}

/// `f` over `items` on scoped threads, results in `items`' order. Small inputs
/// run inline: a thread costs more than a few hundred CRCs.
fn parallel_flat_map<T: Sync, R: Send>(items: &[T], f: impl Fn(&T) -> Vec<R> + Sync) -> Vec<R> {
    const MIN_PER_THREAD: usize = 256;
    let threads = std::thread::available_parallelism()
        .map_or(1, |n| n.get())
        .min(items.len() / MIN_PER_THREAD + 1);
    if threads == 1 {
        return items.iter().flat_map(&f).collect();
    }
    let f = &f;
    std::thread::scope(|scope| {
        let workers: Vec<_> = items
            .chunks(items.len().div_ceil(threads))
            .map(|chunk| scope.spawn(move || chunk.iter().flat_map(f).collect::<Vec<_>>()))
            .collect();
        workers
            .into_iter()
            .flat_map(|worker| worker.join().unwrap())
            .collect()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_parallel_map_keeps_the_input_order() {
        let items: Vec<u32> = (0..10_000).collect();
        let doubled = parallel_flat_map(&items, |&n| vec![n, n]);
        let expected: Vec<u32> = items.iter().flat_map(|&n| [n, n]).collect();
        assert_eq!(doubled, expected);
    }
    use crate::algorithms::{crc8_checksum, crc16_modbus_checksum, sum8_checksum, xor_checksum};

    /// A checksum at the last byte, calculated over everything before it.
    const TRAILING_BYTE: SolveTarget = SolveTarget {
        position: -1,
        byte_length: 1,
        big_endian: true,
        calc_start_byte: 0,
        calc_end_byte: -1,
    };

    const TRAILING_WORD: SolveTarget = SolveTarget {
        position: -2,
        byte_length: 2,
        big_endian: false,
        calc_start_byte: 0,
        calc_end_byte: -2,
    };

    /// Payloads with a checksum appended by `f`. Deliberately varied so a wrong
    /// candidate has somewhere to disagree.
    fn frames_with<F: Fn(&[u8]) -> u8>(count: u32, f: F) -> Vec<Vec<u8>> {
        (0..count)
            .map(|i| {
                let mut body = vec![
                    0x10,
                    i as u8,
                    (i >> 8) as u8,
                    (i.wrapping_mul(37) ^ 0x5A) as u8,
                    (i.wrapping_mul(211)) as u8,
                    0xC3,
                    (i.wrapping_mul(7) ^ 0xF0) as u8,
                ];
                let checksum = f(&body);
                body.push(checksum);
                body
            })
            .collect()
    }

    /// The one CRC a solve is expected to find. Panics on an empty result so a
    /// failure reads as "found nothing" rather than an index panic.
    fn only_crc(solved: &[SolvedChecksum]) -> CrcParameters {
        match solved.first().map(|s| &s.specification) {
            Some(ChecksumSpecification::Crc(crc)) => crc.clone(),
            other => panic!("expected a CRC, got {other:?}"),
        }
    }

    #[test]
    fn test_solve_additive_finds_a_plain_sum() {
        let solved = solve_additive(&frames_with(40, sum8_checksum), &TRAILING_BYTE).unwrap();
        assert_eq!(
            solved.specification,
            ChecksumSpecification::Additive {
                op: AdditiveOp::Sum,
                offset: 0
            }
        );
        assert_eq!(solved.sample_count, 40);
    }

    #[test]
    fn test_solve_additive_finds_a_plain_xor() {
        let solved = solve_additive(&frames_with(40, xor_checksum), &TRAILING_BYTE).unwrap();
        assert_eq!(
            solved.specification,
            ChecksumSpecification::Additive {
                op: AdditiveOp::Xor,
                offset: 0
            }
        );
    }

    /// The variant the fixed eleven-algorithm list cannot express, and the
    /// reason this is a solve rather than a sweep.
    #[test]
    fn test_solve_additive_finds_a_sum_with_a_constant_offset() {
        let frames = frames_with(40, |d| sum8_checksum(d).wrapping_add(0xA5));
        let solved = solve_additive(&frames, &TRAILING_BYTE).unwrap();
        assert_eq!(
            solved.specification,
            ChecksumSpecification::Additive {
                op: AdditiveOp::Sum,
                offset: 0xA5
            }
        );
    }

    #[test]
    fn test_solve_additive_finds_a_twos_complement_sum() {
        let frames = frames_with(40, |d| sum8_checksum(d).wrapping_neg());
        let solved = solve_additive(&frames, &TRAILING_BYTE).unwrap();
        assert_eq!(
            solved.specification,
            ChecksumSpecification::Additive {
                op: AdditiveOp::NegatedSum,
                offset: 0
            }
        );
    }

    #[test]
    fn test_solve_additive_rejects_a_crc() {
        assert!(solve_additive(&frames_with(40, crc8_checksum), &TRAILING_BYTE).is_none());
    }

    #[test]
    fn test_solve_additive_needs_more_than_a_couple_of_samples() {
        assert!(solve_additive(&frames_with(2, sum8_checksum), &TRAILING_BYTE).is_none());
    }

    #[test]
    fn test_solve_crc_recovers_a_named_crc8() {
        let crc = only_crc(&solve_crc(
            &frames_with(40, crc8_checksum),
            &TRAILING_BYTE,
            &Default::default(),
        ));

        assert_eq!(crc.polynomial, 0x07);
        assert!(!crc.reflect_in);
        assert!(crc.well_known);
        // init 0, xorOut 0 for this one, so the residue is 0.
        assert_eq!(crc.xor_out, 0x0000);
    }

    /// The point of the whole exercise: a polynomial nobody catalogued, with a
    /// non-zero init and xorOut, recovered without enumerating either.
    #[test]
    fn test_solve_crc_recovers_an_arbitrary_polynomial() {
        let frames = frames_with(60, |d| crc8_parameterised(d, 0x4D, 0xB7, 0x2C, false));
        let crc = only_crc(&solve_crc(&frames, &TRAILING_BYTE, &Default::default()));
        assert_eq!(crc.polynomial, 0x4D);
        assert!(!crc.well_known);

        // The canonical form must reproduce the capture exactly.
        for frame in &frames {
            let body = &frame[..frame.len() - 1];
            let reproduced = crc8_parameterised(
                body,
                crc.polynomial as u8,
                crc.init as u8,
                crc.xor_out as u8,
                crc.reflect_in,
            );
            assert_eq!(reproduced, *frame.last().unwrap());
        }
    }

    #[test]
    fn test_solve_crc_recovers_a_reflected_polynomial() {
        let frames = frames_with(60, |d| crc8_parameterised(d, 0x31, 0x00, 0x00, true));
        let crc = only_crc(&solve_crc(&frames, &TRAILING_BYTE, &Default::default()));

        assert_eq!(crc.polynomial, 0x31);
        assert!(crc.reflect_in);
    }

    #[test]
    fn test_solve_crc_recovers_a_16_bit_polynomial() {
        let frames: Vec<Vec<u8>> = (0..60u32)
            .map(|i| {
                let mut body = vec![
                    0x02,
                    i as u8,
                    (i >> 8) as u8,
                    (i.wrapping_mul(97)) as u8,
                    0x11,
                ];
                let crc = crc16_modbus_checksum(&body);
                body.push((crc & 0xFF) as u8);
                body.push((crc >> 8) as u8);
                body
            })
            .collect();

        let crc = only_crc(&solve_crc(&frames, &TRAILING_WORD, &Default::default()));
        assert_eq!(crc.polynomial, 0x8005);
        assert!(crc.reflect_in);
        assert!(crc.well_known);
    }

    /// `init` and `xorOut` are not separately identifiable from fixed-length
    /// payloads, and the result has to say so rather than pick one.
    #[test]
    fn test_solve_crc_offers_the_conventional_inits_as_alternatives() {
        let frames = frames_with(40, |d| crc8_parameterised(d, 0x1D, 0xFF, 0xFF, false));
        let crc = only_crc(&solve_crc(&frames, &TRAILING_BYTE, &Default::default()));

        assert_eq!(crc.polynomial, 0x1D);
        assert_eq!(crc.init, 0);

        let alternative = crc.alternatives.iter().find(|a| a.init == 0xFF).unwrap();
        // Both pairs must reproduce the capture; neither is more true.
        for frame in &frames {
            let body = &frame[..frame.len() - 1];
            assert_eq!(
                crc8_parameterised(body, 0x1D, 0x00, crc.xor_out as u8, false),
                *frame.last().unwrap()
            );
            assert_eq!(
                crc8_parameterised(body, 0x1D, 0xFF, alternative.xor_out as u8, false),
                *frame.last().unwrap()
            );
        }
    }

    #[test]
    fn test_solve_crc_finds_nothing_in_noise() {
        let frames: Vec<Vec<u8>> = (0..60u32)
            .map(|i| {
                vec![
                    0x10,
                    i as u8,
                    (i.wrapping_mul(37)) as u8,
                    (i.wrapping_mul(91) ^ 0x3C) as u8,
                ]
            })
            .collect();

        assert!(solve_crc(&frames, &TRAILING_BYTE, &Default::default()).is_empty());
    }

    #[test]
    fn test_solve_crc_excludes_samples_of_a_different_range_length() {
        let mut frames = frames_with(40, crc8_checksum);
        // A short frame on the same link: a different calculation length, so a
        // different residue, so not evidence about this one.
        frames.push(vec![0x10, 0x20, 0x30]);

        let solved = solve_crc(&frames, &TRAILING_BYTE, &Default::default());
        assert_eq!(solved[0].sample_count, 40);
        assert_eq!(solved[0].excluded_count, 1);
        assert_eq!(only_crc(&solved).polynomial, 0x07);
    }

    #[test]
    fn test_solve_crc_honours_the_known_only_option() {
        let frames = frames_with(60, |d| crc8_parameterised(d, 0x4D, 0xB7, 0x2C, false));
        let options = CrcSolveOptions {
            known_polynomials_only: true,
            ..Default::default()
        };

        assert!(solve_crc(&frames, &TRAILING_BYTE, &options).is_empty());
        assert!(!solve_crc(&frames, &TRAILING_BYTE, &Default::default()).is_empty());
    }

    /// A constant prefix cancels in the residue just as `init` does, so the
    /// frame id being inside or outside the calculation changes the residue but
    /// never the polynomial.
    #[test]
    fn test_solve_crc_is_indifferent_to_a_constant_prefix() {
        let frames = frames_with(40, crc8_checksum);
        let prefixed: Vec<Vec<u8>> = frames
            .iter()
            .map(|f| [&[0x07u8, 0x01][..], f].concat())
            .collect();

        let bare = only_crc(&solve_crc(&frames, &TRAILING_BYTE, &Default::default())).polynomial;
        let with_prefix =
            only_crc(&solve_crc(&prefixed, &TRAILING_BYTE, &Default::default())).polynomial;

        assert_eq!(bare, with_prefix);
    }

    /// Every start solves when the bytes they differ by never change, because a
    /// constant range is absorbed — into the offset here. One answer, and it
    /// must come back as one.
    #[test]
    fn test_solve_all_folds_ranges_the_data_cannot_tell_apart() {
        // Bytes 0 and 1 are constant, so starts 0, 1 and 2 all reproduce the
        // frames with a different offset each.
        let frames: Vec<Vec<u8>> = (0..40u32)
            .map(|i| {
                let mut body = vec![0x10, 0x20, i as u8, (i.wrapping_mul(37) ^ 0x5A) as u8];
                body.push(sum8_checksum(&body).wrapping_add(0xA5));
                body
            })
            .collect();

        let targets: Vec<SolveTarget> = [0, 1, 2]
            .iter()
            .map(|start| SolveTarget {
                calc_start_byte: *start,
                ..TRAILING_BYTE
            })
            .collect();

        let solved = solve_all(&frames, &targets, &Default::default());
        assert_eq!(
            solved.len(),
            1,
            "one answer, {} ways: {solved:?}",
            solved.len()
        );
        // The widest range wins; the others are kept rather than dropped,
        // because none of them is more true than another.
        assert_eq!(solved[0].target.calc_start_byte, 0);
        assert_eq!(
            solved[0].specification,
            ChecksumSpecification::Additive {
                op: AdditiveOp::Sum,
                offset: 0xA5
            }
        );
        let starts: Vec<i32> = solved[0]
            .equivalent_ranges
            .iter()
            .map(|r| r.calc_start_byte)
            .collect();
        assert_eq!(starts, vec![1, 2]);
    }

    /// The other direction, and the reason the wider range space exists: a
    /// leading byte that *moves* is not absorbed, so only the range excluding it
    /// solves and there is nothing to be ambiguous about.
    #[test]
    fn test_solve_all_keeps_the_one_range_that_fits_when_the_prefix_moves() {
        let frames: Vec<Vec<u8>> = (0..40u32)
            .map(|i| {
                let mut body = vec![(i % 7) as u8, i as u8, (i.wrapping_mul(37) ^ 0x5A) as u8];
                body.push(sum8_checksum(&body[1..]));
                body
            })
            .collect();

        let targets: Vec<SolveTarget> = [0, 1, 2]
            .iter()
            .map(|start| SolveTarget {
                calc_start_byte: *start,
                ..TRAILING_BYTE
            })
            .collect();

        let solved = solve_all(&frames, &targets, &Default::default());
        assert_eq!(solved.len(), 1, "{solved:?}");
        assert_eq!(solved[0].target.calc_start_byte, 1);
        assert!(solved[0].equivalent_ranges.is_empty());
    }

    /// Two genuinely different explanations must stay two. `family()` keys the
    /// fold, so a different polynomial is a different answer however similar the
    /// geometry.
    #[test]
    fn test_collapse_keeps_different_families_apart() {
        let frames = frames_with(40, crc8_checksum);
        let solved = solve_all(&frames, &[TRAILING_BYTE], &Default::default());
        let families: std::collections::HashSet<_> =
            solved.iter().map(|s| s.specification.family()).collect();

        assert_eq!(families.len(), solved.len(), "{solved:?}");
    }

    /// An exhaustive 16-bit sweep is 262,140 candidates.
    #[test]
    fn test_solve_crc16_exhaustive_sweep_is_fast() {
        let frames: Vec<Vec<u8>> = (0..200u32)
            .map(|i| {
                let mut body = vec![
                    0x02,
                    i as u8,
                    (i >> 8) as u8,
                    (i.wrapping_mul(97)) as u8,
                    0x11,
                ];
                let crc = crc16_parameterised(&body, 0x9EB2, 0x1234, 0x5678, false, false);
                body.push((crc & 0xFF) as u8);
                body.push((crc >> 8) as u8);
                body
            })
            .collect();

        let start = std::time::Instant::now();
        let solved = solve_crc(&frames, &TRAILING_WORD, &Default::default());
        let elapsed = start.elapsed();

        assert_eq!(only_crc(&solved).polynomial, 0x9EB2);
        assert!(
            elapsed < std::time::Duration::from_secs(5),
            "exhaustive CRC-16 sweep took {elapsed:?}"
        );
    }
}
