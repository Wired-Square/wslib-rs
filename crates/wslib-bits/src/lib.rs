//! Bits and bytes of a payload: fields cut by bit position and order, word
//! swaps, hex, register readings and value formatting.

pub mod field;
pub mod frame_id;
pub mod groups;
pub mod hex;
pub mod register;
mod signal;

pub use field::{PayloadField, ScaledField};
#[cfg(feature = "display")]
pub use signal::DisplayHint;
pub use signal::SignalFormat;

#[cfg(feature = "decimal")]
use rust_decimal::Decimal;
#[cfg(feature = "decimal")]
use rust_decimal::prelude::FromPrimitive;
use serde::{Deserialize, Serialize};

/// Byte or word order: `Big` is high-order first, `Little` swapped ("CDAB" for
/// words).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(rename_all = "lowercase")]
pub enum Endianness {
    Big,
    Little,
}

/// A bit field as an `f64`, honouring byte order and sign; exact up to 64 bits,
/// and NaN past 128.
pub fn extract_bits(
    bytes: &[u8],
    start_bit: u32,
    bit_length: u32,
    endian: Endianness,
    signed: bool,
) -> f64 {
    match bit_length {
        0 => return 0.0,
        129.. => return f64::NAN,
        _ => {}
    }
    let mut bits: Vec<bool> = bit_walk(bytes, endian)
        .skip(start_bit as usize)
        .take(bit_length as usize)
        .map(|(_, bit)| bit)
        .collect();
    if endian == Endianness::Little {
        bits.reverse();
    }
    let value = bits
        .into_iter()
        .fold(0u128, |value, bit| (value << 1) | u128::from(bit));
    if signed {
        let unused = 128 - bit_length;
        return ((value << unused) as i128 >> unused) as f64;
    }
    value as f64
}

/// Each bit of `bytes` in the order [`extract_bits`] reads them, with its
/// position (`byte * 8 + bit`, bit 0 least significant): big walks each byte
/// from bit 7 down, little from bit 0 up.
pub(crate) fn bit_walk(
    bytes: &[u8],
    endian: Endianness,
) -> impl Iterator<Item = (usize, bool)> + '_ {
    (0..bytes.len() * 8).map(move |i| {
        let position = match endian {
            Endianness::Big => i / 8 * 8 + 7 - i % 8,
            Endianness::Little => i,
        };
        (position, bytes[position / 8] >> (position % 8) & 1 == 1)
    })
}

/// Reverses the 16-bit words within a field's byte span, low word first to high
/// word first ("CDAB").
pub fn apply_word_swap(bytes: &mut [u8], start_bit: u32, bit_length: u32) {
    let start_byte = (start_bit / 8) as usize;
    let num_bytes = bit_length.div_ceil(8) as usize;
    let num_words = num_bytes.div_ceil(2);
    let mut words: Vec<(u8, u8)> = Vec::with_capacity(num_words);
    for i in 0..num_words {
        let idx = start_byte + i * 2;
        let a = bytes.get(idx).copied().unwrap_or(0);
        let b = bytes.get(idx + 1).copied().unwrap_or(0);
        words.push((a, b));
    }
    words.reverse();
    for (i, (a, b)) in words.into_iter().enumerate() {
        let idx = start_byte + i * 2;
        if idx < bytes.len() {
            bytes[idx] = a;
        }
        if idx + 1 < bytes.len() {
            bytes[idx + 1] = b;
        }
    }
}

/// How a data block's bits are ordered: a register bank's, which a signal may
/// override, or a coil bank's, eight to a byte, least significant bit first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BitOrder {
    Registers {
        endianness: Endianness,
        word_order: Option<Endianness>,
    },
    Coils,
}

impl BitOrder {
    /// The byte order bits are read in.
    pub fn endianness(self) -> Endianness {
        match self {
            BitOrder::Registers { endianness, .. } => endianness,
            BitOrder::Coils => Endianness::Little,
        }
    }

    /// Apply a signal's own orders. Only a register bank has any to override.
    pub fn with_overrides(
        self,
        endianness: Option<Endianness>,
        word_order: Option<Endianness>,
    ) -> Self {
        match self {
            BitOrder::Registers {
                endianness: e,
                word_order: w,
            } => BitOrder::Registers {
                endianness: endianness.unwrap_or(e),
                word_order: word_order.or(w),
            },
            BitOrder::Coils => BitOrder::Coils,
        }
    }
}

/// A signal's raw bits in its bank's ordering, words swapped only for a register
/// bank in little word order, past one register's width.
pub fn extract_field(
    bytes: &[u8],
    start_bit: u32,
    bit_length: u32,
    order: BitOrder,
    signed: bool,
) -> f64 {
    let swap = matches!(
        order,
        BitOrder::Registers {
            word_order: Some(Endianness::Little),
            ..
        }
    ) && bit_length > 16;
    if swap {
        // The swap needs a mutable copy; otherwise read the caller's buffer.
        let mut swapped = bytes.to_vec();
        apply_word_swap(&mut swapped, start_bit, bit_length);
        return extract_bits(&swapped, start_bit, bit_length, order.endianness(), signed);
    }
    extract_bits(bytes, start_bit, bit_length, order.endianness(), signed)
}

/// `raw × factor + offset` (×1 +0 by default) in exact `Decimal`, so `3374 ×
/// 0.1` is `337.4`; `None` when an input is non-finite or the result leaves
/// `Decimal`'s range.
#[cfg(feature = "decimal")]
pub fn scale(raw: f64, factor: Option<f64>, offset: Option<f64>) -> Option<Decimal> {
    let factor = factor.map_or(Some(Decimal::ONE), to_decimal)?;
    let offset = offset.map_or(Some(Decimal::ZERO), to_decimal)?;
    to_decimal(raw)?.checked_mul(factor)?.checked_add(offset)
}

/// `from_f64` rounds a magnitude below ~1e-28 to zero rather than refusing it.
#[cfg(feature = "decimal")]
fn to_decimal(x: f64) -> Option<Decimal> {
    Decimal::from_f64(x).filter(|d| !d.is_zero() || x == 0.0)
}

/// A `Decimal` without trailing zeros: `55.50` as `"55.5"`.
#[cfg(feature = "decimal")]
#[deprecated(
    since = "0.1.2",
    note = "use `wslib_quantity::format_decimal(value, Precision::Exact)` from the wslib-quantity crate"
)]
pub fn format_decimal(value: Decimal) -> String {
    value.normalize().to_string()
}

/// A raw value as spaced hex bytes (`"1A 2B 3C"`), most significant first for
/// big endian.
pub fn format_hex(value: f64, bit_length: u32, endian: Endianness) -> String {
    let num_bytes = bit_length.div_ceil(8).max(1) as usize;
    let mask: u128 = if bit_length >= 128 {
        u128::MAX
    } else {
        (1u128 << bit_length) - 1
    };
    let mut v = (value as i128 as u128) & mask;
    let mut bytes = Vec::with_capacity(num_bytes);
    for _ in 0..num_bytes {
        bytes.push((v & 0xff) as u8);
        v >>= 8;
    }
    if endian == Endianness::Big {
        bytes.reverse();
    }
    bytes
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(" ")
}

/// The bytes a text field spans as a string, NULs dropped.
pub fn decode_text(bytes: &[u8], start_bit: u32, bit_length: u32) -> String {
    let start_byte = (start_bit / 8) as usize;
    let num_bytes = bit_length.div_ceil(8) as usize;
    let mut out = String::new();
    for i in 0..num_bytes {
        let b = bytes.get(start_byte + i).copied().unwrap_or(0);
        if b != 0 {
            out.push(b as char);
        }
    }
    out
}

/// A byte as its character, or `.` outside printable ASCII.
pub(crate) fn printable(byte: u8) -> char {
    if (0x20..=0x7e).contains(&byte) {
        byte as char
    } else {
        '.'
    }
}

/// A unix timestamp as `YYYY-MM-DD HH:MM:SS` UTC; a value past the year 3000 in
/// seconds is read as milliseconds.
pub fn format_unix_time(value: f64) -> String {
    if !value.is_finite() {
        return format!("Invalid ({value})");
    }
    let secs = if value > 32_503_680_000.0 {
        (value / 1000.0) as i64
    } else {
        value as i64
    };
    let (y, mo, d, h, mi, s) = civil_from_unix(secs);
    format!("{y:04}-{mo:02}-{d:02} {h:02}:{mi:02}:{s:02}")
}

/// Howard Hinnant's days-to-civil algorithm, proleptic Gregorian.
fn civil_from_unix(secs: i64) -> (i64, u32, u32, u32, u32, u32) {
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (h, mi, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);

    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let year = if m <= 2 { y + 1 } else { y };
    (year, m, d, h as u32, mi as u32, s as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn big_endian_reads_the_first_byte_as_most_significant() {
        // 0x1234 over 16 bits, big endian.
        assert_eq!(
            extract_bits(&[0x12, 0x34], 0, 16, Endianness::Big, false),
            0x1234 as f64
        );
    }

    #[test]
    fn little_endian_reads_the_first_byte_as_least_significant() {
        assert_eq!(
            extract_bits(&[0x34, 0x12], 0, 16, Endianness::Little, false),
            0x1234 as f64
        );
    }

    #[test]
    fn an_unaligned_field_reads_across_the_byte_boundary() {
        assert_eq!(
            extract_bits(&[0xE8, 0x08], 3, 8, Endianness::Big, false),
            0x40 as f64
        );
        assert_eq!(
            extract_bits(&[0xE8, 0x08], 3, 8, Endianness::Little, false),
            0x1D as f64
        );
        assert_eq!(
            extract_bits(&[0xE8], 6, 8, Endianness::Little, false),
            0x3 as f64
        );
    }

    #[test]
    fn a_128_bit_field_reads_and_a_longer_one_is_nan() {
        let bytes = [0xFF; 20];
        assert_eq!(extract_bits(&bytes, 0, 128, Endianness::Big, true), -1.0);
        assert_eq!(
            extract_bits(&bytes, 0, 128, Endianness::Little, false),
            u128::MAX as f64
        );
        for len in [129, 160, u32::MAX] {
            assert!(extract_bits(&bytes, 0, len, Endianness::Big, true).is_nan());
        }
    }

    #[test]
    fn a_field_past_the_end_reads_the_bits_it_has_unsigned() {
        assert_eq!(extract_bits(&[0xFF], 0, 16, Endianness::Big, true), 255.0);
    }

    #[test]
    fn a_signed_field_reads_twos_complement() {
        // 0xFF over 8 bits signed = -1.
        assert_eq!(extract_bits(&[0xFF], 0, 8, Endianness::Big, true), -1.0);
    }

    #[test]
    fn word_swap_reverses_the_words() {
        // "CDAB" word order: 0xAABB 0xCCDD stored as 0xCCDD 0xAABB.
        let mut b = [0xCC, 0xDD, 0xAA, 0xBB];
        apply_word_swap(&mut b, 0, 32);
        assert_eq!(b, [0xAA, 0xBB, 0xCC, 0xDD]);
    }

    #[cfg(feature = "decimal")]
    #[test]
    #[allow(deprecated)]
    fn scale_is_exact_not_float_noisy() {
        assert_eq!(
            scale(555.0, Some(0.1), None).map(format_decimal).as_deref(),
            Some("55.5")
        );
        assert_eq!(
            scale(3374.0, Some(0.1), None)
                .map(format_decimal)
                .as_deref(),
            Some("337.4")
        );
        assert_eq!(
            scale(555.0, Some(0.1), None),
            Some(rust_decimal_macros::dec!(55.5))
        );
    }

    #[cfg(feature = "decimal")]
    #[test]
    #[allow(deprecated)]
    fn scale_defaults_and_offset() {
        assert_eq!(
            scale(100.0, None, None),
            Some(rust_decimal_macros::dec!(100))
        );
        assert_eq!(
            scale(100.0, None, None).map(format_decimal).as_deref(),
            Some("100")
        );
        assert_eq!(
            scale(10.0, Some(2.0), Some(5.0)),
            Some(rust_decimal_macros::dec!(25))
        );
        assert_eq!(
            scale(0.0, Some(0.0), Some(0.0)),
            Some(rust_decimal_macros::dec!(0))
        );
        assert_eq!(
            scale(10.0, Some(1e-28), None),
            Some(rust_decimal_macros::dec!(1e-27))
        );
    }

    #[cfg(feature = "decimal")]
    #[test]
    fn scale_is_none_when_the_result_overflows_decimal() {
        assert_eq!(scale(u64::MAX as f64, Some(1e15), None), None);
        assert_eq!(scale(4294967295.0, Some(2e19), None), None);
        assert_eq!(scale(-(i64::MAX as f64), Some(-1e10), None), None);
        assert_eq!(scale(7.9e28, Some(1.0), Some(7.9e28)), None);
    }

    #[cfg(feature = "decimal")]
    #[test]
    fn scale_is_none_for_a_non_finite_or_out_of_range_input() {
        for bad in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY, 1e29] {
            assert_eq!(scale(10.0, Some(bad), None), None, "factor {bad}");
            assert_eq!(scale(10.0, None, Some(bad)), None, "offset {bad}");
            assert_eq!(scale(bad, None, None), None, "raw {bad}");
        }
    }

    #[cfg(feature = "decimal")]
    #[test]
    fn scale_is_none_for_a_factor_too_small_for_decimal_not_zero() {
        assert_eq!(scale(10.0, Some(1e-30), None), None);
        assert_eq!(scale(10.0, None, Some(-1e-30)), None);
    }

    #[test]
    fn big_endian_hex_is_most_significant_byte_first() {
        assert_eq!(format_hex(0x1A2B as f64, 16, Endianness::Big), "1A 2B");
    }

    #[test]
    fn text_drops_nuls() {
        assert_eq!(decode_text(b"AB\0D", 0, 32), "ABD");
    }

    #[test]
    fn unix_time_utc() {
        assert_eq!(format_unix_time(0.0), "1970-01-01 00:00:00");
    }
}
