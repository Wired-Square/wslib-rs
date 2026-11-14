use rust_decimal::{Decimal, RoundingStrategy};

/// How many decimal places a value is shown with.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Precision {
    /// Every digit the value has, trailing zeros dropped.
    Exact,
    /// Exactly this many places, padded with zeros.
    Fixed(u8),
    /// At most this many places, trailing zeros dropped.
    AtMost(u8),
    /// Fewer places the larger the value: 0 from 10 000, 1 from 1 000, 2 from
    /// 100, else 3, padded.
    Magnitude,
}

impl Precision {
    /// Home Assistant's rule: an entity's `display_precision` when it sets one,
    /// else at most 3 places.
    pub fn ha(display_precision: Option<u8>) -> Precision {
        display_precision.map_or(Precision::AtMost(3), Precision::Fixed)
    }
}

/// `value` as a plain decimal string in `precision`, rounded half away from
/// zero, with no thousands separators and never a negative zero.
pub fn format_decimal(value: Decimal, precision: Precision) -> String {
    let (mut shown, places) = match precision {
        Precision::Exact => (value.normalize(), 0),
        Precision::Fixed(places) => (round(value, places), places),
        Precision::AtMost(places) => (round(value, places).normalize(), 0),
        Precision::Magnitude => {
            let places = magnitude_places(value);
            (round(value, places), places)
        }
    };
    if shown.is_zero() {
        shown.set_sign_positive(true);
    }
    pad(shown.to_string(), places.into())
}

pub(crate) fn round(value: Decimal, places: u8) -> Decimal {
    value.round_dp_with_strategy(places.into(), RoundingStrategy::MidpointAwayFromZero)
}

fn magnitude_places(value: Decimal) -> u8 {
    let magnitude = value.abs();
    if magnitude >= Decimal::from(10_000) {
        0
    } else if magnitude >= Decimal::from(1_000) {
        1
    } else if magnitude >= Decimal::ONE_HUNDRED {
        2
    } else {
        3
    }
}

/// Pads with zeros by text, since a `Decimal` can't carry more than 28 places
/// or the scale a large value would need.
fn pad(mut text: String, places: usize) -> String {
    let have = text
        .split_once('.')
        .map_or(0, |(_, fraction)| fraction.len());
    if have < places {
        if have == 0 {
            text.push('.');
        }
        text.extend(std::iter::repeat_n('0', places - have));
    }
    text
}
