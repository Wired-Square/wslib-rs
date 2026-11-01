//! A measured value and its unit: tolerant unit parsing, exact conversion,
//! auto-scaling and display precision.

mod format;
mod unit;

use std::fmt;

pub use format::{Precision, format_decimal};
use rust_decimal::Decimal;
pub use unit::{Dimension, Unit};

/// A value in a unit.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Quantity {
    pub value: Decimal,
    pub unit: Unit,
}

/// Why [`Quantity::to`] could not convert.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConvertError {
    Incompatible { from: Unit, to: Unit },
    Overflow,
}

impl fmt::Display for ConvertError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConvertError::Incompatible { from, to } => write!(f, "can't convert {from} to {to}"),
            ConvertError::Overflow => f.write_str("the converted value is out of Decimal's range"),
        }
    }
}

impl std::error::Error for ConvertError {}

impl Quantity {
    pub fn new(value: Decimal, unit: Unit) -> Quantity {
        Quantity { value, unit }
    }

    /// A state string (plain or scientific, whitespace trimmed) in `unit`, or
    /// `None` when it isn't a number; no unit is `Other("")`.
    pub fn parse(state: &str, unit: Option<&str>) -> Option<Quantity> {
        let state = state.trim();
        if !state
            .bytes()
            .all(|b| b.is_ascii_digit() || matches!(b, b'.' | b'-' | b'+' | b'e' | b'E'))
        {
            return None;
        }
        let value = if state.contains(['e', 'E']) {
            Decimal::from_scientific_lossy(state)
        } else {
            state.parse()
        };
        Some(Quantity::new(value.ok()?, Unit::parse(unit.unwrap_or(""))))
    }

    /// The same quantity in `unit`, which must measure the same dimension.
    pub fn to(&self, unit: Unit) -> Result<Quantity, ConvertError> {
        if self.unit == unit {
            return Ok(self.clone());
        }
        if self.unit.dimension().is_none() || self.unit.dimension() != unit.dimension() {
            return Err(ConvertError::Incompatible {
                from: self.unit.clone(),
                to: unit,
            });
        }
        let value = match (self.unit.exponent(), unit.exponent()) {
            (Some(from), Some(to)) => shift(self.value, from - to),
            _ => to_celsius(self.value, &self.unit).and_then(|c| from_celsius(c, &unit)),
        };
        value
            .map(|value| Quantity::new(value, unit))
            .ok_or(ConvertError::Overflow)
    }

    /// The quantity in the largest unit of its kind that keeps it at or above
    /// 1, or unchanged when its unit doesn't scale or it is zero.
    pub fn auto_scaled(&self) -> Quantity {
        if self.unit.dimension() == Some(Dimension::PricePerEnergy) {
            return match self.to(Unit::DollarsPerKWh) {
                Ok(dollars) if dollars.value.abs() > Decimal::ONE => dollars,
                _ => self.to(Unit::CentsPerKWh).unwrap_or_else(|_| self.clone()),
            };
        }
        if self.value.is_zero() {
            return self.clone();
        }
        let scaled: Vec<Quantity> = (self.unit.ladder().iter())
            .filter_map(|unit| self.to(unit.clone()).ok())
            .collect();
        scaled
            .iter()
            .rev()
            .find(|q| q.value.abs() >= Decimal::ONE)
            .or(scaled.first())
            .cloned()
            .unwrap_or_else(|| self.clone())
    }

    /// The value alone, in `precision`.
    pub fn format(&self, precision: Precision) -> String {
        format_decimal(self.value, precision)
    }

    /// The value and its unit, spaced as Home Assistant's frontend does in
    /// English: a space before every unit but `%` and `°`.
    pub fn display(&self, precision: Precision) -> String {
        let number = self.format(precision);
        match self.unit.to_string().as_str() {
            "" => number,
            unit @ ("%" | "°") => format!("{number}{unit}"),
            unit => format!("{number} {unit}"),
        }
    }
}

fn shift(value: Decimal, places: i32) -> Option<Decimal> {
    let factor = Decimal::from_i128_with_scale(10i128.pow(places.unsigned_abs()), 0);
    if places >= 0 {
        value.checked_mul(factor)
    } else {
        value.checked_div(factor)
    }
}

const KELVIN_AT_ZERO_CELSIUS: Decimal = Decimal::from_parts(27315, 0, 0, false, 2);

fn to_celsius(value: Decimal, unit: &Unit) -> Option<Decimal> {
    match unit {
        Unit::Celsius => Some(value),
        Unit::Fahrenheit => {
            Some(value.checked_sub(32.into())?.checked_mul(5.into())? / Decimal::from(9))
        }
        Unit::Kelvin => value.checked_sub(KELVIN_AT_ZERO_CELSIUS),
        _ => None,
    }
}

fn from_celsius(celsius: Decimal, unit: &Unit) -> Option<Decimal> {
    match unit {
        Unit::Celsius => Some(celsius),
        Unit::Fahrenheit => {
            (celsius.checked_mul(9.into())? / Decimal::from(5)).checked_add(32.into())
        }
        Unit::Kelvin => celsius.checked_add(KELVIN_AT_ZERO_CELSIUS),
        _ => None,
    }
}
