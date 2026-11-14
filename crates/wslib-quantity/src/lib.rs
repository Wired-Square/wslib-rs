//! A measured value and its unit: tolerant unit parsing, exact conversion,
//! auto-scaling and display precision.

mod format;
mod unit;

use std::fmt;

use format::round;
pub use format::{Precision, format_decimal};
use rust_decimal::Decimal;
pub use unit::{Dimension, Unit};

/// A value in a unit.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Quantity {
    pub value: Decimal,
    pub unit: Unit,
}

/// Why a quantity could not convert to another unit.
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
        let temperature = Some(Dimension::Temperature);
        if self.unit != unit
            && self.unit.dimension() == temperature
            && unit.dimension() == temperature
        {
            return to_celsius(self.value, &self.unit)
                .and_then(|celsius| from_celsius(celsius, &unit))
                .map(|value| Quantity::new(value, unit))
                .ok_or(ConvertError::Overflow);
        }
        self.to_by_ratio(unit)
    }

    fn to_by_ratio(&self, unit: Unit) -> Result<Quantity, ConvertError> {
        if self.unit == unit {
            return Ok(self.clone());
        }
        let (true, Some(from), Some(to)) = (
            self.unit.dimension() == unit.dimension(),
            self.unit.smallest_units(),
            unit.smallest_units(),
        ) else {
            return Err(ConvertError::Incompatible {
                from: self.unit.clone(),
                to: unit,
            });
        };
        let value = if from >= to {
            self.value.checked_mul((from / to).into())
        } else {
            self.value.checked_div((to / from).into())
        };
        value
            .map(|value| Quantity::new(value, unit))
            .ok_or(ConvertError::Overflow)
    }

    /// The nearest multiple of `resolution`'s magnitude, half away from zero,
    /// in this quantity's unit; a zero resolution leaves it as it is. A
    /// resolution converts by ratio only, never by a temperature offset.
    pub fn rounded_to(&self, resolution: &Quantity) -> Result<Quantity, ConvertError> {
        let step = resolution.value.abs();
        if step.is_zero() {
            return Quantity::new(Decimal::ZERO, self.unit.clone())
                .to_by_ratio(resolution.unit.clone())
                .map(|_| self.clone());
        }
        let value = self.to_by_ratio(resolution.unit.clone())?.value;
        let rounded = value
            .checked_div(step)
            .and_then(|steps| round(steps, 0).checked_mul(step))
            .ok_or(ConvertError::Overflow)?;
        Quantity::new(rounded, resolution.unit.clone()).to_by_ratio(self.unit.clone())
    }

    /// Rounded to `resolution`, auto-scaled (carrying into the next unit when
    /// rounding reaches it) and shown to the step's first significant place, so
    /// `3598 s` at `7 s` is `1 h`. A rounded zero shows in the unit one step
    /// scales to.
    pub fn display_at(&self, resolution: &Quantity) -> Result<String, ConvertError> {
        let rounded = self.rounded_to(resolution)?;
        let step = Quantity::new(resolution.value.abs(), resolution.unit.clone());
        if step.value.is_zero() {
            return Ok(rounded.auto_scaled().display(Precision::Exact));
        }
        let mut shown = if rounded.value.is_zero() {
            Quantity::new(Decimal::ZERO, step.auto_scaled().unit)
        } else {
            rounded.auto_scaled()
        };
        loop {
            let places = first_significant_place(step.to_by_ratio(shown.unit.clone())?.value);
            let carried =
                Quantity::new(round(shown.value, places), shown.unit.clone()).auto_scaled();
            if carried.unit == shown.unit {
                return Ok(shown.display(Precision::AtMost(places)));
            }
            shown = carried;
        }
    }

    /// The quantity in the largest unit of its kind that keeps it at or above
    /// 1, or unchanged when its unit isn't on a scale or it is zero.
    pub fn auto_scaled(&self) -> Quantity {
        if self.unit.dimension() == Some(Dimension::PricePerEnergy) {
            return match self.to(Unit::DollarsPerKWh) {
                Ok(dollars) if dollars.value.abs() > Decimal::ONE => dollars,
                _ => self.to(Unit::CentsPerKWh).unwrap_or_else(|_| self.clone()),
            };
        }
        let ladder = self.unit.ladder();
        if self.value.is_zero() || !ladder.contains(&self.unit) {
            return self.clone();
        }
        let scaled: Vec<Quantity> = ladder
            .iter()
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

fn first_significant_place(step: Decimal) -> u8 {
    (0..28)
        .take_while(|&places| Decimal::new(1, places) > step)
        .count() as u8
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
