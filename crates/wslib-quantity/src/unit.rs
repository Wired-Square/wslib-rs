use std::convert::Infallible;
use std::fmt;
use std::str::FromStr;

/// What a unit measures; units convert only within one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Dimension {
    Power,
    Energy,
    Temperature,
    Current,
    Voltage,
    Charge,
    Frequency,
    ApparentPower,
    ReactivePower,
    Ratio,
    PricePerEnergy,
    Time,
}

/// A unit of measure, displayed in Home Assistant's spelling.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Unit {
    W,
    KiloW,
    MegaW,
    Wh,
    KiloWh,
    MegaWh,
    Celsius,
    Fahrenheit,
    Kelvin,
    A,
    MilliA,
    V,
    MilliV,
    KiloV,
    Ah,
    MilliAh,
    Percent,
    Hz,
    VA,
    KiloVA,
    Var,
    KiloVar,
    CentsPerKWh,
    DollarsPerKWh,
    Millisecond,
    Second,
    Minute,
    Hour,
    Day,
    Other(String),
}

impl Unit {
    /// The unit `text` names, or `Other(text)` when it names none unambiguously.
    pub fn parse(text: &str) -> Unit {
        let trimmed = text.trim();
        let exact = match trimmed {
            "MW" => Some(Unit::MegaW),
            "MWh" => Some(Unit::MegaWh),
            "mA" => Some(Unit::MilliA),
            "mV" => Some(Unit::MilliV),
            "mAh" => Some(Unit::MilliAh),
            "C" => Some(Unit::Celsius),
            "F" => Some(Unit::Fahrenheit),
            "K" => Some(Unit::Kelvin),
            "ms" => Some(Unit::Millisecond),
            "s" => Some(Unit::Second),
            "min" => Some(Unit::Minute),
            "h" => Some(Unit::Hour),
            "d" => Some(Unit::Day),
            _ => None,
        };
        exact
            .or_else(|| Self::parse_folded(&trimmed.to_lowercase()))
            .unwrap_or_else(|| Unit::Other(text.to_string()))
    }

    /// Spellings safe to match in any case: none is a symbol that case alone
    /// tells apart from another, as `mW` from `MW` or `s` from siemens' `S`.
    fn parse_folded(folded: &str) -> Option<Unit> {
        Some(match folded {
            "w" | "watt" | "watts" => Unit::W,
            "kw" | "kilowatt" | "kilowatts" => Unit::KiloW,
            "wh" | "watt-hour" | "watt-hours" => Unit::Wh,
            "kwh" | "kilowatt-hour" | "kilowatt-hours" => Unit::KiloWh,
            "°c" | "℃" | "degc" | "deg c" => Unit::Celsius,
            "°f" | "℉" | "degf" | "deg f" => Unit::Fahrenheit,
            "a" => Unit::A,
            "v" => Unit::V,
            "kv" => Unit::KiloV,
            "ah" => Unit::Ah,
            "%" => Unit::Percent,
            "hz" => Unit::Hz,
            "va" => Unit::VA,
            "kva" => Unit::KiloVA,
            "var" => Unit::Var,
            "kvar" => Unit::KiloVar,
            "c/kwh" | "¢/kwh" | "cents/kwh" => Unit::CentsPerKWh,
            "$/kwh" | "aud/kwh" => Unit::DollarsPerKWh,
            "millisecond" | "milliseconds" => Unit::Millisecond,
            "sec" | "secs" | "second" | "seconds" => Unit::Second,
            "mins" | "minute" | "minutes" => Unit::Minute,
            "hr" | "hrs" | "hour" | "hours" => Unit::Hour,
            "day" | "days" => Unit::Day,
            _ => return None,
        })
    }

    /// What the unit measures; `None` for `Other`.
    pub fn dimension(&self) -> Option<Dimension> {
        use Dimension::*;
        Some(match self {
            Unit::W | Unit::KiloW | Unit::MegaW => Power,
            Unit::Wh | Unit::KiloWh | Unit::MegaWh => Energy,
            Unit::Celsius | Unit::Fahrenheit | Unit::Kelvin => Temperature,
            Unit::A | Unit::MilliA => Current,
            Unit::V | Unit::MilliV | Unit::KiloV => Voltage,
            Unit::Ah | Unit::MilliAh => Charge,
            Unit::Percent => Ratio,
            Unit::Hz => Frequency,
            Unit::VA | Unit::KiloVA => ApparentPower,
            Unit::Var | Unit::KiloVar => ReactivePower,
            Unit::CentsPerKWh | Unit::DollarsPerKWh => PricePerEnergy,
            Unit::Millisecond | Unit::Second | Unit::Minute | Unit::Hour | Unit::Day => Time,
            Unit::Other(_) => return None,
        })
    }

    /// How many of its dimension's smallest unit this unit is; `None` for a
    /// temperature, whose scales are offset, and for `Other`.
    pub(crate) fn smallest_units(&self) -> Option<u64> {
        Some(match self {
            Unit::W
            | Unit::Wh
            | Unit::MilliA
            | Unit::MilliV
            | Unit::MilliAh
            | Unit::VA
            | Unit::Var
            | Unit::Percent
            | Unit::Hz
            | Unit::CentsPerKWh
            | Unit::Millisecond => 1,
            Unit::DollarsPerKWh => 100,
            Unit::KiloW
            | Unit::KiloWh
            | Unit::A
            | Unit::V
            | Unit::Ah
            | Unit::KiloVA
            | Unit::KiloVar
            | Unit::Second => 1000,
            Unit::Minute => 60_000,
            Unit::MegaW | Unit::MegaWh | Unit::KiloV => 1_000_000,
            Unit::Hour => 3_600_000,
            Unit::Day => 86_400_000,
            Unit::Celsius | Unit::Fahrenheit | Unit::Kelvin | Unit::Other(_) => return None,
        })
    }

    /// The units auto-scaling moves between, smallest first.
    pub(crate) fn ladder(&self) -> &'static [Unit] {
        static POWER: [Unit; 3] = [Unit::W, Unit::KiloW, Unit::MegaW];
        static ENERGY: [Unit; 3] = [Unit::Wh, Unit::KiloWh, Unit::MegaWh];
        static CURRENT: [Unit; 2] = [Unit::MilliA, Unit::A];
        static VOLTAGE: [Unit; 3] = [Unit::MilliV, Unit::V, Unit::KiloV];
        static CHARGE: [Unit; 2] = [Unit::MilliAh, Unit::Ah];
        static APPARENT_POWER: [Unit; 2] = [Unit::VA, Unit::KiloVA];
        static REACTIVE_POWER: [Unit; 2] = [Unit::Var, Unit::KiloVar];
        static TIME: [Unit; 4] = [Unit::Millisecond, Unit::Second, Unit::Minute, Unit::Hour];
        match self.dimension() {
            Some(Dimension::Power) => &POWER,
            Some(Dimension::Energy) => &ENERGY,
            Some(Dimension::Current) => &CURRENT,
            Some(Dimension::Voltage) => &VOLTAGE,
            Some(Dimension::Charge) => &CHARGE,
            Some(Dimension::ApparentPower) => &APPARENT_POWER,
            Some(Dimension::ReactivePower) => &REACTIVE_POWER,
            Some(Dimension::Time) => &TIME,
            _ => &[],
        }
    }

    fn symbol(&self) -> &str {
        match self {
            Unit::W => "W",
            Unit::KiloW => "kW",
            Unit::MegaW => "MW",
            Unit::Wh => "Wh",
            Unit::KiloWh => "kWh",
            Unit::MegaWh => "MWh",
            Unit::Celsius => "°C",
            Unit::Fahrenheit => "°F",
            Unit::Kelvin => "K",
            Unit::A => "A",
            Unit::MilliA => "mA",
            Unit::V => "V",
            Unit::MilliV => "mV",
            Unit::KiloV => "kV",
            Unit::Ah => "Ah",
            Unit::MilliAh => "mAh",
            Unit::Percent => "%",
            Unit::Hz => "Hz",
            Unit::VA => "VA",
            Unit::KiloVA => "kVA",
            Unit::Var => "var",
            Unit::KiloVar => "kvar",
            Unit::CentsPerKWh => "c/kWh",
            Unit::DollarsPerKWh => "$/kWh",
            Unit::Millisecond => "ms",
            Unit::Second => "s",
            Unit::Minute => "min",
            Unit::Hour => "h",
            Unit::Day => "d",
            Unit::Other(text) => text,
        }
    }
}

impl fmt::Display for Unit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.symbol())
    }
}

impl FromStr for Unit {
    type Err = Infallible;

    fn from_str(text: &str) -> Result<Unit, Infallible> {
        Ok(Unit::parse(text))
    }
}

#[cfg(test)]
mod tests {
    use super::Unit::{self, *};

    const SCALED: [Unit; 26] = [
        W,
        KiloW,
        MegaW,
        Wh,
        KiloWh,
        MegaWh,
        A,
        MilliA,
        V,
        MilliV,
        KiloV,
        Ah,
        MilliAh,
        Percent,
        Hz,
        VA,
        KiloVA,
        Var,
        KiloVar,
        CentsPerKWh,
        DollarsPerKWh,
        Millisecond,
        Second,
        Minute,
        Hour,
        Day,
    ];

    #[test]
    fn every_larger_unit_is_a_whole_multiple_of_every_smaller_one_in_its_dimension() {
        for a in &SCALED {
            for b in SCALED.iter().filter(|b| b.dimension() == a.dimension()) {
                let (a_size, b_size) = (a.smallest_units().unwrap(), b.smallest_units().unwrap());
                assert_eq!(a_size.max(b_size) % a_size.min(b_size), 0, "{a} and {b}");
            }
        }
    }
}
