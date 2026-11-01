use std::convert::Infallible;
use std::fmt;
use std::str::FromStr;

/// What a unit measures; units convert only within one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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
}

/// A unit of measure, displayed in Home Assistant's spelling.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
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
            _ => None,
        };
        exact
            .or_else(|| Self::parse_folded(&trimmed.to_lowercase()))
            .unwrap_or_else(|| Unit::Other(text.to_string()))
    }

    /// Spellings safe to match in any case: none of them has a milli or mega
    /// prefix, which only case tells apart.
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
            "c/kwh" | "¢/kwh" => Unit::CentsPerKWh,
            "$/kwh" => Unit::DollarsPerKWh,
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
            Unit::Other(_) => return None,
        })
    }

    /// The power of ten this unit is of its dimension's base; `None` for a
    /// temperature, whose scales are offset, and for `Other`.
    pub(crate) fn exponent(&self) -> Option<i32> {
        Some(match self {
            Unit::MilliA | Unit::MilliV | Unit::MilliAh => -3,
            Unit::W
            | Unit::Wh
            | Unit::A
            | Unit::V
            | Unit::Ah
            | Unit::VA
            | Unit::Var
            | Unit::Percent
            | Unit::Hz
            | Unit::CentsPerKWh => 0,
            Unit::DollarsPerKWh => 2,
            Unit::KiloW | Unit::KiloWh | Unit::KiloV | Unit::KiloVA | Unit::KiloVar => 3,
            Unit::MegaW | Unit::MegaWh => 6,
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
        match self.dimension() {
            Some(Dimension::Power) => &POWER,
            Some(Dimension::Energy) => &ENERGY,
            Some(Dimension::Current) => &CURRENT,
            Some(Dimension::Voltage) => &VOLTAGE,
            Some(Dimension::Charge) => &CHARGE,
            Some(Dimension::ApparentPower) => &APPARENT_POWER,
            Some(Dimension::ReactivePower) => &REACTIVE_POWER,
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
