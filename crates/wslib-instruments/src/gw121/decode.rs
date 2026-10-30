use wslib_framelink_protocol::types::{
    ASPECT_AC, ASPECT_DC, ASPECT_DEFAULT, QTY_BITMASK, QTY_CURRENT, QTY_TEMPERATURE, QTY_VOLTAGE,
    SIGNAL_CHANNEL_NONE,
};

use super::frame::{
    Coupling, Display, Frame, MAIN_CELSIUS, MAIN_FAHRENHEIT, MAIN_RANGE_MASK, SUB_HERTZ, SUB_KILO,
    SUB_POINT_MASK,
};
use crate::{
    sample::{Sample, Stamp},
    signal::{self, SignalKey},
    value::Value,
};

pub const CHANNEL_V_OHM: u8 = 0;
pub const CHANNEL_MICRO_MILLI_AMP: u8 = 1;
pub const CHANNEL_AMP: u8 = 2;
pub const STATUS: SignalKey = signal::status(QTY_BITMASK, ASPECT_DEFAULT, SIGNAL_CHANNEL_NONE);
pub const STATUS_BATTERY_LOW: i64 = 1 << 0;
pub const STATUS_AUTO_POWER_OFF: i64 = 1 << 1;
pub const STATUS_OVERLOAD: i64 = 1 << 2;
pub const THERMOCOUPLE: SignalKey =
    signal::measurement(QTY_TEMPERATURE, ASPECT_DEFAULT, CHANNEL_V_OHM);
pub const METER_TEMPERATURE: SignalKey =
    signal::measurement(QTY_TEMPERATURE, ASPECT_DEFAULT, SIGNAL_CHANNEL_NONE);
pub const BATTERY: SignalKey = signal::measurement(QTY_VOLTAGE, ASPECT_DC, SIGNAL_CHANNEL_NONE);

const STATUS_EXPONENT: i8 = 0;
const MODE_TEMPERATURE: u8 = 5;
const SUB_MODE_METER_CELSIUS: u8 = 100;
const TENTHS: i8 = -1;
const RANGE_0: u8 = 0;
const CELSIUS_EXPONENT: i8 = -2;
const RADIX: i128 = 10;
const FREEZING_FAHRENHEIT_HUNDREDTHS: i128 = 3_200;
const CELSIUS_PER_FAHRENHEIT_NUMERATOR: i128 = 5;
const CELSIUS_PER_FAHRENHEIT_DENOMINATOR: i128 = 9;
const HALF: i128 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Unit {
    Plain,
    TemperatureFlags,
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "no row in TABLE uses it until a capture confirms one"
        )
    )]
    Fahrenheit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Aspect {
    Fixed(u8),
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "no row in TABLE uses it until a capture confirms one"
        )
    )]
    Coupling,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct MainRow {
    pub(crate) mode: u8,
    pub(crate) range: u8,
    pub(crate) quantity: u8,
    pub(crate) aspect: Aspect,
    pub(crate) channel: u8,
    pub(crate) exponent: i8,
    pub(crate) unit: Unit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SubSource {
    Fixed(SignalKey),
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "no row in TABLE uses it until a capture confirms one"
        )
    )]
    BurdenOfMain,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SubRow {
    pub(crate) mode: u8,
    pub(crate) source: SubSource,
    pub(crate) unit: Unit,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct Table {
    pub(crate) main: &'static [MainRow],
    pub(crate) sub: &'static [SubRow],
}

pub(crate) const TABLE: Table = Table {
    main: &[MainRow {
        mode: MODE_TEMPERATURE,
        range: RANGE_0,
        quantity: QTY_TEMPERATURE,
        aspect: Aspect::Fixed(ASPECT_DEFAULT),
        channel: CHANNEL_V_OHM,
        exponent: TENTHS,
        unit: Unit::TemperatureFlags,
    }],
    sub: &[SubRow {
        mode: SUB_MODE_METER_CELSIUS,
        source: SubSource::Fixed(METER_TEMPERATURE),
        unit: Unit::Plain,
    }],
};

const NAMES: &[(SignalKey, &str)] = &[
    (THERMOCOUPLE, "Thermocouple"),
    (METER_TEMPERATURE, "Meter Temperature"),
    (BATTERY, "Battery"),
    (
        signal::measurement(QTY_VOLTAGE, ASPECT_DC, CHANNEL_MICRO_MILLI_AMP),
        "DC Burden Voltage (µA/mA)",
    ),
    (
        signal::measurement(QTY_VOLTAGE, ASPECT_AC, CHANNEL_MICRO_MILLI_AMP),
        "AC Burden Voltage (µA/mA)",
    ),
    (
        signal::measurement(QTY_VOLTAGE, ASPECT_DC, CHANNEL_AMP),
        "DC Burden Voltage (A)",
    ),
    (
        signal::measurement(QTY_VOLTAGE, ASPECT_AC, CHANNEL_AMP),
        "AC Burden Voltage (A)",
    ),
    (STATUS, "Status"),
];

const FLAG_NAMES: &[(i64, &str)] = &[
    (STATUS_AUTO_POWER_OFF, "APO on"),
    (STATUS_BATTERY_LOW, "battery LOW"),
    (STATUS_OVERLOAD, "OL"),
];

const COUPLED_ASPECTS: [u8; 2] = [ASPECT_DC, ASPECT_AC];

pub fn display_name(key: &SignalKey) -> Option<&'static str> {
    NAMES
        .iter()
        .find(|(named, _)| named == key)
        .map(|(_, name)| *name)
}

pub(crate) fn key_named(name: &str) -> Option<SignalKey> {
    signals()
        .into_iter()
        .find(|key| display_name(key) == Some(name))
}

pub(crate) fn status_flags(bits: i64) -> Vec<&'static str> {
    FLAG_NAMES
        .iter()
        .filter(|(bit, _)| bits & bit != 0)
        .map(|(_, name)| *name)
        .collect()
}

fn row_keys(row: &MainRow) -> Vec<SignalKey> {
    match row.aspect {
        Aspect::Fixed(aspect) => vec![signal::measurement(row.quantity, aspect, row.channel)],
        Aspect::Coupling => COUPLED_ASPECTS
            .iter()
            .map(|aspect| signal::measurement(row.quantity, *aspect, row.channel))
            .collect(),
    }
}

fn burden_of(key: SignalKey) -> Option<SignalKey> {
    (key.quantity == QTY_CURRENT).then_some(signal::measurement(
        QTY_VOLTAGE,
        key.aspect,
        key.channel,
    ))
}

/// Every signal the 121GW publishes.
pub fn signals() -> Vec<SignalKey> {
    signals_of(&TABLE)
}

pub(crate) fn signals_of(table: &Table) -> Vec<SignalKey> {
    let main: Vec<SignalKey> = table.main.iter().flat_map(row_keys).collect();
    let sub = table.sub.iter().flat_map(|row| match row.source {
        SubSource::Fixed(key) => vec![key],
        SubSource::BurdenOfMain => main.iter().copied().filter_map(burden_of).collect(),
    });
    let mut keys: Vec<SignalKey> = main.iter().copied().chain(sub).chain([STATUS]).collect();
    keys.sort();
    keys.dedup();
    keys
}

pub(crate) fn samples(frame: &Frame, table: &Table, stamp: Stamp) -> Vec<Sample> {
    let status = Sample::new(
        STATUS,
        Value::new(status_bits(frame), STATUS_EXPONENT),
        stamp,
    );
    if !live(frame) {
        return vec![status];
    }
    let main_key = main_row(frame, table).and_then(|row| main_key(frame, row));
    [
        Some(status),
        main_sample(frame, table, stamp),
        sub_sample(frame, table, main_key, stamp),
    ]
    .into_iter()
    .flatten()
    .collect()
}

fn live(frame: &Frame) -> bool {
    let icons = &frame.icons;
    !(icons.relative
        || icons.min_max
        || icons.held
        || icons.peak
        || icons.coupling == Coupling::DcAc)
}

fn status_bits(frame: &Frame) -> i64 {
    [
        (frame.icons.battery_low, STATUS_BATTERY_LOW),
        (frame.icons.auto_power_off, STATUS_AUTO_POWER_OFF),
        (frame.main.overload || frame.sub.overload, STATUS_OVERLOAD),
    ]
    .into_iter()
    .filter(|(set, _)| *set)
    .fold(0, |bits, (_, bit)| bits | bit)
}

fn signed(display: &Display) -> i64 {
    let magnitude = i64::from(display.raw);
    if display.negative {
        -magnitude
    } else {
        magnitude
    }
}

fn round_half_away(numerator: i128, denominator: i128) -> i128 {
    (numerator + numerator.signum() * denominator / HALF) / denominator
}

pub(crate) fn fahrenheit_to_celsius(value: Value) -> Option<Value> {
    let shift = i32::from(value.exponent) - i32::from(CELSIUS_EXPONENT);
    let mantissa = i128::from(value.mantissa);
    let (above_freezing, scale) = if shift >= 0 {
        (
            mantissa.checked_mul(RADIX.checked_pow(shift.unsigned_abs())?)?
                - FREEZING_FAHRENHEIT_HUNDREDTHS,
            1,
        )
    } else {
        let scale = RADIX.checked_pow(shift.unsigned_abs())?;
        (
            mantissa - FREEZING_FAHRENHEIT_HUNDREDTHS.checked_mul(scale)?,
            scale,
        )
    };
    let celsius = round_half_away(
        above_freezing.checked_mul(CELSIUS_PER_FAHRENHEIT_NUMERATOR)?,
        CELSIUS_PER_FAHRENHEIT_DENOMINATOR.checked_mul(scale)?,
    );
    Some(Value::new(i64::try_from(celsius).ok()?, CELSIUS_EXPONENT))
}

fn in_unit(frame: &Frame, unit: Unit, value: Value) -> Option<Value> {
    let celsius = frame.main.flags & MAIN_CELSIUS != 0;
    let fahrenheit = frame.main.flags & MAIN_FAHRENHEIT != 0;
    match unit {
        Unit::Plain => Some(value),
        Unit::Fahrenheit => fahrenheit_to_celsius(value),
        Unit::TemperatureFlags => match (celsius, fahrenheit) {
            (true, false) => Some(value),
            (false, true) => fahrenheit_to_celsius(value),
            _ => None,
        },
    }
}

fn main_row<'a>(frame: &Frame, table: &'a Table) -> Option<&'a MainRow> {
    let range = frame.main.flags & MAIN_RANGE_MASK;
    table
        .main
        .iter()
        .find(|row| row.mode == frame.main.mode && row.range == range)
}

fn main_key(frame: &Frame, row: &MainRow) -> Option<SignalKey> {
    let aspect = match row.aspect {
        Aspect::Fixed(aspect) => aspect,
        Aspect::Coupling => match frame.icons.coupling {
            Coupling::Dc => ASPECT_DC,
            Coupling::Ac => ASPECT_AC,
            Coupling::None | Coupling::DcAc => return None,
        },
    };
    Some(signal::measurement(row.quantity, aspect, row.channel))
}

fn main_sample(frame: &Frame, table: &Table, stamp: Stamp) -> Option<Sample> {
    if frame.main.overload {
        return None;
    }
    let row = main_row(frame, table)?;
    let key = main_key(frame, row)?;
    let value = in_unit(
        frame,
        row.unit,
        Value::new(signed(&frame.main), row.exponent),
    )?;
    Some(Sample::new(key, value, stamp))
}

fn sub_sample(
    frame: &Frame,
    table: &Table,
    main_key: Option<SignalKey>,
    stamp: Stamp,
) -> Option<Sample> {
    if frame.sub.overload || frame.sub.flags & (SUB_KILO | SUB_HERTZ) != 0 {
        return None;
    }
    let row = table.sub.iter().find(|row| row.mode == frame.sub.mode)?;
    let key = match row.source {
        SubSource::Fixed(key) => key,
        SubSource::BurdenOfMain => burden_of(main_key?)?,
    };
    let point = i8::try_from(frame.sub.flags & SUB_POINT_MASK).ok()?;
    let value = in_unit(frame, row.unit, Value::new(signed(&frame.sub), -point))?;
    Some(Sample::new(key, value, stamp))
}

#[cfg(test)]
mod tests;
