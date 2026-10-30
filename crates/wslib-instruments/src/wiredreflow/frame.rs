use std::mem;

use wslib_framelink_protocol::{
    can_id::{CAN_DEVICE_ID_MASK, can_device_id, can_host, can_slot},
    types::{ASPECT_DEFAULT, ASPECT_INTEGRITY, ASPECT_REFERENCE, QTY_COUNT, QTY_TEMPERATURE},
};

use crate::{
    sample::{Sample, Stamp},
    signal::{self, SignalKey},
    value::Value,
};

pub const SLOT_THERMOCOUPLES: u8 = 0x21;
pub const SLOT_THERMOCOUPLE_FAULT: u8 = 0x25;
const THERMOCOUPLES_DLC: usize = 8;
const THERMOCOUPLE_FAULT_DLC: usize = 2;
const DEVICE_ID_SHIFT: u32 = CAN_DEVICE_ID_MASK.trailing_zeros();
pub const DEVICE_ID_MAX: u32 = CAN_DEVICE_ID_MASK >> DEVICE_ID_SHIFT;
const DEVICE_ID_DIGITS: usize = 6;
const DECI: i8 = -1;
const UNITY: i8 = 0;
const CHANNEL_1: u8 = 0;
const CHANNEL_2: u8 = 1;
const NO_FAULT: i64 = 0;
const I16_BYTES: usize = size_of::<i16>();

pub const TC1: SignalKey = signal::measurement(QTY_TEMPERATURE, ASPECT_DEFAULT, CHANNEL_1);
pub const TC2: SignalKey = signal::measurement(QTY_TEMPERATURE, ASPECT_DEFAULT, CHANNEL_2);
pub const CJ1: SignalKey = signal::measurement(QTY_TEMPERATURE, ASPECT_REFERENCE, CHANNEL_1);
pub const CJ2: SignalKey = signal::measurement(QTY_TEMPERATURE, ASPECT_REFERENCE, CHANNEL_2);
pub const TC1_FAULT: SignalKey = signal::diagnostic(QTY_COUNT, ASPECT_INTEGRITY, CHANNEL_1);
pub const TC2_FAULT: SignalKey = signal::diagnostic(QTY_COUNT, ASPECT_INTEGRITY, CHANNEL_2);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawFrame {
    pub id: u32,
    pub extended: bool,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, Copy)]
enum Width {
    I16Le,
    U8,
}

#[derive(Debug, Clone, Copy)]
struct Field {
    slot: u8,
    at: usize,
    width: Width,
    exponent: i8,
    key: SignalKey,
    name: &'static str,
    withholds: Option<SignalKey>,
}

const SLOTS: [(u8, usize); 2] = [
    (SLOT_THERMOCOUPLES, THERMOCOUPLES_DLC),
    (SLOT_THERMOCOUPLE_FAULT, THERMOCOUPLE_FAULT_DLC),
];

const fn temperature(at: usize, key: SignalKey, name: &'static str) -> Field {
    Field {
        slot: SLOT_THERMOCOUPLES,
        at,
        width: Width::I16Le,
        exponent: DECI,
        key,
        name,
        withholds: None,
    }
}

const fn fault(at: usize, key: SignalKey, name: &'static str, withholds: SignalKey) -> Field {
    Field {
        slot: SLOT_THERMOCOUPLE_FAULT,
        at,
        width: Width::U8,
        exponent: UNITY,
        key,
        name,
        withholds: Some(withholds),
    }
}

const TC1_AT: usize = 0;
const TC2_AT: usize = 2;
const CJ1_AT: usize = 4;
const CJ2_AT: usize = 6;
const TC1_FAULT_AT: usize = 0;
const TC2_FAULT_AT: usize = 1;

const FIELDS: [Field; 6] = [
    temperature(TC1_AT, TC1, "TC1"),
    temperature(TC2_AT, TC2, "TC2"),
    temperature(CJ1_AT, CJ1, "CJ1"),
    temperature(CJ2_AT, CJ2, "CJ2"),
    fault(TC1_FAULT_AT, TC1_FAULT, "TC1 fault", TC1),
    fault(TC2_FAULT_AT, TC2_FAULT, "TC2 fault", TC2),
];

pub fn device_text(device: u32) -> String {
    format!("{device:0width$X}", width = DEVICE_ID_DIGITS)
}

pub fn device_of(frame: &RawFrame) -> Option<u32> {
    (frame.extended && !can_host(frame.id)).then(|| can_device_id(frame.id) >> DEVICE_ID_SHIFT)
}

pub fn signals() -> Vec<SignalKey> {
    FIELDS.iter().map(|field| field.key).collect()
}

pub fn display_name(key: &SignalKey) -> Option<&'static str> {
    FIELDS
        .iter()
        .find(|field| field.key == *key)
        .map(|field| field.name)
}

pub fn key_named(name: &str) -> Option<SignalKey> {
    FIELDS
        .iter()
        .find(|field| field.name == name)
        .map(|field| field.key)
}

fn raw(data: &[u8], field: &Field) -> Option<i64> {
    match field.width {
        Width::I16Le => data
            .get(field.at..)?
            .first_chunk::<I16_BYTES>()
            .map(|bytes| i64::from(i16::from_le_bytes(*bytes))),
        Width::U8 => data.get(field.at).map(|byte| i64::from(*byte)),
    }
}

pub fn known_slot(frame: &RawFrame) -> Option<u8> {
    let slot = can_slot(frame.id);
    SLOTS
        .iter()
        .any(|(known, dlc)| *known == slot && *dlc == frame.data.len())
        .then_some(slot)
}

fn guarded(key: &SignalKey) -> bool {
    FIELDS.iter().any(|field| field.withholds == Some(*key))
}

#[derive(Debug)]
pub struct Decoder {
    device: u32,
    held: Vec<Sample>,
}

impl Decoder {
    pub fn new(device: u32) -> Self {
        Self {
            device,
            held: Vec::new(),
        }
    }

    pub fn samples(&mut self, frame: &RawFrame, stamp: Stamp) -> Vec<Sample> {
        if device_of(frame) != Some(self.device) {
            return Vec::new();
        }
        let Some(slot) = known_slot(frame) else {
            return Vec::new();
        };
        let decoded: Vec<(Field, i64)> = FIELDS
            .iter()
            .filter(|field| field.slot == slot)
            .filter_map(|field| raw(&frame.data, field).map(|value| (*field, value)))
            .collect();
        let mut released = Vec::new();
        if decoded.iter().any(|(field, _)| field.withholds.is_some()) {
            let faulted: Vec<SignalKey> = decoded
                .iter()
                .filter(|(_, value)| *value != NO_FAULT)
                .filter_map(|(field, _)| field.withholds)
                .collect();
            released = mem::take(&mut self.held)
                .into_iter()
                .filter(|sample| !faulted.contains(&sample.key))
                .collect();
        }
        let (held, published): (Vec<Sample>, Vec<Sample>) = decoded
            .into_iter()
            .map(|(field, value)| Sample::new(field.key, Value::new(value, field.exponent), stamp))
            .partition(|sample| guarded(&sample.key));
        self.held = held;
        released.extend(published);
        released
    }
}
