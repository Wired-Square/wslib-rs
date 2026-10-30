use crate::{
    gw121::{
        decode::{
            Aspect, CHANNEL_MICRO_MILLI_AMP, CHANNEL_V_OHM, METER_TEMPERATURE, MainRow, STATUS,
            STATUS_AUTO_POWER_OFF, STATUS_OVERLOAD, SubRow, SubSource, TABLE, THERMOCOUPLE, Table,
            Unit, fahrenheit_to_celsius, samples, signals, signals_of, status_flags,
        },
        frame::{Assembler, FRAME_LEN, Frame},
    },
    sample::{Sample, Stamp},
    signal::{
        self, ASPECT_AC, ASPECT_DC, ASPECT_DEFAULT, QTY_CURRENT, QTY_TEMPERATURE, QTY_VOLTAGE,
        SIGNAL_CHANNEL_NONE, SignalKey,
    },
    value::Value,
};

const ROOM: &str = include_str!("../../../tests/fixtures/121gw-room-2026-09-26.notify");
const HEAT: &str = include_str!("../../../tests/fixtures/121gw-heat-2026-09-26.notify");
const TEMP_ROOM: [u8; FRAME_LEN] = [
    0xF2, 0x17, 0x80, 0x00, 0x00, 0x05, 0x20, 0x00, 0xD2, 0x64, 0x01, 0x00, 0xD8, 0x15, 0x00, 0x02,
    0x40, 0x00, 0x78,
];
const TENTHS: i8 = -1;
const ROOM_TENTHS: i64 = 210;
const METER_ROOM_TENTHS: i64 = 216;
const MAIN_MODE: usize = 5;
const MAIN_FLAGS: usize = 6;
const MAIN_VALUE_HIGH: usize = 7;
const MAIN_VALUE_LOW: usize = 8;
const SUB_FLAGS: usize = 10;
const ICONS_2: usize = 16;
const ICONS_3: usize = 17;
const OVERLOAD: u8 = 0x80;
const NEGATIVE: u8 = 0x40;
const CELSIUS: u8 = 0x20;
const FAHRENHEIT: u8 = 0x10;
const RANGE_1: u8 = 0x01;
const VALUE_BIT_16: u8 = 0x40;
const MODE_DCV_IN_EITHER_NUMBERING: u8 = 0x01;
const START_UP_FRAMES: usize = 3;
const HEAT_MIN_TENTHS: i64 = 214;
const HEAT_MAX_TENTHS: i64 = 2759;
const HEAT_LAST_TENTHS: i64 = 241;
const COLD_TENTHS: i64 = -1000;
const COLD_HIGH: u8 = 0x03;
const COLD_LOW: u8 = 0xE8;
const SEVENTEEN_BIT: i64 = 0x1_0000;

fn chunks(fixture: &str) -> Vec<Vec<u8>> {
    fixture
        .lines()
        .map(|line| {
            let hex = line.split_once(' ').unwrap().1;
            (0..hex.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
                .collect()
        })
        .collect()
}

fn frames(fixture: &str) -> Vec<Frame> {
    let mut assembler = Assembler::default();
    chunks(fixture)
        .iter()
        .flat_map(|c| assembler.push(c))
        .map(|bytes| Frame::decode(&bytes))
        .collect()
}

fn edited(edit: impl FnOnce(&mut [u8; FRAME_LEN])) -> Frame {
    let mut bytes = TEMP_ROOM;
    edit(&mut bytes);
    bytes[FRAME_LEN - 1] = bytes[..FRAME_LEN - 1].iter().fold(0, |x, b| x ^ b);
    Frame::decode(&bytes)
}

fn decoded(frame: &Frame) -> Vec<Sample> {
    samples(frame, &TABLE, Stamp::now())
}

fn value_of(samples: &[Sample], key: SignalKey) -> Option<Value> {
    samples.iter().find(|s| s.key == key).map(|s| s.value)
}

fn status_of(samples: &[Sample]) -> i64 {
    value_of(samples, STATUS)
        .expect("every frame publishes the status bitmask")
        .mantissa
}

#[test]
fn the_room_frame_publishes_the_thermocouple_the_meter_temperature_and_the_status() {
    let samples = decoded(&Frame::decode(&TEMP_ROOM));
    assert_eq!(
        value_of(&samples, THERMOCOUPLE),
        Some(Value::new(ROOM_TENTHS, TENTHS)),
        "the display read 21.0 °C"
    );
    assert_eq!(
        value_of(&samples, METER_TEMPERATURE),
        Some(Value::new(METER_ROOM_TENTHS, TENTHS)),
        "sub mode 100 with point 1 read 21.6 °C (display flickered 21.6–21.7)"
    );
    assert_eq!(
        status_of(&samples),
        STATUS_AUTO_POWER_OFF,
        "APO was on and the battery fine in the capture"
    );
    assert_eq!(samples.len(), 3);
}

#[test]
fn the_heating_capture_spans_room_to_the_peak_the_display_showed() {
    let tenths: Vec<i64> = frames(HEAT)
        .iter()
        .filter_map(|f| value_of(&decoded(f), THERMOCOUPLE))
        .map(|v| v.mantissa)
        .collect();
    assert_eq!(tenths.iter().min(), Some(&HEAT_MIN_TENTHS));
    assert_eq!(
        tenths.iter().max(),
        Some(&HEAT_MAX_TENTHS),
        "the display peaked at 275.9 °C"
    );
    assert_eq!(tenths.last(), Some(&HEAT_LAST_TENTHS));
}

#[test]
fn an_overloaded_main_value_still_publishes_the_sub_value_and_sets_ol() {
    let samples = decoded(&edited(|b| b[MAIN_FLAGS] |= OVERLOAD));
    assert_eq!(value_of(&samples, THERMOCOUPLE), None, "OL has no number");
    assert!(
        value_of(&samples, METER_TEMPERATURE).is_some(),
        "the sub value is unaffected"
    );
    assert_ne!(status_of(&samples) & STATUS_OVERLOAD, 0);
}

#[test]
fn an_overloaded_sub_value_sets_ol_and_keeps_the_main_value() {
    let samples = decoded(&edited(|b| b[SUB_FLAGS] |= OVERLOAD));
    assert_eq!(value_of(&samples, METER_TEMPERATURE), None);
    assert!(value_of(&samples, THERMOCOUPLE).is_some());
    assert_ne!(status_of(&samples) & STATUS_OVERLOAD, 0);
}

#[test]
fn an_unmapped_mode_or_range_publishes_no_thermocouple_value() {
    let dcv = decoded(&edited(|b| b[MAIN_MODE] = MODE_DCV_IN_EITHER_NUMBERING));
    assert_eq!(
        value_of(&dcv, THERMOCOUPLE),
        None,
        "no DCV row is confirmed yet"
    );
    let ranged = decoded(&edited(|b| b[MAIN_FLAGS] |= RANGE_1));
    assert_eq!(
        value_of(&ranged, THERMOCOUPLE),
        None,
        "Temp has only range 0; any other is mis-scaled"
    );
}

#[test]
fn a_temperature_flagged_neither_celsius_nor_fahrenheit_publishes_nothing() {
    let unflagged = decoded(&edited(|b| b[MAIN_FLAGS] &= !CELSIUS));
    assert_eq!(value_of(&unflagged, THERMOCOUPLE), None);
}

#[test]
fn negative_and_seventeen_bit_values_decode() {
    let cold = decoded(&edited(|b| {
        b[MAIN_FLAGS] |= NEGATIVE;
        b[MAIN_VALUE_HIGH] = COLD_HIGH;
        b[MAIN_VALUE_LOW] = COLD_LOW;
    }));
    assert_eq!(
        value_of(&cold, THERMOCOUPLE),
        Some(Value::new(COLD_TENTHS, TENTHS)),
        "−100.0 °C"
    );
    let big = decoded(&edited(|b| {
        b[MAIN_MODE] |= VALUE_BIT_16;
        b[MAIN_VALUE_HIGH] = 0;
        b[MAIN_VALUE_LOW] = 0;
    }));
    assert_eq!(
        value_of(&big, THERMOCOUPLE).map(|v| v.mantissa),
        Some(SEVENTEEN_BIT),
        "bit 16 is in the mode byte"
    );
}

#[test]
fn a_relative_min_max_or_held_display_publishes_only_the_status() {
    for (name, byte, bit) in [
        ("REL", ICONS_2, 0x10),
        ("MIN/MAX bit 0", ICONS_2, 0x01),
        ("MIN/MAX bit 1", ICONS_2, 0x02),
        ("MIN/MAX bit 2", ICONS_2, 0x04),
        ("A-HOLD bit 2", ICONS_3, 0x04),
        ("A-HOLD bit 3", ICONS_3, 0x08),
    ] {
        let samples = decoded(&edited(|b| b[byte] |= bit));
        assert_eq!(
            samples.iter().map(|s| s.key).collect::<Vec<_>>(),
            [STATUS],
            "{name}"
        );
    }
}

#[test]
fn the_neighbouring_mem_ac_and_dc_icons_do_not_suppress_a_live_value() {
    for (name, bit) in [
        ("MEM bit 4", 0x10),
        ("MEM bit 5", 0x20),
        ("AC", 0x02),
        ("DC", 0x01),
    ] {
        let samples = decoded(&edited(|b| b[ICONS_3] |= bit));
        assert_eq!(
            value_of(&samples, THERMOCOUPLE),
            Some(Value::new(ROOM_TENTHS, TENTHS)),
            "{name}"
        );
    }
}

#[test]
fn the_start_up_frames_after_connecting_publish_no_temperature() {
    let temperatures: Vec<Option<Value>> = frames(ROOM)
        .iter()
        .map(|f| value_of(&decoded(f), THERMOCOUPLE))
        .collect();
    assert!(
        temperatures[..START_UP_FRAMES].iter().all(Option::is_none),
        "the meter's first frames read 0.0 and −0.3 °C with REL set; they must not reach a consumer"
    );
    assert!(
        temperatures[START_UP_FRAMES..].iter().all(Option::is_some),
        "{temperatures:?}"
    );
}

#[test]
fn the_table_lists_every_signal_it_can_publish_including_the_status() {
    assert_eq!(signals(), {
        let mut keys = vec![THERMOCOUPLE, METER_TEMPERATURE, STATUS];
        keys.sort();
        keys
    });
}

#[test]
fn status_flags_name_each_set_bit() {
    assert_eq!(status_flags(0), Vec::<&str>::new());
    assert_eq!(
        status_flags(STATUS_AUTO_POWER_OFF | STATUS_OVERLOAD),
        ["APO on", "OL"]
    );
}

const ICONS_1: usize = 15;
const SUB_MODE: usize = 9;
const COUPLING_DC: u8 = 0x08;
const COUPLING_AC: u8 = 0x10;
const COUPLING_DC_AC: u8 = 0x18;
const PEAK: u8 = 0x20;
const SUB_KILO: u8 = 0x20;
const SUB_HERTZ: u8 = 0x10;
const TEST_LOW_Z: u8 = 0;
const TEST_DC_MA: u8 = 19;
const TEST_TEMPERATURE: u8 = 5;
const TEST_BURDEN: u8 = 150;
const TEST_METER_FAHRENHEIT: u8 = 105;
const SUB_MODE_METER_CELSIUS_TEST: u8 = 100;
const LOW_Z_TENTHS: i8 = -1;
const MILLIAMP_TENTH_MICRO: i8 = -7;
const CENTI: i8 = -2;
const ROOM_FAHRENHEIT_HIGH: u8 = 0x02;
const ROOM_FAHRENHEIT_LOW: u8 = 0xBC;
const ROOM_FROM_FAHRENHEIT_CENTI: i64 = 2_111;
const FREEZING_PLUS_TENTH_F: i64 = 321;
const JUST_ABOVE_FREEZING_CENTI: i64 = 6;
const MINUS_FORTY_TENTHS: i64 = -400;
const MINUS_FORTY_CENTI: i64 = -4_000;
const LOW_Z_DC: SignalKey = signal::measurement(QTY_VOLTAGE, ASPECT_DC, CHANNEL_V_OHM);
const LOW_Z_AC: SignalKey = signal::measurement(QTY_VOLTAGE, ASPECT_AC, CHANNEL_V_OHM);
const DC_MILLIAMPS: SignalKey =
    signal::measurement(QTY_CURRENT, ASPECT_DC, CHANNEL_MICRO_MILLI_AMP);
const DC_BURDEN: SignalKey = signal::measurement(QTY_VOLTAGE, ASPECT_DC, CHANNEL_MICRO_MILLI_AMP);
const TEST: Table = Table {
    main: &[
        MainRow {
            mode: TEST_LOW_Z,
            range: 0,
            quantity: QTY_VOLTAGE,
            aspect: Aspect::Coupling,
            channel: CHANNEL_V_OHM,
            exponent: LOW_Z_TENTHS,
            unit: Unit::Plain,
        },
        MainRow {
            mode: TEST_DC_MA,
            range: 0,
            quantity: QTY_CURRENT,
            aspect: Aspect::Fixed(ASPECT_DC),
            channel: CHANNEL_MICRO_MILLI_AMP,
            exponent: MILLIAMP_TENTH_MICRO,
            unit: Unit::Plain,
        },
        MainRow {
            mode: TEST_TEMPERATURE,
            range: 0,
            quantity: QTY_TEMPERATURE,
            aspect: Aspect::Fixed(ASPECT_DEFAULT),
            channel: CHANNEL_V_OHM,
            exponent: TENTHS,
            unit: Unit::TemperatureFlags,
        },
    ],
    sub: &[
        SubRow {
            mode: TEST_BURDEN,
            source: SubSource::BurdenOfMain,
            unit: Unit::Plain,
        },
        SubRow {
            mode: TEST_METER_FAHRENHEIT,
            source: SubSource::Fixed(METER_TEMPERATURE),
            unit: Unit::Fahrenheit,
        },
        SubRow {
            mode: SUB_MODE_METER_CELSIUS_TEST,
            source: SubSource::Fixed(METER_TEMPERATURE),
            unit: Unit::Plain,
        },
    ],
};

fn in_test_table(frame: &Frame) -> Vec<Sample> {
    samples(frame, &TEST, Stamp::now())
}

fn keys(samples: &[Sample]) -> Vec<SignalKey> {
    samples.iter().map(|s| s.key).collect()
}

#[test]
fn low_z_takes_dc_or_ac_from_the_coupling_icons() {
    let dc = in_test_table(&edited(|b| {
        b[MAIN_MODE] = TEST_LOW_Z;
        b[ICONS_1] |= COUPLING_DC;
    }));
    assert!(keys(&dc).contains(&LOW_Z_DC), "{dc:?}");
    let ac = in_test_table(&edited(|b| {
        b[MAIN_MODE] = TEST_LOW_Z;
        b[ICONS_1] |= COUPLING_AC;
    }));
    assert!(keys(&ac).contains(&LOW_Z_AC), "{ac:?}");
    let neither = in_test_table(&edited(|b| b[MAIN_MODE] = TEST_LOW_Z));
    assert!(
        !keys(&neither)
            .iter()
            .any(|k| k.quantity == QTY_VOLTAGE && k.channel == CHANNEL_V_OHM),
        "{neither:?}"
    );
}

#[test]
fn dc_plus_ac_and_one_ms_peak_publish_only_the_status() {
    for (name, bits) in [("DC+AC", COUPLING_DC_AC), ("1 ms PEAK", PEAK)] {
        let samples = in_test_table(&edited(|b| b[ICONS_1] |= bits));
        assert_eq!(keys(&samples), [STATUS], "{name}: not the live signal");
    }
}

#[test]
fn burden_voltage_follows_the_current_jack_and_coupling() {
    let samples = in_test_table(&edited(|b| {
        b[MAIN_MODE] = TEST_DC_MA;
        b[SUB_MODE] = TEST_BURDEN;
    }));
    assert!(keys(&samples).contains(&DC_MILLIAMPS), "{samples:?}");
    assert!(
        keys(&samples).contains(&DC_BURDEN),
        "burden voltage sits on the current jack's channel: {samples:?}"
    );
}

#[test]
fn burden_voltage_outside_a_current_mode_publishes_nothing() {
    let samples = in_test_table(&edited(|b| b[SUB_MODE] = TEST_BURDEN));
    assert!(
        !keys(&samples).iter().any(|k| k.quantity == QTY_VOLTAGE),
        "{samples:?}"
    );
}

#[test]
fn a_fahrenheit_main_temperature_is_converted_to_celsius_hundredths() {
    let samples = in_test_table(&edited(|b| {
        b[MAIN_FLAGS] = FAHRENHEIT;
        b[MAIN_VALUE_HIGH] = ROOM_FAHRENHEIT_HIGH;
        b[MAIN_VALUE_LOW] = ROOM_FAHRENHEIT_LOW;
    }));
    assert_eq!(
        value_of(&samples, THERMOCOUPLE),
        Some(Value::new(ROOM_FROM_FAHRENHEIT_CENTI, CENTI)),
        "0x02BC is 700 tenths: 70.0 °F is 21.11 °C"
    );
}

#[test]
fn a_fahrenheit_meter_temperature_is_converted() {
    let samples = in_test_table(&edited(|b| b[SUB_MODE] = TEST_METER_FAHRENHEIT));
    assert!(
        value_of(&samples, METER_TEMPERATURE).is_some_and(|v| v.exponent == CENTI),
        "{samples:?}"
    );
}

#[test]
fn a_sub_value_flagged_k_or_hz_publishes_nothing_until_captures_define_the_flags() {
    for (name, bit) in [("k", SUB_KILO), ("Hz", SUB_HERTZ)] {
        let samples = in_test_table(&edited(|b| b[SUB_FLAGS] |= bit));
        assert_eq!(value_of(&samples, METER_TEMPERATURE), None, "{name}");
    }
}

#[test]
fn fahrenheit_conversion_rounds_half_away_from_zero_at_hundredths() {
    assert_eq!(
        fahrenheit_to_celsius(Value::new(FREEZING_PLUS_TENTH_F, TENTHS)),
        Some(Value::new(JUST_ABOVE_FREEZING_CENTI, CENTI)),
        "32.1 °F is 0.0556 °C, which rounds to 0.06"
    );
    assert_eq!(
        fahrenheit_to_celsius(Value::new(MINUS_FORTY_TENTHS, TENTHS)),
        Some(Value::new(MINUS_FORTY_CENTI, CENTI)),
        "−40 is the same on both scales"
    );
}

#[test]
fn the_test_table_lists_both_low_z_aspects_and_the_burden_voltage_it_can_produce() {
    let listed = signals_of(&TEST);
    for key in [
        LOW_Z_DC,
        LOW_Z_AC,
        DC_MILLIAMPS,
        DC_BURDEN,
        THERMOCOUPLE,
        METER_TEMPERATURE,
        STATUS,
    ] {
        assert!(listed.contains(&key), "{} missing", signal::slug(&key));
    }
    assert!(
        !listed
            .iter()
            .any(|k| k.channel == SIGNAL_CHANNEL_NONE && k.quantity == QTY_VOLTAGE)
    );
}
