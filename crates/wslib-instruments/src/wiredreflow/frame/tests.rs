use crate::{
    sample::{Sample, Stamp},
    signal::SignalKey,
    value::Value,
    wiredreflow::frame::{
        CJ1, CJ2, Decoder, RawFrame, TC1, TC1_FAULT, TC2, TC2_FAULT, device_of, display_name,
        key_named, signals,
    },
};

const RUN_F: &str = include_str!("../../../tests/fixtures/wiredreflow-run-f-2026-10-15.candump");
const BENCH_DEVICE: u32 = 0x02_8F08;
const OTHER_DEVICE: u32 = 0x03_1200;
const DECI: i8 = -1;
const UNITY: i8 = 0;
const HEX: u32 = 16;
const EXTENDED_ID_DIGITS: usize = 8;
const ID_FIELD: usize = 2;
const DATA_FROM: usize = 4;
const TC1_DECI: [i64; 8] = [232, 232, 232, 1_393, 1_393, 1_395, 1_394, 1_392];
const TC2_DECI: [i64; 8] = [227, 227, 227, 796, 800, 804, 808, 812];
const CJ1_DECI: [i64; 8] = [252, 252, 252, 251, 251, 251, 251, 251];
const CJ2_DECI: [i64; 8] = [250, 251, 250, 249, 250, 250, 250, 250];
const NO_FAULT: [i64; 8] = [0; 8];
const RUN_F_SAMPLES: usize = 48;
const THERMOCOUPLE_ID: u32 = 0x028F_0821;
const FAULT_ID: u32 = 0x028F_0825;
const HOST_THERMOCOUPLE_ID: u32 = 0x128F_0821;
const OTHER_THERMOCOUPLE_ID: u32 = 0x0312_0021;
const ROOM: [u8; 8] = [0xE8, 0x00, 0xE3, 0x00, 0xFC, 0x00, 0xFA, 0x00];
const MINUS_12_3_DECI: i64 = -123;
const MINUS_12_3: [u8; 8] = [0x85, 0xFF, 0xE3, 0x00, 0xFC, 0x00, 0xFA, 0x00];
const OPEN_CIRCUIT: u8 = 0x01;
const TC1_OPEN: [u8; 2] = [OPEN_CIRCUIT, 0x00];
const TC1_UNREACHABLE: [u8; 2] = [0xFF, 0x00];
const CLEAR: [u8; 2] = [0x00, 0x00];

fn frame(line: &str) -> RawFrame {
    let fields: Vec<&str> = line.split_whitespace().collect();
    let id = fields[ID_FIELD];
    RawFrame {
        id: u32::from_str_radix(id, HEX).unwrap(),
        extended: id.len() == EXTENDED_ID_DIGITS,
        data: fields[DATA_FROM..]
            .iter()
            .map(|byte| u8::from_str_radix(byte, HEX).unwrap())
            .collect(),
    }
}

fn broadcast(id: u32, data: &[u8]) -> RawFrame {
    RawFrame {
        id,
        extended: true,
        data: data.to_vec(),
    }
}

fn run_f() -> Vec<Sample> {
    let mut decoder = Decoder::new(BENCH_DEVICE);
    let at = Stamp::now();
    RUN_F
        .lines()
        .flat_map(|line| decoder.samples(&frame(line), at))
        .collect()
}

fn mantissas(samples: &[Sample], key: SignalKey, exponent: i8) -> Vec<i64> {
    samples
        .iter()
        .filter(|s| s.key == key)
        .map(|s| {
            assert_eq!(s.value.exponent, exponent, "{key:?}");
            s.value.mantissa
        })
        .collect()
}

#[test]
fn run_f_decodes_to_the_values_the_board_logged() {
    let samples = run_f();
    assert_eq!(
        mantissas(&samples, TC1, DECI),
        TC1_DECI,
        "cold-start-F-can-2026-10-15.csv tc1_c"
    );
    assert_eq!(mantissas(&samples, TC2, DECI), TC2_DECI, "tc2_c");
    assert_eq!(mantissas(&samples, CJ1, DECI), CJ1_DECI, "cj1_c");
    assert_eq!(mantissas(&samples, CJ2, DECI), CJ2_DECI, "cj2_c");
    assert_eq!(mantissas(&samples, TC1_FAULT, UNITY), NO_FAULT, "fault1");
    assert_eq!(mantissas(&samples, TC2_FAULT, UNITY), NO_FAULT, "fault2");
}

#[test]
fn run_f_publishes_four_temperatures_and_two_faults_per_period_and_nothing_else() {
    assert_eq!(
        run_f().len(),
        RUN_F_SAMPLES,
        "8 thermocouple frames × 4 + 8 fault frames × 2"
    );
}

#[test]
fn the_device_id_is_the_can_id_without_its_slot() {
    assert_eq!(
        device_of(&frame(RUN_F.lines().next().unwrap())),
        Some(BENCH_DEVICE)
    );
    assert_eq!(
        device_of(&broadcast(HOST_THERMOCOUPLE_ID, &ROOM)),
        None,
        "host-to-device is not a broadcast"
    );
}

#[test]
fn another_devices_frames_publish_nothing() {
    let mut decoder = Decoder::new(BENCH_DEVICE);
    assert!(
        decoder
            .samples(&broadcast(OTHER_THERMOCOUPLE_ID, &ROOM), Stamp::now())
            .is_empty()
    );
    assert_eq!(
        device_of(&broadcast(OTHER_THERMOCOUPLE_ID, &ROOM)),
        Some(OTHER_DEVICE)
    );
}

#[test]
fn a_host_to_device_or_standard_frame_publishes_nothing() {
    let mut decoder = Decoder::new(BENCH_DEVICE);
    assert!(
        decoder
            .samples(&broadcast(HOST_THERMOCOUPLE_ID, &ROOM), Stamp::now())
            .is_empty()
    );
    let standard = RawFrame {
        id: THERMOCOUPLE_ID,
        extended: false,
        data: ROOM.to_vec(),
    };
    assert!(decoder.samples(&standard, Stamp::now()).is_empty());
}

#[test]
fn a_frame_of_the_wrong_length_publishes_nothing() {
    let mut decoder = Decoder::new(BENCH_DEVICE);
    let (short, _) = ROOM.split_at(ROOM.len() / 2);
    assert!(
        decoder
            .samples(&broadcast(THERMOCOUPLE_ID, short), Stamp::now())
            .is_empty()
    );
    let mut long = ROOM.to_vec();
    long.push(0);
    assert!(
        decoder
            .samples(&broadcast(THERMOCOUPLE_ID, &long), Stamp::now())
            .is_empty()
    );
}

fn keys(samples: &[Sample]) -> Vec<SignalKey> {
    samples.iter().map(|s| s.key).collect()
}

fn period(decoder: &mut Decoder, thermocouples: &[u8], faults: &[u8]) -> Vec<Sample> {
    let at = Stamp::now();
    let mut samples = decoder.samples(&broadcast(THERMOCOUPLE_ID, thermocouples), at);
    samples.extend(decoder.samples(&broadcast(FAULT_ID, faults), at));
    samples
}

#[test]
fn a_negative_temperature_decodes_with_its_sign() {
    let mut decoder = Decoder::new(BENCH_DEVICE);
    let samples = period(&mut decoder, &MINUS_12_3, &CLEAR);
    assert_eq!(
        samples.iter().find(|s| s.key == TC1).map(|s| s.value),
        Some(Value::new(MINUS_12_3_DECI, DECI))
    );
}

#[test]
fn constructed_frames_a_faulted_channel_withholds_its_temperature_until_the_fault_clears() {
    let mut decoder = Decoder::new(BENCH_DEVICE);
    period(&mut decoder, &ROOM, &CLEAR);
    let faulted = period(&mut decoder, &ROOM, &TC1_OPEN);
    assert_eq!(
        faulted
            .iter()
            .find(|s| s.key == TC1_FAULT)
            .map(|s| s.value.mantissa),
        Some(i64::from(OPEN_CIRCUIT))
    );
    assert!(
        !keys(&faulted).contains(&TC1),
        "the faulted period's TC1 is never published: {:?}",
        keys(&faulted)
    );
    assert!(keys(&faulted).contains(&TC2), "{:?}", keys(&faulted));
    let recovered = period(&mut decoder, &ROOM, &CLEAR);
    assert!(
        keys(&recovered).contains(&TC1),
        "the first period after the fault clears: {:?}",
        keys(&recovered)
    );
}

#[test]
fn constructed_frames_an_unreachable_sensor_withholds_like_any_fault() {
    let mut decoder = Decoder::new(BENCH_DEVICE);
    let unreachable = period(&mut decoder, &ROOM, &TC1_UNREACHABLE);
    assert!(
        !keys(&unreachable).contains(&TC1),
        "{:?}",
        keys(&unreachable)
    );
    assert!(
        keys(&unreachable).contains(&TC2),
        "{:?}",
        keys(&unreachable)
    );
}

#[test]
fn constructed_frames_a_channel_faulted_from_the_first_period_never_publishes_its_temperature() {
    let mut decoder = Decoder::new(BENCH_DEVICE);
    let first = period(&mut decoder, &ROOM, &TC1_OPEN);
    assert!(!keys(&first).contains(&TC1), "{:?}", keys(&first));
    assert!(keys(&first).contains(&TC2), "{:?}", keys(&first));
}

#[test]
fn the_cold_junctions_publish_at_once_and_the_thermocouples_wait_for_their_periods_fault_frame() {
    let mut decoder = Decoder::new(BENCH_DEVICE);
    let at = Stamp::now();
    assert_eq!(
        keys(&decoder.samples(&broadcast(THERMOCOUPLE_ID, &ROOM), at)),
        [CJ1, CJ2]
    );
    let released = keys(&decoder.samples(&broadcast(FAULT_ID, &CLEAR), at));
    assert_eq!(released, [TC1, TC2, TC1_FAULT, TC2_FAULT]);
}

#[test]
fn a_lost_fault_frame_drops_only_its_periods_thermocouples() {
    let mut decoder = Decoder::new(BENCH_DEVICE);
    let at = Stamp::now();
    decoder.samples(&broadcast(THERMOCOUPLE_ID, &ROOM), at);
    decoder.samples(&broadcast(THERMOCOUPLE_ID, &MINUS_12_3), at);
    let released = decoder.samples(&broadcast(FAULT_ID, &CLEAR), at);
    assert_eq!(
        mantissas(&released, TC1, DECI),
        [MINUS_12_3_DECI],
        "the held period is replaced, never published late"
    );
}

#[test]
fn the_six_signals_have_the_boards_names_and_resolve_back() {
    let names: Vec<&str> = signals().iter().filter_map(display_name).collect();
    assert_eq!(
        names,
        ["TC1", "TC2", "CJ1", "CJ2", "TC1 fault", "TC2 fault"]
    );
    assert_eq!(key_named("CJ2"), Some(CJ2));
    assert_eq!(key_named("tc1"), None, "names match exactly");
}
