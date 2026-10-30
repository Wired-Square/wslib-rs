use wslib_instruments::{
    gw121::{Replay, decode::THERMOCOUPLE},
    sample::Stamp,
};

const ROOM: &str = include_str!("fixtures/121gw-room-2026-09-26.notify");
const ROOM_FRAMES: usize = 38;
const TEMPERATURE_MODE: u8 = 5;
const ROOM_TENTHS: i64 = 210;

fn chunk(line: &str) -> Vec<u8> {
    let hex = line.split_once(' ').unwrap().1;
    (0..hex.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&hex[at..at + 2], 16).unwrap())
        .collect()
}

#[test]
fn a_capture_replays_to_every_frame_with_its_mode_and_samples() {
    let mut replay = Replay::default();
    let stamp = Stamp::now();
    let frames: Vec<_> = ROOM
        .lines()
        .flat_map(|line| replay.push(&(stamp, chunk(line))))
        .collect();
    assert_eq!(frames.len(), ROOM_FRAMES);
    let last = frames.last().unwrap();
    assert_eq!((last.mode, last.range), (TEMPERATURE_MODE, 0));
    let thermocouple = last
        .samples
        .iter()
        .find(|sample| sample.key == THERMOCOUPLE);
    assert_eq!(
        thermocouple.map(|sample| (sample.value.mantissa, sample.wall_clock)),
        Some((ROOM_TENTHS, stamp.wall_clock))
    );
}
