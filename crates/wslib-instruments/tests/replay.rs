use wslib_instruments::{
    gw121::{Replay, decode::THERMOCOUPLE, notify},
    sample::Stamp,
};

const ROOM: &str = include_str!("fixtures/121gw-room-2026-09-26.notify");
const HEAT: &str = include_str!("fixtures/121gw-heat-2026-09-26.notify");
const ROOM_FRAMES: usize = 38;
const HEAT_FRAMES: usize = 349;
const TEMPERATURE_MODE: u8 = 5;
const ROOM_TENTHS: i64 = 210;

#[test]
fn a_capture_replays_to_every_frame_with_its_mode_and_samples() {
    let chunks = notify::parse(ROOM, Stamp::now()).unwrap();
    let mut replay = Replay::default();
    let frames: Vec<_> = chunks.iter().flat_map(|chunk| replay.push(chunk)).collect();
    assert_eq!(frames.len(), ROOM_FRAMES);
    let last = frames.last().unwrap();
    assert_eq!((last.mode, last.range), (TEMPERATURE_MODE, 0));
    let thermocouple = last
        .samples
        .iter()
        .find(|sample| sample.key == THERMOCOUPLE);
    let completed_by = chunks.last().unwrap().0;
    assert_eq!(
        thermocouple.map(|sample| (sample.value.mantissa, sample.wall_clock)),
        Some((ROOM_TENTHS, completed_by.wall_clock))
    );
}

#[test]
fn every_shipped_capture_parses_and_replays() {
    for (capture, frames) in [(ROOM, ROOM_FRAMES), (HEAT, HEAT_FRAMES)] {
        let mut replay = Replay::default();
        let replayed: usize = notify::parse(capture, Stamp::now())
            .unwrap()
            .iter()
            .map(|chunk| replay.push(chunk).len())
            .sum();
        assert_eq!(replayed, frames);
    }
}
