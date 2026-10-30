use crate::gw121::frame::{Assembler, FRAME_LEN};

const ROOM: &str = include_str!("../../../tests/fixtures/121gw-room-2026-09-26.notify");
const HEAT: &str = include_str!("../../../tests/fixtures/121gw-heat-2026-09-26.notify");
const ROOM_FRAMES: usize = 38;
const HEAT_FRAMES: usize = 349;
const GARBAGE_FRAMES: usize = 5;
const TEMP_ROOM: [u8; FRAME_LEN] = [
    0xF2, 0x17, 0x80, 0x00, 0x00, 0x05, 0x20, 0x00, 0xD2, 0x64, 0x01, 0x00, 0xD8, 0x15, 0x00, 0x02,
    0x40, 0x00, 0x78,
];
const START: u8 = 0xF2;

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

fn frames(fixture: &str) -> Vec<[u8; FRAME_LEN]> {
    let mut assembler = Assembler::default();
    chunks(fixture)
        .iter()
        .flat_map(|c| assembler.push(c))
        .collect()
}

#[test]
fn every_captured_frame_is_recovered_and_no_false_start_leaks() {
    assert_eq!(frames(ROOM).len(), ROOM_FRAMES);
    let heat = frames(HEAT);
    assert_eq!(
        heat.len(),
        HEAT_FRAMES,
        "13 stray 0xF2 bytes inside frames must not start frames"
    );
    assert!(heat.iter().all(|f| f.iter().fold(0, |x, b| x ^ b) == 0));
}

#[test]
fn a_frame_split_across_any_chunk_boundary_is_reassembled() {
    for split in 1..FRAME_LEN {
        let mut assembler = Assembler::default();
        let mut out = assembler.push(&TEMP_ROOM[..split]);
        out.extend(assembler.push(&TEMP_ROOM[split..]));
        assert_eq!(out, vec![TEMP_ROOM], "split at {split}");
    }
}

#[test]
fn garbage_with_stray_starts_never_hides_the_next_frame() {
    let mut assembler = Assembler::default();
    let mut garbage = vec![START; FRAME_LEN * GARBAGE_FRAMES];
    garbage.extend_from_slice(&TEMP_ROOM);
    assert_eq!(assembler.push(&garbage), vec![TEMP_ROOM]);
}
