use std::time::Duration;

use wslib_isotp::testing::{Conversation, Responder};
use wslib_isotp::{
    Addressing, DEFAULT_FLOW_CONTROL_WINDOW, FdLength, FlowControl, FlowStatus, FrameFormat,
    Framing, IsoTpTap, NoticeKind, Side, StMin, TapConfig, TapEvent, TimedFrame, detect,
};

const TESTER: u32 = 0x7E0;
const ECU: u32 = 0x7E8;
const SIZES: [usize; 7] = [1, 7, 8, 20, 63, 200, 4095];
const ECU_BLOCK: u8 = 3;
const ECU_ST_MIN: StMin = StMin(0x02);
const TESTER_BLOCK: u8 = 5;
const TESTER_ST_MIN: StMin = StMin(0xF3);
const WAITS: u8 = 2;
const WAIT_GAP: Duration = Duration::from_millis(20);

fn message(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i * 11 + len) as u8).collect()
}

fn reversed(request: &[u8]) -> Vec<Vec<u8>> {
    vec![request.iter().rev().copied().collect()]
}

fn ecu_framings() -> Vec<Framing> {
    let mut padded = Framing::new(
        Addressing::Extended { tx: 0xF1, rx: 0x10 },
        FrameFormat::Classic,
    );
    padded.padding = Some(0xAA);
    vec![
        Framing::default(),
        padded,
        Framing::new(
            Addressing::Normal,
            FrameFormat::Fd {
                length: FdLength::MAX,
            },
        ),
        Framing::new(
            Addressing::Mixed { tx: 0x33, rx: 0x44 },
            FrameFormat::Fd {
                length: FdLength::new(12).unwrap(),
            },
        ),
    ]
}

fn conversation(ecu: Framing) -> Conversation<impl FnMut(&[u8]) -> Vec<Vec<u8>>> {
    let responder = Responder::new(ecu, reversed)
        .flow_control(ECU_BLOCK, ECU_ST_MIN)
        .waits(WAITS, WAIT_GAP);
    Conversation::new(TESTER, ECU, false, 0, responder)
        .tester_flow_control(TESTER_BLOCK, TESTER_ST_MIN)
}

fn tap_for(ecu: &Framing) -> IsoTpTap {
    let mut config = TapConfig::new(TESTER, ECU, false);
    config.framing = ecu.peer();
    IsoTpTap::new(config).unwrap()
}

fn feed(tap: &mut IsoTpTap, frames: &[TimedFrame]) -> Vec<TapEvent> {
    frames.iter().flat_map(|frame| tap.push(frame)).collect()
}

fn cts(block_size: u8, st_min: StMin) -> FlowControl {
    FlowControl {
        status: FlowStatus::ContinueToSend,
        block_size,
        st_min,
    }
}

#[test]
fn the_tap_reassembles_a_scripted_conversation_in_every_framing() {
    for ecu in ecu_framings() {
        let mut script = conversation(ecu);
        let mut expected = Vec::new();
        for len in SIZES {
            let request = message(len);
            let responses = script.exchange(&request);
            assert_eq!(responses, reversed(&request), "{ecu:?} {len}");
            expected.push((Side::A, request));
            expected.extend(responses.into_iter().map(|response| (Side::B, response)));
            script.pause(Duration::from_millis(50));
        }
        let frames = script.into_frames();
        let mut seen = Vec::new();
        for event in feed(&mut tap_for(&ecu), &frames) {
            match event {
                TapEvent::Message(message) => {
                    let at = |at_us| frames.iter().position(|f| f.at_us == at_us).unwrap();
                    let (first, last) = (at(message.first_at_us), at(message.last_at_us));
                    let sender = if message.from == Side::A { TESTER } else { ECU };
                    let sent = frames[first..=last]
                        .iter()
                        .filter(|f| f.id == sender)
                        .count();
                    assert_eq!(message.frames as usize, sent, "{ecu:?}");
                    if message.frames > 1 {
                        let flow = match message.from {
                            Side::A => cts(ECU_BLOCK, ECU_ST_MIN),
                            Side::B => cts(TESTER_BLOCK, TESTER_ST_MIN),
                        };
                        assert!(message.flow_controls.contains(&flow), "{ecu:?}");
                    }
                    seen.push((message.from, message.data));
                }
                TapEvent::Notice(notice) => {
                    assert_eq!(
                        (notice.side, notice.kind),
                        (Side::A, NoticeKind::Wait),
                        "{ecu:?}"
                    );
                }
            }
        }
        assert_eq!(seen, expected, "{ecu:?}");
    }
}

#[test]
fn a_replayed_capture_gives_what_the_live_bus_gave() {
    let ecu = ecu_framings()[1];
    let mut script = conversation(ecu);
    for len in SIZES {
        script.exchange(&message(len));
    }
    let live = feed(&mut tap_for(&ecu), script.frames());
    let saved = serde_json::to_string(script.frames()).unwrap();
    let replayed: Vec<TimedFrame> = serde_json::from_str(&saved).unwrap();
    assert_eq!(replayed, script.frames());
    let again = feed(&mut tap_for(&ecu), &replayed);
    assert_eq!(again, live);
    let events = serde_json::to_string(&live).unwrap();
    assert_eq!(
        serde_json::from_str::<Vec<TapEvent>>(&events).unwrap(),
        live
    );
}

#[test]
fn a_frame_lost_from_the_capture_is_reported_and_the_tap_recovers() {
    let ecu = Framing::default();
    let mut script = conversation(ecu);
    script.exchange(&message(100));
    script.exchange(&[0x3E, 0x00]);
    let mut frames = script.into_frames();
    let lost = frames
        .iter()
        .position(|frame| frame.id == TESTER && frame.data[0] == 0x23)
        .unwrap();
    frames.remove(lost);
    let events = feed(&mut tap_for(&ecu), &frames);
    let notices: Vec<NoticeKind> = events
        .iter()
        .filter_map(|event| match event {
            TapEvent::Notice(notice) if notice.kind != NoticeKind::Wait => Some(notice.kind),
            _ => None,
        })
        .collect();
    assert_eq!(
        notices[0],
        NoticeKind::OutOfSequence {
            expected: 3,
            received: 4
        }
    );
    assert!(matches!(notices[1], NoticeKind::Resynchronised { .. }));
    assert!(events.iter().any(|event| matches!(
        event,
        TapEvent::Message(message) if message.data == [0x3E, 0x00]
    )));
}

#[test]
fn detection_finds_the_scripted_conversation_among_periodic_traffic() {
    let ecu = ecu_framings()[1];
    let mut script = conversation(ecu);
    for len in SIZES {
        script.exchange(&message(len));
    }
    let mut frames = script.into_frames();
    for i in 0..500_u32 {
        frames.push(TimedFrame {
            id: 0x101,
            extended: false,
            data: vec![0x10, 0x30, i as u8, 0x21, 0, 0, 0, 0],
            at_us: u64::from(i) * 10_000,
        });
    }
    frames.sort_by_key(|frame| frame.at_us);
    let detection = detect(&frames, DEFAULT_FLOW_CONTROL_WINDOW);
    let iso_tp: Vec<u32> = detection
        .ids
        .iter()
        .filter(|ids| ids.iso_tp)
        .map(|ids| ids.id)
        .collect();
    assert_eq!(iso_tp.len(), 2);
    assert!(iso_tp.contains(&TESTER) && iso_tp.contains(&ECU));
    assert_eq!(detection.pairs.len(), 1);
    assert_eq!(
        detection.pairs[0].addressing,
        Addressing::Extended { tx: 0x10, rx: 0xF1 }
    );
}
