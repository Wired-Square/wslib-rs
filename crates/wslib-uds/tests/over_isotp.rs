//! The simulated ECU answering over ISO-TP framing, and the frames it leaves
//! read back through the passive tap into the tracker.

use wslib_isotp::testing::{Conversation, Responder};
use wslib_isotp::{Framing, IsoTpTap, PciKind, Side, TapConfig, TapEvent, TimedFrame};
use wslib_uds::testing::{Did, Ecu};
use wslib_uds::{Observed, Outcome, Sender, Tracker};

const TESTER: u32 = 0x7E0;
const ECU: u32 = 0x7E8;
const VIN: [u8; 17] = *b"ABCDEFGHJKLMNPRST";
const ROUTINE: u16 = 0x0203;

const SHORT_READ: [u8; 3] = [0x22, 0x01, 0x00];
const LONG_READ: [u8; 3] = [0x22, 0xF1, 0x90];
const ROUTINE_START: [u8; 4] = [0x31, 0x01, 0x02, 0x03];
const UNKNOWN_READ: [u8; 3] = [0x22, 0x12, 0x34];

fn ecu() -> Ecu {
    Ecu::new()
        .with_did(0x0100, Did::readable([0x01, 0x02]))
        .with_did(0xF190, Did::readable(VIN))
        .with_did(0x0200, Did::writable([0; 17]))
        .with_routine(ROUTINE, [0x00])
        .with_pending(0x31, 2)
}

fn over_isotp(mut ecu: Ecu) -> Conversation<impl FnMut(&[u8]) -> Vec<Vec<u8>>> {
    let responder = Responder::new(Framing::default(), move |request: &[u8]| {
        ecu.answer(request)
    });
    Conversation::new(TESTER, ECU, false, 0, responder)
}

fn kinds(frames: &[TimedFrame]) -> Vec<(u32, PciKind)> {
    frames
        .iter()
        .map(|frame| (frame.id, PciKind::classify(&frame.data).unwrap()))
        .collect()
}

fn long_write() -> Vec<u8> {
    [0x2E, 0x02, 0x00].into_iter().chain(VIN).collect()
}

#[test]
fn a_short_read_is_one_single_frame_each_way() {
    let mut script = over_isotp(ecu());
    assert_eq!(
        script.exchange(&SHORT_READ),
        [vec![0x62, 0x01, 0x00, 0x01, 0x02]]
    );
    assert_eq!(
        kinds(script.frames()),
        [(TESTER, PciKind::Single), (ECU, PciKind::Single)]
    );
}

#[test]
fn a_long_did_read_comes_back_in_frames_the_tester_paces_with_flow_control() {
    let mut script = over_isotp(ecu());
    let response: Vec<u8> = [0x62, 0xF1, 0x90].into_iter().chain(VIN).collect();
    assert_eq!(script.exchange(&LONG_READ), [response]);
    assert_eq!(
        kinds(script.frames()),
        [
            (TESTER, PciKind::Single),
            (ECU, PciKind::First),
            (TESTER, PciKind::FlowControl),
            (ECU, PciKind::Consecutive),
            (ECU, PciKind::Consecutive),
        ]
    );
}

#[test]
fn a_long_write_goes_in_frames_the_ecu_paces_with_flow_control() {
    let mut script = over_isotp(ecu());
    assert_eq!(script.exchange(&long_write()), [vec![0x6E, 0x02, 0x00]]);
    assert_eq!(
        kinds(script.frames()),
        [
            (TESTER, PciKind::First),
            (ECU, PciKind::FlowControl),
            (TESTER, PciKind::Consecutive),
            (TESTER, PciKind::Consecutive),
            (ECU, PciKind::Single),
        ]
    );
}

#[test]
fn response_pending_answers_each_come_in_their_own_frame_before_the_final_answer() {
    let mut script = over_isotp(ecu());
    let pending = vec![0x7F, 0x31, 0x78];
    assert_eq!(
        script.exchange(&ROUTINE_START),
        [pending.clone(), pending, vec![0x71, 0x01, 0x02, 0x03]]
    );
    assert_eq!(
        kinds(script.frames()),
        [
            (TESTER, PciKind::Single),
            (ECU, PciKind::Single),
            (ECU, PciKind::Single),
            (ECU, PciKind::Single),
        ]
    );
}

#[test]
fn a_negative_response_comes_back_in_a_single_frame() {
    let mut script = over_isotp(ecu());
    assert_eq!(script.exchange(&UNKNOWN_READ), [vec![0x7F, 0x22, 0x31]]);
}

#[test]
fn the_tap_and_tracker_see_the_transactions_the_tester_had() {
    let mut script = over_isotp(ecu());
    let requests = [
        SHORT_READ.to_vec(),
        LONG_READ.to_vec(),
        long_write(),
        ROUTINE_START.to_vec(),
        UNKNOWN_READ.to_vec(),
        vec![0x3E, 0x80],
    ];
    let had: Vec<(Vec<u8>, Vec<Vec<u8>>)> = requests
        .iter()
        .map(|request| (request.clone(), script.exchange(request)))
        .collect();

    let mut tap = IsoTpTap::new(TapConfig::new(TESTER, ECU, false)).unwrap();
    let mut tracker = Tracker::new();
    let mut seen = Vec::new();
    for frame in script.frames() {
        for event in tap.push(frame) {
            let TapEvent::Message(message) = event else {
                panic!("{event:?}")
            };
            let sender = match message.from {
                Side::A => Sender::Tester,
                Side::B => Sender::Ecu,
            };
            seen.extend(tracker.observe(sender, &message.data, message.last_at_us));
        }
    }
    seen.extend(tracker.finish());

    let saw: Vec<(Vec<u8>, u32, Option<Vec<u8>>)> = seen
        .into_iter()
        .map(|observed| match observed {
            Observed::Transaction(t) => match t.outcome {
                Outcome::Answered { response, .. } => {
                    (t.request, t.pending_responses, Some(response))
                }
                Outcome::Suppressed => (t.request, t.pending_responses, None),
                other => panic!("{other:?}"),
            },
            other => panic!("{other:?}"),
        })
        .collect();
    let expected: Vec<(Vec<u8>, u32, Option<Vec<u8>>)> = had
        .into_iter()
        .map(|(request, mut responses)| {
            let last = responses.pop();
            (request, responses.len() as u32, last)
        })
        .collect();
    assert_eq!(saw, expected);
}
