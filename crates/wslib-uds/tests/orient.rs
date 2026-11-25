use std::time::Duration;

use wslib_isotp::testing::{Conversation as Script, Responder};
use wslib_isotp::{
    Addressing, DEFAULT_FLOW_CONTROL_WINDOW, FrameFormat, Framing, TimedFrame, detect,
};
use wslib_uds::testing::{Did, Ecu};
use wslib_uds::{
    Conversation, Endpoint, MAX_PARTNERS, Orientation, Sender, Timing, Unsettled, orient,
};

const TESTER: u32 = 0x7E0;
const ECU: u32 = 0x7E8;
const VIN: [u8; 17] = *b"ABCDEFGHJKLMNPRST";
const BETWEEN: Duration = Duration::from_millis(100);

const SHORT_READ: [u8; 3] = [0x22, 0x01, 0x00];
const LONG_READ: [u8; 3] = [0x22, 0xF1, 0x90];
const TESTER_PRESENT: [u8; 2] = [0x3E, 0x00];
const DEFAULT_SESSION: [u8; 2] = [0x10, 0x01];
const UNKNOWN_READ: [u8; 3] = [0x22, 0x12, 0x34];
const ROUTINE_START: [u8; 4] = [0x31, 0x01, 0x02, 0x03];

fn ecu() -> Ecu {
    Ecu::new()
        .with_did(0x0100, Did::readable([0x01, 0x02]))
        .with_did(0xF190, Did::readable(VIN))
        .with_did(0x0200, Did::writable([0; 17]))
        .with_routine(0x0203, [0x00])
        .with_pending(0x31, 2)
}

fn long_write() -> Vec<u8> {
    [0x2E, 0x02, 0x00].into_iter().chain(VIN).collect()
}

fn script(tester: u32, ecu_id: u32, framing: Framing, requests: &[&[u8]]) -> Vec<TimedFrame> {
    let mut ecu = ecu();
    let responder = Responder::new(framing, move |request: &[u8]| ecu.answer(request));
    let mut script = Script::new(tester, ecu_id, false, 0, responder);
    for request in requests {
        script.exchange(request);
        script.pause(BETWEEN);
    }
    script.into_frames()
}

fn single(id: u32, at_us: u64, message: &[u8]) -> TimedFrame {
    let mut data = vec![message.len() as u8];
    data.extend_from_slice(message);
    TimedFrame {
        id,
        extended: false,
        data,
        at_us,
    }
}

fn merged(mut frames: Vec<TimedFrame>, more: Vec<TimedFrame>) -> Vec<TimedFrame> {
    frames.extend(more);
    frames.sort_by_key(|frame| frame.at_us);
    frames
}

fn at(id: u32) -> Endpoint {
    Endpoint {
        id,
        address_byte: None,
    }
}

fn conversation(tester: u32, ecu: u32) -> Conversation {
    Conversation {
        extended: false,
        tester: at(tester),
        ecu: at(ecu),
        exchanges: 0,
        negative: 0,
        pending: 0,
        flow_controlled_requests: 0,
        flow_controlled_responses: 0,
    }
}

#[test]
fn a_conversation_of_single_frames_alone_is_found_and_oriented_whichever_id_is_lower() {
    for (tester, ecu) in [(TESTER, ECU), (0x7F1, 0x7E9)] {
        let frames = script(
            tester,
            ecu,
            Framing::default(),
            &[
                &SHORT_READ,
                &TESTER_PRESENT,
                &DEFAULT_SESSION,
                &UNKNOWN_READ,
                &ROUTINE_START,
            ],
        );
        assert_eq!(detect(&frames, DEFAULT_FLOW_CONTROL_WINDOW).pairs, []);
        assert_eq!(
            orient(&frames, &Timing::default()),
            Orientation {
                conversations: vec![Conversation {
                    exchanges: 5,
                    negative: 1,
                    pending: 2,
                    ..conversation(tester, ecu)
                }],
                unsettled: vec![],
            },
            "{tester:#x}"
        );
    }
}

#[test]
fn a_multi_frame_conversation_is_oriented_with_its_flow_control_counted_each_way() {
    let write = long_write();
    let frames = script(
        TESTER,
        ECU,
        Framing::default(),
        &[
            &LONG_READ,
            &write,
            &LONG_READ,
            &SHORT_READ,
            &LONG_READ,
            &write,
        ],
    );
    assert_eq!(
        orient(&frames, &Timing::default()).conversations,
        [Conversation {
            exchanges: 6,
            flow_controlled_requests: 2,
            flow_controlled_responses: 3,
            ..conversation(TESTER, ECU)
        }]
    );
}

#[test]
fn an_addressed_conversation_detect_reads_is_oriented_by_address_byte() {
    let ecu_framing = Framing::new(
        Addressing::Extended { tx: 0xF1, rx: 0x10 },
        FrameFormat::Classic,
    );
    let frames = script(
        0x6F1,
        0x610,
        ecu_framing,
        &[&LONG_READ, &SHORT_READ, &LONG_READ, &LONG_READ],
    );
    let found = orient(&frames, &Timing::default());
    assert_eq!(
        found.conversations,
        [Conversation {
            tester: Endpoint {
                id: 0x6F1,
                address_byte: Some(0x10),
            },
            ecu: Endpoint {
                id: 0x610,
                address_byte: Some(0xF1),
            },
            exchanges: 4,
            flow_controlled_responses: 3,
            ..conversation(0, 0)
        }]
    );
}

fn every_10_ms(until_us: u64, id: u32, data: impl Fn(u8) -> Vec<u8>) -> Vec<TimedFrame> {
    (0..until_us)
        .step_by(10_000)
        .enumerate()
        .map(|(i, at_us)| TimedFrame {
            id,
            extended: false,
            data: data(i as u8),
            at_us: at_us + 300,
        })
        .collect()
}

fn reply_look_alike(until_us: u64) -> Vec<TimedFrame> {
    every_10_ms(until_us, 0x100, |i| vec![0x06, 0x62, 0x01, 0x00, i, 0, 0])
}

fn counter(until_us: u64) -> Vec<TimedFrame> {
    every_10_ms(until_us, 0x102, |i| {
        vec![i, 0x22, 0x01, 0x00, 0x7E, 0x00, 0x62, 0x01]
    })
}

fn real_reads() -> Vec<TimedFrame> {
    script(TESTER, ECU, Framing::default(), &[&SHORT_READ[..]; 20])
}

fn assert_only_the_reads_found(frames: &[TimedFrame]) {
    assert_eq!(
        orient(frames, &Timing::default()),
        Orientation {
            conversations: vec![Conversation {
                exchanges: 20,
                ..conversation(TESTER, ECU)
            }],
            unsettled: vec![],
        }
    );
}

#[test]
fn periodic_ids_beside_a_real_conversation_are_not_reported() {
    let real = real_reads();
    let end = real.last().unwrap().at_us;
    let periodic = merged(reply_look_alike(end), counter(end));
    assert_only_the_reads_found(&merged(real, periodic));
}

#[test]
fn a_periodic_request_look_alike_loses_the_ecu_to_the_tester_it_was_answering() {
    let real = real_reads();
    let end = real.last().unwrap().at_us;
    let look_alike = every_10_ms(end, 0x101, |_| [&[0x03][..], &SHORT_READ].concat());
    assert_only_the_reads_found(&merged(real, look_alike));
}

#[test]
fn a_periodic_reply_look_alike_is_no_ecu_even_for_a_tester_nothing_else_answers() {
    let requests: Vec<TimedFrame> = (0..20_u64)
        .map(|round| single(TESTER, round * 100_000 + 5_000, &SHORT_READ))
        .collect();
    let until = requests.last().unwrap().at_us;
    assert_eq!(
        orient(
            &merged(requests, reply_look_alike(until)),
            &Timing::default()
        ),
        Orientation::default()
    );
}

#[test]
fn two_ecus_answering_every_functional_request_leave_the_tester_unsettled() {
    let mut frames = Vec::new();
    for round in 0..20_u64 {
        let t = round * 100_000;
        frames.push(single(0x7DF, t, &TESTER_PRESENT));
        frames.push(single(0x7E8, t + 1_000, &[0x7E, 0x00]));
        frames.push(single(0x7E9, t + 2_000, &[0x7E, 0x00]));
    }
    assert_eq!(
        orient(&frames, &Timing::default()),
        Orientation {
            conversations: vec![],
            unsettled: vec![Unsettled {
                extended: false,
                endpoint: at(0x7DF),
                side: Sender::Tester,
                candidates: vec![at(0x7E8), at(0x7E9)],
            }],
        }
    );
}

#[test]
fn two_testers_whose_requests_every_answer_could_answer_leave_the_ecu_unsettled() {
    let mut frames = Vec::new();
    for round in 0..20_u64 {
        let t = round * 100_000;
        frames.push(single(0x7E0, t, &SHORT_READ));
        frames.push(single(0x7E1, t + 1_000, &SHORT_READ));
        frames.push(single(ECU, t + 2_000, &[0x62, 0x01, 0x00, 0x01, 0x02]));
    }
    assert_eq!(
        orient(&frames, &Timing::default()),
        Orientation {
            conversations: vec![],
            unsettled: vec![Unsettled {
                extended: false,
                endpoint: at(ECU),
                side: Sender::Ecu,
                candidates: vec![at(0x7E0), at(0x7E1)],
            }],
        }
    );
}

#[test]
fn a_tester_answered_by_several_ids_none_in_most_rounds_is_unsettled() {
    let answerers = [0x7E8, 0x7E8, 0x7E8, 0x7E9, 0x7E9, 0x7EA, 0x7EA];
    let mut frames = Vec::new();
    for (round, answerer) in answerers.into_iter().enumerate() {
        let t = round as u64 * 100_000;
        frames.push(single(TESTER, t, &TESTER_PRESENT));
        frames.push(single(answerer, t + 1_000, &[0x7E, 0x00]));
    }
    assert_eq!(
        orient(&frames, &Timing::default()),
        Orientation {
            conversations: vec![],
            unsettled: vec![Unsettled {
                extended: false,
                endpoint: at(TESTER),
                side: Sender::Tester,
                candidates: vec![at(0x7E8), at(0x7E9), at(0x7EA)],
            }],
        }
    );
}

#[test]
fn ids_whose_multi_frame_messages_another_id_paced_are_not_paired_by_their_answers() {
    const PACER: u32 = 0x7E9;
    let write = long_write();
    let paced = Responder::new(Framing::default(), |_: &[u8]| Vec::new());
    let mut script = Script::new(TESTER, PACER, false, 0, paced);
    let mut answers = Vec::new();
    for _ in 0..5 {
        script.exchange(&write);
        let done = script.frames().last().unwrap().at_us;
        answers.push(single(ECU, done + 1_000, &[0x6E, 0x02, 0x00]));
        script.pause(BETWEEN);
    }
    let frames = merged(script.into_frames(), answers);
    assert_eq!(detect(&frames, DEFAULT_FLOW_CONTROL_WINDOW).pairs.len(), 1);
    assert_eq!(
        orient(&frames, &Timing::default()),
        Orientation {
            conversations: vec![],
            unsettled: vec![
                Unsettled {
                    extended: false,
                    endpoint: at(TESTER),
                    side: Sender::Tester,
                    candidates: vec![at(ECU)],
                },
                Unsettled {
                    extended: false,
                    endpoint: at(ECU),
                    side: Sender::Ecu,
                    candidates: vec![at(TESTER)],
                },
            ],
        }
    );
}

#[test]
fn a_keep_alive_while_the_ecu_is_pending_leaves_the_request_open_to_its_final_answer() {
    let frames = [
        single(TESTER, 0, &ROUTINE_START),
        single(ECU, 1_000, &[0x7F, 0x31, 0x78]),
        single(TESTER, 2_000_000, &[0x3E, 0x80]),
        single(ECU, 3_000_000, &[0x71, 0x01, 0x02, 0x03]),
    ];
    assert_eq!(
        orient(&frames, &Timing::default()).conversations,
        [Conversation {
            exchanges: 1,
            pending: 1,
            ..conversation(TESTER, ECU)
        }]
    );
}

#[test]
fn a_reply_later_than_p2_and_the_margin_answers_nothing() {
    let timing = Timing::default();
    let late = u64::try_from((timing.p2 + timing.margin).as_micros()).unwrap() + 1;
    let mut frames = Vec::new();
    for round in 0..20_u64 {
        let t = round * 1_000_000;
        frames.push(single(TESTER, t, &SHORT_READ));
        frames.push(single(ECU, t + late, &[0x62, 0x01, 0x00, 0x01, 0x02]));
    }
    assert_eq!(orient(&frames, &timing), Orientation::default());
}

#[test]
fn an_id_answering_more_testers_than_the_cap_is_unsettled_however_clear_the_lead() {
    let mut frames = Vec::new();
    for tester in 0x700..0x700 + MAX_PARTNERS as u32 + 1 {
        frames.push(single(tester, u64::from(tester), &TESTER_PRESENT));
    }
    frames.push(single(ECU, 1_000, &[0x7E, 0x00]));
    for round in 1..10_u64 {
        let t = round * 100_000;
        frames.push(single(0x700, t, &TESTER_PRESENT));
        frames.push(single(ECU, t + 1_000, &[0x7E, 0x00]));
    }
    let found = orient(&frames, &Timing::default());
    assert_eq!(found.conversations, []);
    let ecu = found
        .unsettled
        .iter()
        .find(|unsettled| unsettled.endpoint == at(ECU))
        .unwrap();
    assert_eq!(ecu.side, Sender::Ecu);
    assert_eq!(ecu.candidates.len(), MAX_PARTNERS);
}

#[test]
fn arbitrary_frames_never_panic_and_each_id_has_one_partner_per_role() {
    let mut state = 0x9E37_79B9_7F4A_7C15u64;
    let mut next = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    let leading = [
        0x02, 0x03, 0x05, 0x07, 0x10, 0x21, 0x22, 0x30, 0x31, 0x00, 0xF1, 0x10,
    ];
    let uds = [
        0x22, 0x62, 0x7F, 0x78, 0x3E, 0x7E, 0x10, 0x50, 0x31, 0x71, 0x80, 0x00,
    ];
    for _ in 0..20 {
        let mut frames = Vec::new();
        let mut at_us = 0u64;
        for _ in 0..5_000 {
            let r = next();
            at_us = match r % 50 {
                0 => at_us.saturating_sub(r >> 40),
                1 => u64::MAX - (r >> 60),
                _ => at_us.saturating_add((r >> 8) % 20_000),
            };
            let len = ((r >> 16) % 66) as usize;
            let mut data: Vec<u8> = (0..len)
                .map(|i| match next() % 3 {
                    0 if i == 0 => leading[(r >> 24) as usize % leading.len()],
                    1 => uds[(r >> 32) as usize % uds.len()],
                    _ => next() as u8,
                })
                .collect();
            if r & 0x100 != 0 {
                data.truncate(8);
            }
            frames.push(TimedFrame {
                id: 0x7E0 + (r >> 52) as u32 % 6,
                extended: r & 0x200 != 0,
                data,
                at_us,
            });
        }
        let found = orient(&frames, &Timing::default());
        let mut testers: Vec<(bool, Endpoint)> = found
            .conversations
            .iter()
            .map(|c| (c.extended, c.tester))
            .collect();
        let mut ecus: Vec<(bool, Endpoint)> = found
            .conversations
            .iter()
            .map(|c| (c.extended, c.ecu))
            .collect();
        for ids in [&mut testers, &mut ecus] {
            let len = ids.len();
            ids.sort_by_key(|(extended, endpoint)| (*extended, endpoint.id, endpoint.address_byte));
            ids.dedup();
            assert_eq!(ids.len(), len);
        }
        assert!(
            found
                .unsettled
                .iter()
                .all(|unsettled| unsettled.candidates.len() <= MAX_PARTNERS)
        );
    }
}
