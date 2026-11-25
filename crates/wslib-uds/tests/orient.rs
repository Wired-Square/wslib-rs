use std::time::Duration;

use wslib_isotp::testing::{Conversation as Script, Responder};
use wslib_isotp::{
    Addressing, DEFAULT_FLOW_CONTROL_WINDOW, FdLength, FrameFormat, Framing, TimedFrame, detect,
};
use wslib_uds::testing::{Did, Ecu};
use wslib_uds::{
    Conversation, Endpoint, MAX_MESSAGE_BYTES, MAX_PARTNERS, Orientation, Sender, Timing,
    Unsettled, orient,
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
    scripted(tester, ecu_id, false, 0, framing, requests)
}

fn scripted(
    tester: u32,
    ecu_id: u32,
    extended: bool,
    start_us: u64,
    framing: Framing,
    requests: &[&[u8]],
) -> Vec<TimedFrame> {
    let mut ecu = ecu();
    let responder = Responder::new(framing, move |request: &[u8]| ecu.answer(request));
    let mut script = Script::new(tester, ecu_id, extended, start_us, responder);
    for request in requests {
        script.exchange(request);
        script.pause(BETWEEN);
    }
    script.into_frames()
}

fn raw(id: u32, at_us: u64, data: &[u8]) -> TimedFrame {
    TimedFrame {
        id,
        extended: false,
        data: data.to_vec(),
        at_us,
    }
}

fn single(id: u32, at_us: u64, message: &[u8]) -> TimedFrame {
    let mut data = vec![message.len() as u8];
    data.extend_from_slice(message);
    raw(id, at_us, &data)
}

fn unsettled(id: u32, side: Sender, candidates: &[u32]) -> Unsettled {
    Unsettled {
        extended: false,
        endpoint: at(id),
        side,
        candidates: candidates.iter().copied().map(at).collect(),
    }
}

fn rounds(count: u64, frames: impl Fn(u64) -> Vec<TimedFrame>) -> Vec<TimedFrame> {
    (0..count)
        .flat_map(|round| frames(round * 100_000))
        .collect()
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

/// The reads alone are paired, and neither of their ids is unsettled.
fn assert_only_the_reads_found(frames: &[TimedFrame]) {
    let found = orient(frames, &Timing::default());
    assert_eq!(
        found.conversations,
        [Conversation {
            exchanges: 20,
            ..conversation(TESTER, ECU)
        }]
    );
    assert!(
        found
            .unsettled
            .iter()
            .all(|u| u.endpoint != at(TESTER) && u.endpoint != at(ECU)),
        "{found:#?}"
    );
}

#[test]
fn periodic_ids_beside_a_real_conversation_are_never_paired() {
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
            unsettled: vec![
                unsettled(TESTER, Sender::Tester, &[0x7E8, 0x7E9, 0x7EA]),
                unsettled(0x7E8, Sender::Ecu, &[TESTER]),
                unsettled(0x7E9, Sender::Ecu, &[TESTER]),
                unsettled(0x7EA, Sender::Ecu, &[TESTER]),
            ],
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
fn real_conversations_in_noise_never_panic_and_pair_each_id_once_a_role_one_way_only() {
    let mut state = 0x9E37_79B9_7F4A_7C15u64;
    let mut next = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    let write = long_write();
    let requests: [&[u8]; 7] = [
        &SHORT_READ,
        &LONG_READ,
        &TESTER_PRESENT,
        &DEFAULT_SESSION,
        &UNKNOWN_READ,
        &ROUTINE_START,
        &write,
    ];
    let leading = [0x02, 0x03, 0x05, 0x07, 0x10, 0x21, 0x30, 0x00];
    let uds = [
        0x22, 0x62, 0x7F, 0x78, 0x3E, 0x7E, 0x10, 0x50, 0x31, 0x71, 0x80,
    ];
    let mut paired = 0;
    for _ in 0..20 {
        let mut frames = Vec::new();
        for pair in 0..3 {
            let picks: Vec<&[u8]> = (0..next() % 16)
                .map(|_| requests[next() as usize % requests.len()])
                .collect();
            let start_us = next() % 1_000_000;
            frames.extend(scripted(
                0x7E0 + pair,
                0x7E8 + pair,
                false,
                start_us,
                Framing::default(),
                &picks,
            ));
        }
        let end_us = frames.iter().map(|frame| frame.at_us).max().unwrap_or(0) + 1;
        for _ in 0..1_000 {
            let r = next();
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
                id: 0x7E0 + (r >> 52) as u32 % 16,
                extended: r % 7 == 0,
                data,
                at_us: next() % end_us,
            });
        }
        frames.sort_by_key(|frame| frame.at_us);
        for _ in 0..20 {
            let at = next() as usize % frames.len();
            frames[at].at_us = [0, u64::MAX, next()][at % 3];
        }

        let found = orient(&frames, &Timing::default());
        paired += found.conversations.len();
        let role = |side: Sender, c: &Conversation| match side {
            Sender::Tester => (c.extended, c.tester),
            Sender::Ecu => (c.extended, c.ecu),
        };
        for side in [Sender::Tester, Sender::Ecu] {
            let mut ids: Vec<(bool, Endpoint)> =
                found.conversations.iter().map(|c| role(side, c)).collect();
            let len = ids.len();
            ids.sort_by_key(|(extended, e)| (*extended, e.id, e.address_byte));
            ids.dedup();
            assert_eq!(ids.len(), len, "{found:#?}");
            assert!(
                found
                    .unsettled
                    .iter()
                    .filter(|u| u.side == side)
                    .all(|u| !ids.contains(&(u.extended, u.endpoint))),
                "{found:#?}"
            );
        }
        for c in &found.conversations {
            assert!(
                !found
                    .conversations
                    .iter()
                    .any(|back| (back.tester, back.ecu) == (c.ecu, c.tester)),
                "{found:#?}"
            );
        }
        assert!(
            found
                .unsettled
                .iter()
                .all(|u| (1..=MAX_PARTNERS).contains(&u.candidates.len()))
        );
    }
    assert!(paired > 10, "{paired}");
}

#[test]
fn a_message_whose_first_byte_is_no_iso_request_service_opens_no_request() {
    let byte_one_0x40_apart = rounds(50, |t| {
        vec![
            raw(0x1A0, t, &[0x01, 0x00, t as u8, 0, 0, 0, 0, 0]),
            raw(
                0x2B0,
                t + 3_000,
                &[0x04, 0x40, 0x12, t as u8, 0x55, 0, 0, 0],
            ),
        ]
    });
    let byte_one_0x7f = rounds(50, |t| {
        vec![
            raw(0x1A0, t, &[0x02, 0x00, 0x00, 0, 0, 0, 0, 0]),
            raw(
                0x2B0,
                t + 3_000,
                &[0x05, 0x7F, 0x00, 0x10, t as u8, 0, 0, 0],
            ),
        ]
    });
    let a_response_id_as_request = rounds(50, |t| {
        vec![
            single(0x300, t, &[0x62, 0x01, 0x00, 0xAA]),
            single(0x301, t + 1_000, &[0xA2, 0x01, 0x00]),
        ]
    });
    let both_ways_0x7f = rounds(50, |t| {
        vec![
            raw(0x400, t, &[0x03, 0x7F, 0x7F, 0x7F, 0, 0, 0, 0]),
            raw(0x401, t + 5_000, &[0x03, 0x7F, 0x7F, 0x7F, 0, 0, 0, 0]),
        ]
    });
    let one_coincidence = vec![
        raw(0x1A0, 0, &[0x01, 0x00, 0, 0, 0, 0, 0, 0]),
        raw(0x2B0, 50_000, &[0x04, 0x40, 0x12, 0, 0x55, 0, 0, 0]),
    ];
    for frames in [
        byte_one_0x40_apart,
        byte_one_0x7f,
        a_response_id_as_request,
        both_ways_0x7f,
        one_coincidence,
    ] {
        assert_eq!(orient(&frames, &Timing::default()), Orientation::default());
    }
}

#[test]
fn a_message_that_does_not_decode_as_its_service_opens_no_request() {
    let frames = rounds(20, |t| {
        vec![
            single(TESTER, t, &[0x22, 0x01]),
            single(ECU, t + 1_000, &[0x62, 0x01, 0x00, 0x01]),
        ]
    });
    assert_eq!(orient(&frames, &Timing::default()), Orientation::default());
}

#[test]
fn a_periodic_pair_at_twice_or_half_the_rate_is_neither_tester_nor_ecu() {
    for (request_every, reply_every) in [(10_000, 20_000), (20_000, 10_000)] {
        let mut frames = Vec::new();
        for t in (0..2_000_000).step_by(request_every) {
            frames.push(single(0x1A0, t, &TESTER_PRESENT));
        }
        for t in (0..2_000_000).step_by(reply_every) {
            frames.push(single(0x2B0, t + 3_000, &[0x7E, 0x00]));
        }
        frames.sort_by_key(|frame| frame.at_us);
        assert_eq!(
            orient(&frames, &Timing::default()),
            Orientation::default(),
            "{request_every} {reply_every}"
        );
    }
}

#[test]
fn a_rival_with_more_than_an_eighth_of_the_leaders_exchanges_leaves_the_id_unsettled() {
    let functional = rounds(20, |t| {
        let mut frames = vec![
            single(0x7DF, t, &TESTER_PRESENT),
            single(0x7E8, t + 1_000, &[0x7E, 0x00]),
        ];
        if t != 700_000 {
            frames.push(single(0x7E9, t + 2_000, &[0x7E, 0x00]));
        }
        frames
    });
    assert_eq!(
        orient(&functional, &Timing::default()),
        Orientation {
            conversations: vec![],
            unsettled: vec![
                unsettled(0x7DF, Sender::Tester, &[0x7E8, 0x7E9]),
                unsettled(0x7E8, Sender::Ecu, &[0x7DF]),
                unsettled(0x7E9, Sender::Ecu, &[0x7DF]),
            ],
        }
    );
    let two_testers = rounds(20, |t| {
        let mut frames = vec![single(0x7E0, t, &SHORT_READ)];
        if t != 700_000 {
            frames.push(single(0x7E1, t + 1_000, &SHORT_READ));
        }
        frames.push(single(ECU, t + 2_000, &[0x62, 0x01, 0x00, 0x01, 0x02]));
        frames
    });
    assert_eq!(
        orient(&two_testers, &Timing::default()),
        Orientation {
            conversations: vec![],
            unsettled: vec![
                unsettled(0x7E0, Sender::Tester, &[ECU]),
                unsettled(0x7E1, Sender::Tester, &[ECU]),
                unsettled(ECU, Sender::Ecu, &[0x7E0, 0x7E1]),
            ],
        }
    );
}

#[test]
fn a_rival_with_at_most_an_eighth_of_the_leaders_exchanges_is_unsettled_beside_the_pair() {
    let frames = rounds(16, |t| {
        let mut frames = vec![
            single(0x7DF, t, &TESTER_PRESENT),
            single(0x7E8, t + 1_000, &[0x7E, 0x00]),
        ];
        if t < 200_000 {
            frames.push(single(0x7E9, t + 2_000, &[0x7E, 0x00]));
        }
        frames
    });
    assert_eq!(
        orient(&frames, &Timing::default()),
        Orientation {
            conversations: vec![Conversation {
                exchanges: 16,
                ..conversation(0x7DF, 0x7E8)
            }],
            unsettled: vec![unsettled(0x7E9, Sender::Ecu, &[0x7DF])],
        }
    );
}

#[test]
fn a_tester_whose_ecu_settled_on_another_tester_is_unsettled() {
    let frames = rounds(20, |t| {
        let mut frames = vec![
            single(0x7E0, t, &SHORT_READ),
            single(ECU, t + 1_000, &[0x62, 0x01, 0x00, 0x01, 0x02]),
        ];
        if t < 200_000 {
            frames.push(single(0x7E1, t + 50_000, &[0x22, 0x02, 0x00]));
            frames.push(single(ECU, t + 51_000, &[0x62, 0x02, 0x00, 0x01]));
        }
        frames
    });
    assert_eq!(
        orient(&frames, &Timing::default()),
        Orientation {
            conversations: vec![Conversation {
                exchanges: 20,
                ..conversation(0x7E0, ECU)
            }],
            unsettled: vec![unsettled(0x7E1, Sender::Tester, &[ECU])],
        }
    );
}

#[test]
fn ids_that_each_diagnose_the_other_are_reported_in_neither_orientation() {
    let (a, b, c, d) = (0x700, 0x701, 0x702, 0x703);
    let mut frames = rounds(5, |t| {
        vec![
            single(a, t, &SHORT_READ),
            single(b, t + 1_000, &[0x62, 0x01, 0x00, 0x01]),
            single(b, t + 2_000, &[0x22, 0x02, 0x00]),
            single(a, t + 3_000, &[0x62, 0x02, 0x00, 0x01]),
        ]
    });
    frames.extend([
        single(c, 600_000, &[0x22, 0x03, 0x00]),
        single(b, 601_000, &[0x62, 0x03, 0x00, 0x01]),
        single(d, 700_000, &[0x22, 0x04, 0x00]),
        single(a, 701_000, &[0x62, 0x04, 0x00, 0x01]),
    ]);
    let found = orient(&frames, &Timing::default());
    assert_eq!(found.conversations, [], "{found:#?}");
    for (id, side) in [
        (a, Sender::Tester),
        (a, Sender::Ecu),
        (b, Sender::Tester),
        (b, Sender::Ecu),
    ] {
        assert!(
            found
                .unsettled
                .iter()
                .any(|u| u.endpoint == at(id) && u.side == side),
            "{id:#x} {side:?}: {found:#?}"
        );
    }
}

/// Three rounds of a read answered by a `len`-byte response in an escaped
/// first frame and its consecutive frames.
fn long_responses(len: usize) -> Vec<TimedFrame> {
    let mut frames = Vec::new();
    let mut t = 0;
    for _ in 0..3 {
        frames.push(single(TESTER, t, &LONG_READ));
        t += 1_000;
        let mut first = vec![0x10, 0x00];
        first.extend_from_slice(&(len as u32).to_be_bytes());
        first.extend_from_slice(&[0x62, 0xF1]);
        frames.push(raw(ECU, t, &first));
        t += 500;
        frames.push(raw(TESTER, t, &[0x30, 0x00, 0x00]));
        let mut sn = 1;
        for _ in (2..len).step_by(7) {
            t += 200;
            frames.push(raw(
                ECU,
                t,
                &[0x20 | sn, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90],
            ));
            sn = (sn + 1) & 0x0F;
        }
        t += 100_000;
    }
    frames
}

#[test]
fn a_response_up_to_max_message_bytes_is_an_exchange_and_one_byte_over_is_not() {
    for len in [5_000, MAX_MESSAGE_BYTES] {
        let frames = long_responses(len);
        assert_eq!(detect(&frames, DEFAULT_FLOW_CONTROL_WINDOW).pairs.len(), 1);
        assert_eq!(
            orient(&frames, &Timing::default()).conversations,
            [Conversation {
                exchanges: 3,
                flow_controlled_responses: 3,
                ..conversation(TESTER, ECU)
            }],
            "{len}"
        );
    }
    let over = long_responses(MAX_MESSAGE_BYTES + 1);
    assert_eq!(orient(&over, &Timing::default()), Orientation::default());
}

#[test]
fn an_answer_past_the_per_request_partner_cap_counts_as_answering_nothing() {
    let late = 0x7E0 + MAX_PARTNERS as u32 + 1;
    let mut frames = rounds(20, |t| {
        let mut frames = vec![single(0x700, t, &TESTER_PRESENT)];
        for (i, ecu) in (0x7E1..=late).enumerate() {
            frames.push(single(ecu, t + 1_000 + i as u64, &[0x7E, 0x00]));
        }
        frames
    });
    frames.push(single(0x701, 3_000_000, &TESTER_PRESENT));
    frames.push(single(late, 3_001_000, &[0x7E, 0x00]));
    assert_eq!(orient(&frames, &Timing::default()).conversations, []);
}

#[test]
fn a_refusal_of_a_suppressed_request_is_an_exchange() {
    let frames = rounds(20, |t| {
        vec![
            single(TESTER, t, &[0x10, 0x83]),
            single(ECU, t + 1_000, &[0x7F, 0x10, 0x12]),
        ]
    });
    assert_eq!(
        orient(&frames, &Timing::default()).conversations,
        [Conversation {
            exchanges: 20,
            negative: 20,
            ..conversation(TESTER, ECU)
        }]
    );
}

#[test]
fn a_tester_present_while_the_ecu_is_pending_costs_no_exchange() {
    let frames = [
        single(TESTER, 0, &ROUTINE_START),
        single(ECU, 1_000, &[0x7F, 0x31, 0x78]),
        single(TESTER, 2_000_000, &TESTER_PRESENT),
        single(ECU, 2_001_000, &[0x7E, 0x00]),
        single(ECU, 3_000_000, &[0x71, 0x01, 0x02, 0x03]),
    ];
    assert_eq!(
        orient(&frames, &Timing::default()).conversations,
        [Conversation {
            exchanges: 2,
            pending: 1,
            ..conversation(TESTER, ECU)
        }]
    );
}

#[test]
fn a_reply_is_in_time_up_to_p2_plus_the_margin_or_p2_star_plus_the_margin_after_pending() {
    let timing = Timing::default();
    let micros = |span: Duration| u64::try_from(span.as_micros()).unwrap();
    let p2 = micros(timing.p2 + timing.margin);
    let p2_star = micros(timing.p2_star + timing.margin);
    for (after_pending, in_time) in [(false, true), (true, true), (false, false), (true, false)] {
        let wait = match after_pending {
            false => p2,
            true => p2_star,
        } + u64::from(!in_time);
        let frames = rounds(5, |t| {
            let t = t * 100;
            let mut frames = vec![single(TESTER, t, &ROUTINE_START)];
            let mut since = t;
            if after_pending {
                since += 1_000;
                frames.push(single(ECU, since, &[0x7F, 0x31, 0x78]));
            }
            frames.push(single(ECU, since + wait, &[0x71, 0x01, 0x02, 0x03]));
            frames
        });
        let exchanges = orient(&frames, &timing).conversations.len();
        assert_eq!(exchanges, usize::from(in_time), "{after_pending} {in_time}");
    }
}

#[test]
fn a_29_bit_conversation_is_found_and_a_29_bit_id_never_pairs_with_an_11_bit_one() {
    let frames = scripted(
        0x18DA10F1,
        0x18DAF110,
        true,
        0,
        Framing::default(),
        &[&SHORT_READ, &LONG_READ, &SHORT_READ],
    );
    assert_eq!(
        orient(&frames, &Timing::default()).conversations,
        [Conversation {
            extended: true,
            exchanges: 3,
            flow_controlled_responses: 1,
            ..conversation(0x18DA10F1, 0x18DAF110)
        }]
    );
    let mixed = rounds(10, |t| {
        let mut reply = single(ECU, t + 1_000, &[0x62, 0x01, 0x00, 0x01]);
        reply.extended = true;
        vec![single(TESTER, t, &SHORT_READ), reply]
    });
    assert_eq!(orient(&mixed, &Timing::default()), Orientation::default());
}

#[test]
fn a_can_fd_conversation_is_found_escaped_single_frames_included() {
    let fd = Framing::new(
        Addressing::Normal,
        FrameFormat::Fd {
            length: FdLength::MAX,
        },
    );
    let frames = script(TESTER, ECU, fd, &[&LONG_READ, &SHORT_READ, &long_write()]);
    assert!(frames.iter().any(|frame| frame.data[..2] == [0x00, 0x14]));
    assert_eq!(
        orient(&frames, &Timing::default()).conversations,
        [Conversation {
            exchanges: 3,
            ..conversation(TESTER, ECU)
        }]
    );
}

#[test]
fn ids_relaying_each_others_requests_and_answers_pair_nothing() {
    let frames = rounds(20, |t| {
        vec![
            single(0x7E0, t, &SHORT_READ),
            single(0x6E0, t + 300, &SHORT_READ),
            single(0x7E8, t + 2_000, &[0x62, 0x01, 0x00, 1, 2]),
            single(0x6E8, t + 2_300, &[0x62, 0x01, 0x00, 1, 2]),
        ]
    });
    assert_eq!(orient(&frames, &Timing::default()).conversations, []);
}

#[test]
fn two_conversations_interleaved_with_distinct_requests_are_each_found() {
    let frames = rounds(20, |t| {
        vec![
            single(0x7E0, t, &SHORT_READ),
            single(0x7E1, t + 100, &[0x22, 0x02, 0x00]),
            single(0x7E9, t + 2_000, &[0x62, 0x02, 0x00, 1, 2]),
            single(0x7E8, t + 2_100, &[0x62, 0x01, 0x00, 1, 2]),
        ]
    });
    assert_eq!(
        orient(&frames, &Timing::default()).conversations,
        [
            Conversation {
                exchanges: 20,
                ..conversation(0x7E1, 0x7E9)
            },
            Conversation {
                exchanges: 20,
                ..conversation(0x7E0, 0x7E8)
            },
        ]
    );
}

#[test]
fn a_reply_stamped_before_its_request_answers_nothing_and_no_stamp_panics() {
    let timing = Timing {
        p2: Duration::MAX,
        p2_star: Duration::MAX,
        margin: Duration::MAX,
        ..Timing::default()
    };
    let frames = [
        single(TESTER, u64::MAX, &SHORT_READ),
        single(ECU, u64::MAX, &[0x62, 0x01, 0x00, 1]),
        single(TESTER, 10, &SHORT_READ),
        single(ECU, 5, &[0x62, 0x01, 0x00, 1]),
    ];
    assert_eq!(
        orient(&frames[..2], &timing).conversations,
        [Conversation {
            exchanges: 1,
            ..conversation(TESTER, ECU)
        }]
    );
    assert_eq!(orient(&frames, &timing), Orientation::default());
    assert_eq!(orient(&[], &timing), Orientation::default());
    assert_eq!(
        orient(&[raw(1, 0, &[]), raw(1, 0, &[])], &timing),
        Orientation::default()
    );
}

#[test]
fn a_response_with_a_consecutive_frame_out_of_sequence_is_no_answer() {
    let frames = rounds(10, |t| {
        vec![
            single(TESTER, t, &LONG_READ),
            raw(ECU, t + 1_000, &[0x10, 0x0A, 0x62, 0xF1, 0x90, 1, 2, 3]),
            raw(TESTER, t + 1_500, &[0x30, 0, 0]),
            raw(ECU, t + 2_000, &[0x22, 4, 5, 6, 7, 0, 0, 0]),
            raw(ECU, t + 2_500, &[0x21, 4, 5, 6, 7, 0, 0, 0]),
        ]
    });
    assert_eq!(orient(&frames, &Timing::default()).conversations, []);
}
