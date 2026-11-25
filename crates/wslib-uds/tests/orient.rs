use std::time::Duration;

use wslib_isotp::testing::{Conversation as Script, Responder};
use wslib_isotp::{
    Addressing, DEFAULT_FLOW_CONTROL_WINDOW, FdLength, FrameFormat, Framing, TimedFrame, detect,
};
use wslib_uds::testing::{Did, Ecu};
use wslib_uds::{
    Conversation, Endpoint, MAX_MESSAGE_BYTES, MAX_PARTNERS, Orientation, Request, Sender, Timing,
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

#[test]
fn a_periodic_id_whose_frames_are_no_typed_request_or_answer_leaves_a_conversation_found() {
    let real = real_reads();
    let end = real.last().unwrap().at_us;
    let found = orient(&merged(real, counter(end)), &Timing::default());
    assert_eq!(
        found.conversations,
        [Conversation {
            exchanges: 20,
            ..conversation(TESTER, ECU)
        }]
    );
}

#[test]
fn a_periodic_look_alike_answering_or_asking_every_request_unsettles_the_real_pair() {
    let real = real_reads();
    let end = real.last().unwrap().at_us;
    let request_look_alike = every_10_ms(end, 0x101, |_| [&[0x03][..], &SHORT_READ].concat());
    for (look_alike, side) in [
        (reply_look_alike(end), Sender::Tester),
        (request_look_alike, Sender::Ecu),
    ] {
        let found = orient(&merged(real.clone(), look_alike), &Timing::default());
        assert_eq!(found.conversations, [], "{side:?}");
        let rivalled = found
            .unsettled
            .iter()
            .find(|u| u.side == side && [at(TESTER), at(ECU)].contains(&u.endpoint))
            .unwrap();
        assert_eq!(rivalled.candidates.len(), 2, "{found:#?}");
    }
}

#[test]
fn a_periodic_reply_look_alike_is_never_paired_with_a_tester_nothing_else_answers() {
    let requests: Vec<TimedFrame> = (0..20_u64)
        .map(|round| single(TESTER, round * 100_000 + 5_000, &SHORT_READ))
        .collect();
    let until = requests.last().unwrap().at_us;
    assert_eq!(
        orient(
            &merged(requests, reply_look_alike(until)),
            &Timing::default()
        ),
        Orientation {
            conversations: vec![],
            unsettled: vec![
                unsettled(0x100, Sender::Ecu, &[TESTER]),
                unsettled(TESTER, Sender::Tester, &[0x100]),
            ],
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
    let mut expected: Vec<Unsettled> = (0x700..0x700 + MAX_PARTNERS as u32 + 1)
        .map(|tester| unsettled(tester, Sender::Tester, &[ECU]))
        .collect();
    expected.push(unsettled(ECU, Sender::Ecu, &[0x700, 0x701, 0x702, 0x703]));
    assert_eq!(
        orient(&frames, &Timing::default()),
        Orientation {
            conversations: vec![],
            unsettled: expected,
        }
    );
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
                id: 0x700 + (r >> 52) as u32 % 16,
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
    assert!(paired >= 20, "{paired}");
}

#[test]
fn a_message_whose_first_byte_is_no_iso_request_service_counts_for_nothing() {
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
fn a_message_that_does_not_decode_as_its_service_counts_for_nothing() {
    let frames = rounds(20, |t| {
        vec![
            single(TESTER, t, &[0x22, 0x01]),
            single(ECU, t + 1_000, &[0x62, 0x01, 0x00, 0x01]),
        ]
    });
    assert_eq!(orient(&frames, &Timing::default()), Orientation::default());
}

#[test]
fn a_periodic_pair_out_of_step_is_never_a_conversation() {
    for (request_every, reply_every) in [
        (10_000, 20_000),
        (20_000, 10_000),
        (10_000, 17_000),
        (17_000, 10_000),
        (10_000, 19_000),
        (20_000, 12_501),
        (100_000, 60_000),
    ] {
        let mut frames = Vec::new();
        for t in (0..4_000_000).step_by(request_every) {
            frames.push(single(0x1A0, t, &TESTER_PRESENT));
        }
        for t in (0..4_000_000).step_by(reply_every) {
            frames.push(single(0x2B0, t + 3_000, &[0x7E, 0x00]));
        }
        frames.sort_by_key(|frame| frame.at_us);
        let found = orient(&frames, &Timing::default());
        assert_eq!(found.conversations, [], "{request_every} {reply_every}");
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
    assert_eq!(
        orient(&frames, &timing),
        Orientation {
            conversations: vec![],
            unsettled: vec![
                unsettled(TESTER, Sender::Tester, &[ECU]),
                unsettled(ECU, Sender::Ecu, &[TESTER]),
            ],
        }
    );
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

/// `count` reads of DID 0x0100, each answered, from `start_us` 100 ms apart.
fn reads(count: u64, start_us: u64) -> Vec<TimedFrame> {
    (0..count)
        .flat_map(|i| {
            let t = start_us + i * 100_000;
            [
                single(TESTER, t, &SHORT_READ),
                single(ECU, t + 1_000, &[0x62, 0x01, 0x00, 0x01, 0x02]),
            ]
        })
        .collect()
}

fn only_conversation(frames: &[TimedFrame]) -> Conversation {
    let found = orient(frames, &Timing::default());
    assert_eq!(found.conversations.len(), 1, "{found:#?}");
    found.conversations[0].clone()
}

#[test]
fn a_request_of_a_service_the_crate_does_not_model_counts_for_nothing() {
    for service in [
        0x24_u8, 0x29, 0x2A, 0x2C, 0x38, 0x3D, 0x83, 0x84, 0x86, 0x87, 0x01,
    ] {
        let frames = rounds(50, |t| {
            vec![
                single(0x1A0, t, &[service]),
                single(0x2B0, t + 3_000, &[service + 0x40, 0x12]),
            ]
        });
        assert_eq!(
            orient(&frames, &Timing::default()),
            Orientation::default(),
            "{service:#04x}"
        );
    }
}

#[test]
fn answers_to_requests_the_crate_does_not_type_leave_an_ecu_unpenalised() {
    let frames = rounds(10, |t| {
        vec![
            single(TESTER, t, &SHORT_READ),
            single(ECU, t + 1_000, &[0x62, 0x01, 0x00, 0x01, 0x02]),
            single(TESTER, t + 30_000, &[0x21, 0x01]),
            single(ECU, t + 31_000, &[0x61, 0x01, 0xAA, 0xBB]),
            single(TESTER, t + 60_000, &[0xA5, 0x01]),
            single(ECU, t + 61_000, &[0x7F, 0xA5, 0x11]),
        ]
    });
    assert_eq!(
        orient(&frames, &Timing::default()),
        Orientation {
            conversations: vec![Conversation {
                exchanges: 10,
                ..conversation(TESTER, ECU)
            }],
            unsettled: vec![],
        }
    );
}

#[test]
fn a_single_frame_padded_with_varying_bytes_is_no_message() {
    let frames = rounds(20, |t| {
        vec![
            raw(0x1A0, t, &[0x02, 0x3E, 0x00, t as u8, 0x55, 0, 0, 0]),
            raw(0x2B0, t + 3_000, &[0x02, 0x7E, 0x00, 0, 0, 0, 0, 0]),
        ]
    });
    assert_eq!(orient(&frames, &Timing::default()), Orientation::default());
    let padded = rounds(20, |t| {
        vec![
            raw(0x1A0, t, &[0x02, 0x3E, 0x00, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA]),
            raw(0x2B0, t + 3_000, &[0x02, 0x7E, 0x00, 0, 0, 0, 0, 0]),
        ]
    });
    assert_eq!(only_conversation(&padded).exchanges, 20);
}

#[test]
fn two_periodic_ids_pair_only_when_one_sends_a_typed_request() {
    let mut hits = Vec::new();
    for len in 1..=3_u8 {
        for a in 0..=255_u8 {
            for b in [a.wrapping_add(0x40), 0x7F] {
                let echo = if b == 0x7F { a } else { 0 };
                let frames = rounds(6, |t| {
                    vec![
                        raw(0x1A0, t, &[len, a, 0, 0, 0, 0, 0, 0]),
                        raw(0x2B0, t + 3_000, &[len.max(3), b, echo, 0, 0, 0, 0, 0]),
                    ]
                });
                if !orient(&frames, &Timing::default()).conversations.is_empty() {
                    hits.push([a, 0, 0][..usize::from(len)].to_vec());
                }
            }
        }
    }
    assert!(!hits.is_empty());
    for request in hits {
        let typed = Request::decode(&request);
        assert!(
            matches!(typed, Ok(ref r) if !matches!(r, Request::Other { .. })),
            "{request:02X?}"
        );
    }
}

#[test]
fn a_positive_response_to_a_suppressed_request_with_no_pending_is_unsolicited() {
    let frames = rounds(20, |t| {
        vec![
            single(0x7DF, t, &[0x3E, 0x80]),
            single(0x2B0, t + 40_000, &[0x7E, 0x00]),
        ]
    });
    assert_eq!(orient(&frames, &Timing::default()), Orientation::default());
}

#[test]
fn a_tester_with_many_unanswered_requests_is_unsettled_not_dropped() {
    let mut frames = rounds(10, |t| vec![single(TESTER, t, &SHORT_READ)]);
    frames.extend(reads(10, 1_000_000));
    assert_eq!(
        orient(&frames, &Timing::default()),
        Orientation {
            conversations: vec![],
            unsettled: vec![
                unsettled(TESTER, Sender::Tester, &[ECU]),
                unsettled(ECU, Sender::Ecu, &[TESTER]),
            ],
        }
    );
    let mut tester_presents = reads(5, 0);
    tester_presents.extend((0..5).map(|i| single(TESTER, 50_000 + i * 100_000, &TESTER_PRESENT)));
    let found = orient(&merged(tester_presents, vec![]), &Timing::default());
    assert_eq!(found.conversations, []);
    assert!(
        found
            .unsettled
            .contains(&unsettled(TESTER, Sender::Tester, &[ECU]))
    );
}

#[test]
fn a_rival_unsettles_however_poor_its_own_record() {
    let frames = rounds(20, |t| {
        vec![
            single(0x7DF, t, &TESTER_PRESENT),
            single(0x7E8, t + 1_000, &[0x7E, 0x00]),
            single(0x7E9, t + 2_000, &[0x7E, 0x00]),
            single(0x7E9, t + 50_000, &[0x7E, 0x00]),
            single(0x7E9, t + 60_000, &[0x7E, 0x00]),
        ]
    });
    let found = orient(&frames, &Timing::default());
    assert_eq!(found.conversations, []);
    assert_eq!(
        found.unsettled[0],
        unsettled(0x7DF, Sender::Tester, &[0x7E8, 0x7E9])
    );
}

#[test]
fn a_rival_settles_with_an_eighth_of_the_leaders_exchanges_and_not_with_more() {
    for (rival, settled) in [(2, true), (3, false)] {
        let frames = rounds(16, |t| {
            let mut frames = vec![
                single(0x7DF, t, &TESTER_PRESENT),
                single(0x7E8, t + 1_000, &[0x7E, 0x00]),
            ];
            if t < rival * 100_000 {
                frames.push(single(0x7E9, t + 2_000, &[0x7E, 0x00]));
            }
            frames
        });
        let found = orient(&frames, &Timing::default());
        assert_eq!(found.conversations.len(), usize::from(settled), "{rival}");
    }
    let frames = vec![
        single(TESTER, 0, &TESTER_PRESENT),
        single(0x7E8, 1_000, &[0x7E, 0x00]),
        single(0x7E9, 2_000, &[0x7E, 0x00]),
        single(TESTER, 500_000, &TESTER_PRESENT),
        single(0x7E8, 501_000, &[0x7E, 0x00]),
    ];
    assert_eq!(orient(&frames, &Timing::default()).conversations, []);
}

#[test]
fn junk_filling_an_ecus_partner_slots_leaves_every_id_reported() {
    for tester_first in [false, true] {
        let offset = if tester_first { 0 } else { 50_000 };
        let mut frames = reads(20, offset);
        for junk in 0x101..=0x104_u32 {
            for t in (0..2_100_000).step_by(10_000) {
                frames.push(raw(junk, t + u64::from(junk), &[0x03, 0x22, 0x01, 0x00]));
            }
        }
        let found = orient(&merged(frames, vec![]), &Timing::default());
        assert_eq!(found.conversations, [], "{tester_first}");
        let ecu = found
            .unsettled
            .iter()
            .find(|u| u.endpoint == at(ECU))
            .unwrap();
        assert_eq!(ecu.candidates.len(), MAX_PARTNERS, "{found:#?}");
        assert!(
            found
                .unsettled
                .iter()
                .any(|u| u.endpoint == at(TESTER) && u.candidates == [at(ECU)]),
            "{found:#?}"
        );
    }
}

fn exchange(tester: u32, ecu: u32, t: u64, did: u8) -> [TimedFrame; 2] {
    [
        single(tester, t, &[0x22, did, 0x00]),
        single(ecu, t + 1_000, &[0x62, did, 0x00, 0x01]),
    ]
}

#[test]
fn an_id_settled_as_both_a_tester_and_an_ecu_is_in_no_conversation() {
    let (a, b, c) = (0x700, 0x701, 0x702);
    let mut frames = rounds(16, |t| exchange(a, b, t, 1).to_vec());
    frames.extend(rounds(2, |t| exchange(b, c, 2_000_000 + t, 2).to_vec()));
    assert_eq!(
        orient(&frames, &Timing::default()),
        Orientation {
            conversations: vec![],
            unsettled: vec![
                unsettled(a, Sender::Tester, &[b]),
                unsettled(b, Sender::Tester, &[c]),
                unsettled(b, Sender::Ecu, &[a]),
                unsettled(c, Sender::Ecu, &[b]),
            ],
        }
    );
}

#[test]
fn a_ring_of_ids_diagnosing_the_next_puts_no_id_in_both_roles_and_drops_none() {
    let (a, b, c) = (0x700, 0x701, 0x702);
    for bystanders in [false, true] {
        let mut frames = rounds(5, |t| {
            [
                exchange(a, b, t, 1),
                exchange(b, c, t + 10_000, 2),
                exchange(c, a, t + 20_000, 3),
            ]
            .concat()
        });
        if bystanders {
            for (i, ecu) in [a, b, c].into_iter().enumerate() {
                frames.extend(exchange(
                    0x710 + i as u32,
                    ecu,
                    900_000 + i as u64 * 10_000,
                    9,
                ));
            }
        }
        let found = orient(&frames, &Timing::default());
        assert!(
            !found.conversations.iter().any(|c| found
                .conversations
                .iter()
                .any(|other| other.ecu == c.tester)),
            "{found:#?}"
        );
        for id in [a, b, c] {
            for side in [Sender::Tester, Sender::Ecu] {
                let reported = found.conversations.iter().any(|c| match side {
                    Sender::Tester => c.tester == at(id),
                    Sender::Ecu => c.ecu == at(id),
                }) || found
                    .unsettled
                    .iter()
                    .any(|u| u.endpoint == at(id) && u.side == side);
                assert!(reported, "{id:#x} {side:?} {bystanders}: {found:#?}");
            }
        }
    }
}

#[test]
fn a_normal_request_closes_the_tester_present_held_beside_the_last() {
    let mut frames = reads(7, 0);
    frames.extend([
        single(TESTER, 1_000_000, &TESTER_PRESENT),
        single(TESTER, 1_010_000, &[0x22, 0x02, 0x00]),
        single(ECU, 1_011_000, &[0x7E, 0x00]),
        single(ECU, 1_012_000, &[0x62, 0x02, 0x00, 0x01]),
    ]);
    assert_eq!(only_conversation(&frames).exchanges, 8);
}

#[test]
fn a_second_copy_of_a_response_is_no_second_exchange() {
    let mut frames = reads(10, 0);
    frames.push(single(ECU, 902_000, &[0x62, 0x01, 0x00, 0x01, 0x02]));
    assert_eq!(only_conversation(&frames).exchanges, 10);
}

#[test]
fn a_held_tester_present_answered_after_p2_is_unanswered_and_its_answer_unsolicited() {
    let mut frames = reads(8, 0);
    frames.extend([
        single(TESTER, 900_000, &TESTER_PRESENT),
        single(ECU, 1_000_001, &[0x7E, 0x00]),
    ]);
    let c = only_conversation(&frames);
    assert_eq!((c.exchanges, c.negative, c.pending), (8, 0, 0));
    frames.push(single(ECU, 1_100_000, &[0x7E, 0x00]));
    assert_eq!(orient(&frames, &Timing::default()).conversations, []);
}

#[test]
fn pendings_and_negatives_are_counted_once_each() {
    let mut frames = vec![
        single(TESTER, 0, &ROUTINE_START),
        single(ECU, 1_000, &[0x7F, 0x31, 0x78]),
        single(TESTER, 1_000_000, &[0x3E, 0x80]),
        single(ECU, 2_000_000, &[0x7F, 0x31, 0x78]),
        single(TESTER, 2_500_000, &TESTER_PRESENT),
        single(ECU, 2_501_000, &[0x7E, 0x00]),
        single(ECU, 6_000_000, &[0x7F, 0x31, 0x22]),
        single(ECU, 6_001_000, &[0x7F, 0x31, 0x22]),
        single(TESTER, 7_000_000, &[0x10, 0x83]),
        single(ECU, 7_001_000, &[0x7F, 0x10, 0x12]),
        single(TESTER, 8_000_000, &[0x10, 0x83]),
        single(ECU, 8_001_000, &[0x50, 0x03, 0, 0x32, 0x01, 0xF4]),
    ];
    frames.extend(reads(16, 10_000_000));
    let c = only_conversation(&frames);
    assert_eq!((c.exchanges, c.negative, c.pending), (19, 2, 2), "{c:#?}");
}

#[test]
fn a_refusal_goes_to_the_later_suppressed_request_not_an_expired_earlier_one() {
    let mut frames = vec![
        single(TESTER, 0, &[0x10, 0x03]),
        single(TESTER, 200_000, &[0x10, 0x83]),
        single(ECU, 201_000, &[0x7F, 0x10, 0x12]),
        single(TESTER, 400_000, &[0x10, 0x83]),
        single(ECU, 401_000, &[0x7F, 0x10, 0x12]),
        single(TESTER, 600_000, &[0x10, 0x83]),
        single(ECU, 601_000, &[0x7F, 0x10, 0x12]),
    ];
    frames.extend(reads(8, 1_000_000));
    let c = only_conversation(&frames);
    assert_eq!((c.exchanges, c.negative), (11, 3));
}

#[test]
fn a_pending_chain_at_the_end_of_time_neither_panics_nor_miscounts() {
    let end = u64::MAX;
    let frames = [
        single(TESTER, end - 10_000_000, &ROUTINE_START),
        single(ECU, end - 9_999_000, &[0x7F, 0x31, 0x78]),
        single(ECU, end - 5_000_000, &[0x7F, 0x31, 0x78]),
        single(ECU, end, &[0x71, 0x01, 0x02, 0x03]),
    ];
    let c = only_conversation(&frames);
    assert_eq!((c.exchanges, c.pending), (1, 2));
}

#[test]
fn random_windows_orient_the_same_twice_with_distinct_candidates_and_roles() {
    let mut state = 0x1234_5678_9ABC_DEF1_u64;
    let mut next = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    let messages: [&[u8]; 14] = [
        &[0x3E, 0x00],
        &[0x7E, 0x00],
        &[0x3E, 0x80],
        &[0x22, 0x01, 0x00],
        &[0x62, 0x01, 0x00, 0x01],
        &[0x7F, 0x22, 0x31],
        &[0x7F, 0x22, 0x78],
        &[0x10, 0x03],
        &[0x10, 0x83],
        &[0x50, 0x03],
        &[0x7F, 0x10, 0x12],
        &[0x7F, 0x3E, 0x78],
        &[0x37],
        &[0x77],
    ];
    for case in 0..400 {
        let ids = 2 + next() % 7;
        let mut t = 0;
        let frames: Vec<TimedFrame> = (0..(20 + next() % 300))
            .map(|_| {
                t += next() % 60_000;
                let message = messages[next() as usize % messages.len()];
                single(0x700 + (next() % ids) as u32, t, message)
            })
            .collect();
        let found = orient(&frames, &Timing::default());
        assert_eq!(found, orient(&frames, &Timing::default()), "{case}");
        for u in &found.unsettled {
            let mut seen = u.candidates.clone();
            seen.sort_by_key(|e| e.id);
            seen.dedup();
            assert_eq!(seen.len(), u.candidates.len(), "{found:#?}");
            assert!(!u.candidates.is_empty() && !u.candidates.contains(&u.endpoint));
        }
        let mut roles: Vec<(u32, bool)> = found
            .unsettled
            .iter()
            .map(|u| (u.endpoint.id, u.side == Sender::Ecu))
            .collect();
        let len = roles.len();
        roles.sort();
        roles.dedup();
        assert_eq!(roles.len(), len, "{found:#?}");
    }
}

#[test]
fn time_grows_with_the_frames_not_the_ids_times_the_frames() {
    let time = |count: u32| {
        let frames: Vec<TimedFrame> = (0..count)
            .map(|id| TimedFrame {
                id,
                extended: true,
                data: vec![0x02, 0x3E, 0x00],
                at_us: u64::from(id),
            })
            .collect();
        let started = std::time::Instant::now();
        let _ = orient(&frames, &Timing::default());
        started.elapsed()
    };
    let (small, large) = (time(5_000), time(20_000));
    assert!(
        large < small * 8 + Duration::from_millis(50),
        "{small:?} {large:?}"
    );
}
