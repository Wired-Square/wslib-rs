use std::time::{Duration, Instant};

use wslib_uds::testing::{Did, Ecu};
use wslib_uds::{
    Busy, Client, DEFAULT_SESSION, Event, Nrc, ReadOnly, Request, Response, SubFunction, Timing,
};

fn read(did: u16) -> ReadOnly {
    ReadOnly::new(Request::ReadDataByIdentifier { dids: vec![did] }).unwrap()
}

fn ms(n: u64) -> Duration {
    Duration::from_millis(n)
}

#[test]
fn a_read_only_request_gets_its_positive_response() {
    let mut ecu = Ecu::new().with_did(0xF190, Did::readable(*b"VIN"));
    let mut client = Client::new(Timing::default());
    let t0 = Instant::now();
    let sent = client.send_read_only(read(0xF190), t0).unwrap();
    assert_eq!(sent, [0x22, 0xF1, 0x90]);
    let answers = ecu.answer(&sent);
    assert_eq!(
        client.receive(&answers[0], t0 + ms(5)),
        Event::Positive(Response::ReadDataByIdentifier {
            did: 0xF190,
            data: b"VIN".to_vec()
        })
    );
    assert!(!client.is_busy());
}

#[test]
fn a_negative_response_is_reported_with_its_code() {
    let mut ecu = Ecu::new();
    let mut client = Client::new(Timing::default());
    let t0 = Instant::now();
    let sent = client.send_read_only(read(0x1234), t0).unwrap();
    assert_eq!(
        client.receive(&ecu.answer(&sent)[0], t0),
        Event::Negative {
            service: 0x22,
            code: Nrc::REQUEST_OUT_OF_RANGE
        }
    );
}

#[test]
fn one_request_is_outstanding_at_a_time() {
    let mut client = Client::new(Timing::default());
    let t0 = Instant::now();
    client.send_read_only(read(0xF190), t0).unwrap();
    assert_eq!(client.send_read_only(read(0xF18C), t0), Err(Busy));
}

#[test]
fn no_answer_by_p2_plus_margin_is_a_timeout() {
    let timing = Timing::default();
    let mut client = Client::new(timing);
    let t0 = Instant::now();
    client.send_read_only(read(0xF190), t0).unwrap();
    let deadline = t0 + timing.p2 + timing.margin;
    assert_eq!(client.next_deadline(), Some(deadline));
    assert_eq!(client.poll(deadline - ms(1)), None);
    assert_eq!(
        client.poll(deadline),
        Some(Event::Timeout { service: 0x22 })
    );
    assert!(!client.is_busy());
}

#[test]
fn response_pending_moves_the_deadline_to_p2_star() {
    let mut ecu = Ecu::new()
        .with_did(0xF190, Did::readable(*b"VIN"))
        .with_pending(0x22, 1);
    let timing = Timing::default();
    let mut client = Client::new(timing);
    let t0 = Instant::now();
    let sent = client.send_read_only(read(0xF190), t0).unwrap();
    let answers = ecu.answer(&sent);
    assert_eq!(answers.len(), 2);
    let deadline = t0 + ms(10) + timing.p2_star + timing.margin;
    assert_eq!(
        client.receive(&answers[0], t0 + ms(10)),
        Event::Pending { deadline }
    );
    assert_eq!(client.next_deadline(), Some(deadline));
    assert_eq!(client.poll(t0 + ms(1000)), None);
    assert!(matches!(
        client.receive(&answers[1], t0 + ms(1200)),
        Event::Positive(_)
    ));
}

#[test]
fn a_response_to_another_service_or_with_nothing_outstanding_is_unexpected() {
    let mut client = Client::new(Timing::default());
    let t0 = Instant::now();
    assert_eq!(
        client.receive(&[0x7E, 0x00], t0),
        Event::Unexpected(vec![0x7E, 0x00])
    );
    client.send_read_only(read(0xF190), t0).unwrap();
    assert_eq!(
        client.receive(&[0x50, 0x03], t0),
        Event::Unexpected(vec![0x50, 0x03])
    );
    assert_eq!(client.receive(&[], t0), Event::Unexpected(vec![]));
    assert!(client.is_busy());
}

#[test]
fn a_suppressed_tester_present_ends_suppressed_at_p2() {
    let mut ecu = Ecu::new();
    let timing = Timing::default();
    let mut client = Client::new(timing);
    let t0 = Instant::now();
    let request = ReadOnly::new(Request::TesterPresent {
        sub_function: SubFunction::suppressed(0),
    })
    .unwrap();
    let sent = client.send_read_only(request, t0).unwrap();
    assert!(ecu.answer(&sent).is_empty());
    assert_eq!(
        client.poll(t0 + timing.p2 + timing.margin),
        Some(Event::Suppressed { service: 0x3E })
    );
}

#[test]
fn a_reply_that_does_not_echo_the_requested_did_or_routine_is_unexpected_and_changes_nothing() {
    let mut client = Client::new(Timing::default());
    let t0 = Instant::now();
    client.send_read_only(read(0xF190), t0).unwrap();
    assert_eq!(
        client.receive(&[0x62, 0xF1, 0x8C, 0x01], t0),
        Event::Unexpected(vec![0x62, 0xF1, 0x8C, 0x01])
    );
    assert!(client.is_busy());
    assert!(matches!(
        client.receive(&[0x62, 0xF1, 0x90, 0x01], t0),
        Event::Positive(_)
    ));
    let results = ReadOnly::new(Request::RoutineControl {
        sub_function: SubFunction::new(0x03),
        routine: 0x0203,
        data: vec![],
    })
    .unwrap();
    client.send_read_only(results, t0).unwrap();
    assert!(matches!(
        client.receive(&[0x71, 0x03, 0x02, 0x04], t0),
        Event::Unexpected(_)
    ));
    assert!(matches!(
        client.receive(&[0x71, 0x01, 0x02, 0x03], t0),
        Event::Unexpected(_)
    ));
    assert!(matches!(
        client.receive(&[0x71, 0x03, 0x02, 0x03, 0x00], t0),
        Event::Positive(_)
    ));
}

#[test]
fn a_positive_answer_that_fails_strict_decoding_still_resolves_the_request_as_malformed() {
    let mut client = Client::new(Timing::default());
    let t0 = Instant::now();
    let tester_present = ReadOnly::new(Request::TesterPresent {
        sub_function: SubFunction::new(0),
    })
    .unwrap();
    client.send_read_only(tester_present, t0).unwrap();
    assert_eq!(
        client.receive(&[0x7E, 0x00, 0x00], t0),
        Event::Malformed(vec![0x7E, 0x00, 0x00])
    );
    assert!(!client.is_busy());
}

#[test]
fn silence_after_response_pending_is_a_timeout_even_when_the_positive_response_was_suppressed() {
    let timing = Timing::default();
    let mut client = Client::new(timing);
    let t0 = Instant::now();
    let request = ReadOnly::new(Request::TesterPresent {
        sub_function: SubFunction::suppressed(0),
    })
    .unwrap();
    client.send_read_only(request, t0).unwrap();
    let Event::Pending { deadline } = client.receive(&[0x7F, 0x3E, 0x78], t0) else {
        panic!("no pending");
    };
    assert_eq!(
        client.poll(deadline),
        Some(Event::Timeout { service: 0x3E })
    );
}

#[test]
fn in_the_default_session_nothing_is_due_with_nothing_outstanding() {
    let mut client = Client::new(Timing::default());
    let t0 = Instant::now();
    assert_eq!(client.session(), DEFAULT_SESSION);
    assert_eq!(client.next_deadline(), None);
    assert_eq!(client.poll(t0 + ms(60_000)), None);
}
