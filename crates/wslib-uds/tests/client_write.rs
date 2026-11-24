use std::time::{Duration, Instant};

use wslib_uds::testing::{Did, Ecu};
use wslib_uds::{
    Client, DEFAULT_SESSION, EXTENDED_SESSION, Event, Request, Safety, SendError, SubFunction,
    Timing,
};

fn ms(n: u64) -> Duration {
    Duration::from_millis(n)
}

fn writer(timing: Timing) -> Client {
    Client::up_to(timing, Safety::Destructive)
}

fn session(value: u8) -> Request {
    Request::DiagnosticSessionControl {
        sub_function: SubFunction::new(value),
    }
}

fn exchange(client: &mut Client, ecu: &mut Ecu, request: Request, now: Instant) -> Event {
    let sent = client.send(request, now).unwrap();
    let answers = ecu.answer(&sent);
    let mut last = None;
    for answer in answers {
        last = Some(client.receive(&answer, now));
    }
    last.expect("an answer")
}

fn unlocking_ecu() -> Ecu {
    Ecu::new()
        .with_session(EXTENDED_SESSION)
        .with_security(0x01, [0x12, 0x34], |seed, key| {
            key.iter().zip(seed).all(|(k, s)| *k == !*s)
        })
        .with_did(0x0100, Did::writable([0x00, 0x00]).needs_security())
}

fn unlock(client: &mut Client, ecu: &mut Ecu, now: Instant) {
    exchange(client, ecu, session(EXTENDED_SESSION), now);
    let seed = Request::SecurityAccess {
        sub_function: SubFunction::new(0x01),
        data: vec![],
    };
    exchange(client, ecu, seed, now);
    let key = Request::SecurityAccess {
        sub_function: SubFunction::new(0x02),
        data: vec![!0x12, !0x34],
    };
    assert!(matches!(
        exchange(client, ecu, key, now),
        Event::Positive(_)
    ));
}

#[test]
fn a_positive_session_control_sets_the_session_and_takes_p2_and_p2_star() {
    let mut ecu = unlocking_ecu();
    let mut client = writer(Timing {
        p2: ms(10),
        p2_star: ms(100),
        ..Timing::default()
    });
    exchange(
        &mut client,
        &mut ecu,
        session(EXTENDED_SESSION),
        Instant::now(),
    );
    assert_eq!(client.session(), Some(EXTENDED_SESSION));
    assert_eq!(client.timing().p2, ms(50));
    assert_eq!(client.timing().p2_star, ms(5000));
}

#[test]
fn a_correct_key_unlocks_the_level_its_seed_was_requested_at() {
    let mut ecu = unlocking_ecu();
    let mut client = writer(Timing::default());
    unlock(&mut client, &mut ecu, Instant::now());
    assert_eq!(client.security_level(), Some(0x01));
    assert!(ecu.is_unlocked());
}

#[test]
fn a_session_change_resets_the_security_state() {
    let mut ecu = unlocking_ecu();
    let mut client = writer(Timing::default());
    let t0 = Instant::now();
    unlock(&mut client, &mut ecu, t0);
    exchange(&mut client, &mut ecu, session(EXTENDED_SESSION), t0);
    assert_eq!(client.security_level(), None);
    assert!(!ecu.is_unlocked());
}

#[test]
fn an_ecu_reset_returns_to_the_default_session() {
    let mut ecu = unlocking_ecu();
    let mut client = writer(Timing::default());
    let t0 = Instant::now();
    unlock(&mut client, &mut ecu, t0);
    let reset = Request::EcuReset {
        sub_function: SubFunction::new(0x01),
    };
    exchange(&mut client, &mut ecu, reset, t0);
    assert_eq!(client.session(), Some(DEFAULT_SESSION));
    assert_eq!(client.security_level(), None);
}

#[test]
fn a_write_reaches_the_ecu_once_unlocked() {
    let mut ecu = unlocking_ecu();
    let mut client = writer(Timing::default());
    let t0 = Instant::now();
    let write = Request::WriteDataByIdentifier {
        did: 0x0100,
        data: vec![0xAB, 0xCD],
    };
    exchange(&mut client, &mut ecu, session(EXTENDED_SESSION), t0);
    assert!(matches!(
        exchange(&mut client, &mut ecu, write.clone(), t0),
        Event::Negative { .. }
    ));
    unlock(&mut client, &mut ecu, t0);
    assert!(matches!(
        exchange(&mut client, &mut ecu, write, t0),
        Event::Positive(_)
    ));
    assert_eq!(ecu.did(0x0100), Some(&[0xAB, 0xCD][..]));
}

#[test]
fn a_quiet_non_default_session_is_kept_alive_with_a_suppressed_tester_present() {
    let mut ecu = unlocking_ecu();
    let timing = Timing::default();
    let mut client = writer(timing);
    let t0 = Instant::now();
    exchange(&mut client, &mut ecu, session(EXTENDED_SESSION), t0);
    let keep_alive = timing.keep_alive.unwrap();
    assert_eq!(client.next_deadline(), Some(t0 + keep_alive));
    assert_eq!(client.poll(t0 + keep_alive - ms(1)), None);
    let Some(Event::TesterPresent(bytes)) = client.poll(t0 + keep_alive) else {
        panic!("no tester present due");
    };
    assert_eq!(bytes, [0x3E, 0x80]);
    assert!(ecu.answer(&bytes).is_empty());
    assert_eq!(client.next_deadline(), Some(t0 + keep_alive * 2));
    assert_eq!(client.session(), Some(EXTENDED_SESSION));
}

#[test]
fn s3_expiry_returns_the_client_to_the_default_session() {
    let mut ecu = unlocking_ecu();
    let timing = Timing {
        keep_alive: None,
        ..Timing::default()
    };
    let mut client = writer(timing);
    let t0 = Instant::now();
    unlock(&mut client, &mut ecu, t0);
    assert_eq!(client.next_deadline(), Some(t0 + timing.s3));
    assert_eq!(client.poll(t0 + timing.s3), Some(Event::SessionExpired));
    assert_eq!(client.session(), Some(DEFAULT_SESSION));
    assert_eq!(client.security_level(), None);
    assert_eq!(client.next_deadline(), None);
}

#[test]
fn a_suppressed_session_change_takes_effect_when_no_refusal_comes_by_p2() {
    let mut ecu = unlocking_ecu();
    let timing = Timing::default();
    let mut client = writer(timing);
    let t0 = Instant::now();
    let request = Request::DiagnosticSessionControl {
        sub_function: SubFunction::suppressed(EXTENDED_SESSION),
    };
    let sent = client.send(request, t0).unwrap();
    assert!(ecu.answer(&sent).is_empty());
    assert_eq!(client.session(), Some(DEFAULT_SESSION));
    assert_eq!(
        client.poll(t0 + timing.p2 + timing.margin),
        Some(Event::Suppressed { service: 0x10 })
    );
    assert_eq!(client.session(), Some(EXTENDED_SESSION));
}

#[test]
fn a_session_answer_for_another_session_is_unexpected_and_changes_nothing() {
    let mut client = writer(Timing::default());
    let t0 = Instant::now();
    client.send(session(EXTENDED_SESSION), t0).unwrap();
    assert_eq!(
        client.receive(&[0x50, 0x02, 0x00, 0x32, 0x01, 0xF4], t0),
        Event::Unexpected(vec![0x50, 0x02, 0x00, 0x32, 0x01, 0xF4])
    );
    assert_eq!(client.session(), Some(DEFAULT_SESSION));
    assert!(client.is_busy());
}

#[test]
fn a_suppressed_session_change_that_drew_response_pending_and_then_silence_times_out_unknown() {
    let mut client = writer(Timing::default());
    let t0 = Instant::now();
    let request = Request::DiagnosticSessionControl {
        sub_function: SubFunction::suppressed(EXTENDED_SESSION),
    };
    client.send(request, t0).unwrap();
    let Event::Pending {
        deadline: Some(deadline),
    } = client.receive(&[0x7F, 0x10, 0x78], t0)
    else {
        panic!("no pending");
    };
    assert_eq!(
        client.poll(deadline),
        Some(Event::Timeout { service: 0x10 })
    );
    assert_eq!(client.session(), None);
}

#[test]
fn a_malformed_session_answer_still_changes_the_session_with_default_timing() {
    let defaults = Timing {
        p2: ms(10),
        p2_star: ms(100),
        ..Timing::default()
    };
    let mut ecu = unlocking_ecu();
    let mut client = writer(defaults);
    let t0 = Instant::now();
    unlock(&mut client, &mut ecu, t0);
    assert_eq!(client.timing().p2, ms(50));
    client.send(session(0x40), t0).unwrap();
    assert_eq!(
        client.receive(&[0x50, 0x40, 0x00], t0),
        Event::Malformed(vec![0x50, 0x40, 0x00])
    );
    assert_eq!(client.session(), Some(0x40));
    assert_eq!(client.security_level(), None);
    assert_eq!(
        (client.timing().p2, client.timing().p2_star),
        (ms(10), ms(100))
    );
}

fn custom_defaults() -> Timing {
    Timing {
        p2: ms(10),
        p2_star: ms(100),
        keep_alive: None,
        ..Timing::default()
    }
}

#[test]
fn p2_and_p2_star_return_to_the_defaults_on_s3_expiry() {
    let mut ecu = unlocking_ecu();
    let mut client = writer(custom_defaults());
    let t0 = Instant::now();
    exchange(&mut client, &mut ecu, session(EXTENDED_SESSION), t0);
    assert_eq!(client.timing().p2, ms(50));
    assert_eq!(
        client.poll(t0 + client.timing().s3),
        Some(Event::SessionExpired)
    );
    assert_eq!(
        (client.timing().p2, client.timing().p2_star),
        (ms(10), ms(100))
    );
}

#[test]
fn p2_and_p2_star_return_to_the_defaults_on_ecu_reset() {
    let mut ecu = unlocking_ecu();
    let mut client = writer(custom_defaults());
    let t0 = Instant::now();
    exchange(&mut client, &mut ecu, session(EXTENDED_SESSION), t0);
    let reset = Request::EcuReset {
        sub_function: SubFunction::new(0x01),
    };
    exchange(&mut client, &mut ecu, reset, t0);
    assert_eq!(
        (client.timing().p2, client.timing().p2_star),
        (ms(10), ms(100))
    );
}

#[test]
fn p2_and_p2_star_return_to_the_defaults_on_a_default_session_answer_with_no_timing() {
    let mut client = writer(custom_defaults());
    let t0 = Instant::now();
    client.send(session(EXTENDED_SESSION), t0).unwrap();
    client.receive(&[0x50, 0x03, 0x00, 0x32, 0x01, 0xF4], t0);
    assert_eq!(client.timing().p2, ms(50));
    client.send(session(DEFAULT_SESSION), t0).unwrap();
    client.receive(&[0x50, 0x01], t0);
    assert_eq!(
        (client.timing().p2, client.timing().p2_star),
        (ms(10), ms(100))
    );
}

#[test]
fn a_malformed_ecu_reset_answer_still_returns_session_security_and_timing_to_the_defaults() {
    let mut ecu = unlocking_ecu();
    let mut client = writer(custom_defaults());
    let t0 = Instant::now();
    unlock(&mut client, &mut ecu, t0);
    let reset = Request::EcuReset {
        sub_function: SubFunction::new(0x01),
    };
    client.send(reset, t0).unwrap();
    assert_eq!(
        client.receive(&[0x51, 0x01, 0x00, 0x00], t0),
        Event::Malformed(vec![0x51, 0x01, 0x00, 0x00])
    );
    assert_eq!(client.session(), Some(DEFAULT_SESSION));
    assert_eq!(client.security_level(), None);
    assert_eq!(
        (client.timing().p2, client.timing().p2_star),
        (ms(10), ms(100))
    );
}

#[test]
fn a_key_answer_that_does_not_echo_the_key_sub_function_does_not_unlock() {
    let mut client = writer(Timing::default());
    let t0 = Instant::now();
    client.send(session(EXTENDED_SESSION), t0).unwrap();
    client.receive(&[0x50, 0x03, 0x00, 0x32, 0x01, 0xF4], t0);
    let key = Request::SecurityAccess {
        sub_function: SubFunction::new(0x02),
        data: vec![0xAA],
    };
    client.send(key, t0).unwrap();
    assert_eq!(client.receive(&[0x67], t0), Event::Unexpected(vec![0x67]));
    assert!(matches!(
        client.receive(&[0x67, 0x04], t0),
        Event::Unexpected(_)
    ));
    assert_eq!(client.security_level(), None);
}

#[test]
fn abandoning_the_outstanding_request_frees_the_client_however_long_pending_runs() {
    let mut client = writer(Timing::default());
    let t0 = Instant::now();
    let start = Request::RoutineControl {
        sub_function: SubFunction::new(0x01),
        routine: 0x0203,
        data: vec![],
    };
    let sent = client.send(start, t0).unwrap();
    for i in 1..=100 {
        assert!(matches!(
            client.receive(&[0x7F, 0x31, 0x78], t0 + ms(i * 1000)),
            Event::Pending { .. }
        ));
    }
    assert_eq!(client.abandon(t0 + ms(100_500)), Some(sent));
    assert!(!client.is_busy());
    assert_eq!(client.abandon(t0 + ms(100_500)), None);
}

fn in_extended_session(t0: Instant) -> Client {
    let mut client = writer(Timing::default());
    client.send(session(EXTENDED_SESSION), t0).unwrap();
    client.receive(&[0x50, 0x03, 0x00, 0x32, 0x01, 0xF4], t0);
    client
}

#[test]
fn a_refusal_of_the_keep_alive_is_its_own_event_and_never_closes_the_callers_request() {
    let t0 = Instant::now();
    let mut client = in_extended_session(t0);
    let keep_alive_at = t0 + ms(2000);
    assert!(matches!(
        client.poll(keep_alive_at),
        Some(Event::TesterPresent(_))
    ));
    let tester_present = Request::TesterPresent {
        sub_function: SubFunction::new(0),
    };
    client.send(tester_present, keep_alive_at + ms(5)).unwrap();
    assert_eq!(
        client.receive(&[0x7F, 0x3E, 0x7F], keep_alive_at + ms(10)),
        Event::KeepAliveRefused {
            code: wslib_uds::Nrc::SERVICE_NOT_SUPPORTED_IN_ACTIVE_SESSION
        }
    );
    assert!(client.is_busy());
    assert_eq!(
        client.receive(&[0x7F, 0x3E, 0x12], keep_alive_at + ms(20)),
        Event::Negative {
            service: 0x3E,
            code: wslib_uds::Nrc::SUB_FUNCTION_NOT_SUPPORTED
        }
    );
}

#[test]
fn response_pending_to_the_keep_alive_is_no_refusal_and_holds_its_window_open_to_p2_star() {
    let t0 = Instant::now();
    let mut client = in_extended_session(t0);
    let keep_alive_at = t0 + ms(2000);
    client.poll(keep_alive_at);
    assert_eq!(
        client.receive(&[0x7F, 0x3E, 0x78], keep_alive_at + ms(10)),
        Event::KeepAlivePending
    );
    assert_eq!(
        client.receive(&[0x7F, 0x3E, 0x12], keep_alive_at + ms(1000)),
        Event::KeepAliveRefused {
            code: wslib_uds::Nrc::SUB_FUNCTION_NOT_SUPPORTED
        }
    );
}

#[test]
fn no_timing_however_long_panics_and_a_wait_too_long_to_represent_never_ends() {
    let forever = Timing {
        p2: Duration::MAX,
        p2_star: Duration::MAX,
        s3: Duration::MAX,
        keep_alive: Some(Duration::MAX),
        margin: Duration::MAX,
    };
    let t0 = Instant::now();
    let mut client = writer(forever);
    client.send(session(EXTENDED_SESSION), t0).unwrap();
    assert_eq!(client.next_deadline(), None);
    assert_eq!(client.poll(t0 + ms(60_000)), None);
    client.receive(&[0x50, 0x03], t0);
    assert_eq!(client.next_deadline(), None);
    assert_eq!(client.poll(t0 + ms(60_000)), None);
    assert_eq!(client.session(), Some(EXTENDED_SESSION));
    client.send(session(EXTENDED_SESSION), t0).unwrap();
    assert!(matches!(
        client.receive(&[0x7F, 0x10, 0x78], t0),
        Event::Pending { .. }
    ));
    assert_eq!(client.poll(t0 + ms(60_000)), None);
}

#[test]
fn a_tester_present_refusal_after_the_keep_alive_window_is_unexpected() {
    let t0 = Instant::now();
    let mut client = in_extended_session(t0);
    client.poll(t0 + ms(2000));
    assert!(matches!(
        client.receive(&[0x7F, 0x3E, 0x12], t0 + ms(2200)),
        Event::Unexpected(_)
    ));
}

#[test]
fn s3_counts_from_when_a_request_resolves_so_a_keep_alive_comes_before_expiry() {
    let t0 = Instant::now();
    let mut client = in_extended_session(t0);
    let start = Request::RoutineControl {
        sub_function: SubFunction::new(0x01),
        routine: 0x0203,
        data: vec![],
    };
    client.send(start, t0).unwrap();
    client.receive(&[0x7F, 0x31, 0x78], t0 + ms(10));
    assert_eq!(
        client.poll(t0 + ms(5060)),
        Some(Event::Timeout { service: 0x31 })
    );
    let next = client.next_deadline().unwrap();
    assert_eq!(next, t0 + ms(5060) + ms(2000));
    assert!(matches!(client.poll(next), Some(Event::TesterPresent(_))));
    assert_eq!(client.session(), Some(EXTENDED_SESSION));
}

#[test]
fn a_session_change_or_reset_that_goes_unanswered_locks_security_and_leaves_the_session_unknown() {
    let timing = Timing::default();
    let reset = Request::EcuReset {
        sub_function: SubFunction::new(0x01),
    };
    for (request, abandoned) in [
        (session(EXTENDED_SESSION), false),
        (reset.clone(), false),
        (session(EXTENDED_SESSION), true),
        (reset, true),
    ] {
        let mut ecu = unlocking_ecu();
        let mut client = writer(timing);
        let t0 = Instant::now();
        unlock(&mut client, &mut ecu, t0);
        client.send(request, t0).unwrap();
        let resolved = t0 + timing.p2 + timing.margin;
        if abandoned {
            client.abandon(resolved);
        } else {
            assert!(matches!(client.poll(resolved), Some(Event::Timeout { .. })));
        }
        assert_eq!(client.security_level(), None);
        assert_eq!(client.session(), None);
    }
}

#[test]
fn a_security_access_that_goes_unanswered_locks_security_and_keeps_the_session() {
    let timing = Timing::default();
    let mut ecu = unlocking_ecu();
    let mut client = writer(timing);
    let t0 = Instant::now();
    unlock(&mut client, &mut ecu, t0);
    let seed = Request::SecurityAccess {
        sub_function: SubFunction::new(0x01),
        data: vec![],
    };
    client.send(seed, t0).unwrap();
    client.poll(t0 + timing.p2 + timing.margin);
    assert_eq!(client.security_level(), None);
    assert_eq!(client.session(), Some(EXTENDED_SESSION));
}

#[test]
fn an_unknown_session_gets_no_keep_alive_and_becomes_the_default_at_s3() {
    let timing = Timing::default();
    let mut ecu = unlocking_ecu();
    let mut client = writer(timing);
    let t0 = Instant::now();
    exchange(&mut client, &mut ecu, session(EXTENDED_SESSION), t0);
    client.send(session(EXTENDED_SESSION), t0).unwrap();
    let resolved = t0 + timing.p2 + timing.margin;
    client.poll(resolved);
    assert_eq!(client.next_deadline(), Some(resolved + timing.s3));
    assert_eq!(client.poll(resolved + timing.keep_alive.unwrap()), None);
    assert_eq!(
        client.poll(resolved + timing.s3),
        Some(Event::SessionExpired)
    );
    assert_eq!(client.session(), Some(DEFAULT_SESSION));
    assert_eq!(client.next_deadline(), None);
}

#[test]
fn by_default_a_client_refuses_a_state_changing_request_and_sends_nothing() {
    let mut client = Client::new(Timing::default());
    assert_eq!(
        client.send(session(EXTENDED_SESSION), Instant::now()),
        Err(SendError::AboveCeiling {
            request: session(EXTENDED_SESSION),
            safety: Safety::StateChanging,
            ceiling: Safety::ReadOnly,
        })
    );
    assert!(!client.is_busy());
}

#[test]
fn a_state_changing_ceiling_refuses_destructive_and_vendor_requests_and_keeps_the_session_alive() {
    let mut ecu = unlocking_ecu();
    let timing = Timing::default();
    let mut client = Client::up_to(timing, Safety::StateChanging);
    let t0 = Instant::now();
    exchange(&mut client, &mut ecu, session(EXTENDED_SESSION), t0);
    let write = Request::WriteDataByIdentifier {
        did: 0x0100,
        data: vec![0xAB],
    };
    let vendor = Request::Other {
        service: 0xBA,
        data: vec![0x01],
    };
    for request in [write, vendor] {
        assert!(matches!(
            client.send(request, t0),
            Err(SendError::AboveCeiling {
                safety: Safety::Destructive,
                ..
            })
        ));
        assert!(!client.is_busy());
    }
    let keep_alive = timing.keep_alive.unwrap();
    assert_eq!(
        client.poll(t0 + keep_alive),
        Some(Event::TesterPresent(vec![0x3E, 0x80]))
    );
}
