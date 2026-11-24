use wslib_uds::testing::{Did, Ecu};
use wslib_uds::{Observed, Outcome, Sender, Tracker, Transaction};

fn transaction(observed: impl IntoIterator<Item = Observed>) -> Transaction {
    let observed: Vec<Observed> = observed.into_iter().collect();
    match <[Observed; 1]>::try_from(observed) {
        Ok([Observed::Transaction(t)]) => t,
        other => panic!("expected one transaction, got {other:?}"),
    }
}

fn replay(ecu: &mut Ecu, tracker: &mut Tracker, request: &[u8], at_us: u64) -> Vec<Observed> {
    let mut seen = tracker.observe(Sender::Tester, request, at_us);
    for (i, response) in ecu.answer(request).iter().enumerate() {
        let at = at_us + 1_000 * (i as u64 + 1);
        seen.extend(tracker.observe(Sender::Ecu, response, at));
    }
    seen
}

#[test]
fn a_request_and_its_response_pair_with_latency() {
    let mut ecu = Ecu::new().with_did(0xF190, Did::readable(*b"VIN"));
    let mut tracker = Tracker::new();
    let seen = replay(&mut ecu, &mut tracker, &[0x22, 0xF1, 0x90], 10_000);
    let [Observed::Transaction(t)] = seen.as_slice() else {
        panic!("{seen:?}")
    };
    assert_eq!(t.request, [0x22, 0xF1, 0x90]);
    assert_eq!(t.requested_at_us, 10_000);
    assert_eq!(t.pending_responses, 0);
    assert_eq!(
        t.outcome,
        Outcome::Answered {
            response: vec![0x62, 0xF1, 0x90, b'V', b'I', b'N'],
            latency_us: 1_000
        }
    );
}

#[test]
fn response_pending_answers_are_counted_and_the_final_response_ends_the_transaction() {
    let mut ecu = Ecu::new()
        .with_routine(0x0203, [0x00])
        .with_pending(0x31, 2);
    let mut tracker = Tracker::new();
    let seen = replay(&mut ecu, &mut tracker, &[0x31, 0x01, 0x02, 0x03], 0);
    let [Observed::Transaction(t)] = seen.as_slice() else {
        panic!("{seen:?}")
    };
    assert_eq!(t.pending_responses, 2);
    assert_eq!(
        t.outcome,
        Outcome::Answered {
            response: vec![0x71, 0x01, 0x02, 0x03],
            latency_us: 3_000
        }
    );
}

#[test]
fn a_negative_response_ends_the_transaction() {
    let mut ecu = Ecu::new();
    let mut tracker = Tracker::new();
    let seen = replay(&mut ecu, &mut tracker, &[0x22, 0x12, 0x34], 0);
    let [Observed::Transaction(t)] = seen.as_slice() else {
        panic!("{seen:?}")
    };
    assert!(
        matches!(&t.outcome, Outcome::Answered { response, .. } if response == &[0x7F, 0x22, 0x31])
    );
}

#[test]
fn a_suppressed_request_ends_suppressed_when_the_next_request_comes() {
    let mut ecu = Ecu::new();
    let mut tracker = Tracker::new();
    assert!(replay(&mut ecu, &mut tracker, &[0x3E, 0x80], 0).is_empty());
    let seen = tracker.observe(Sender::Tester, &[0x3E, 0x80], 2_000_000);
    let t = transaction(seen);
    assert_eq!(t.request, [0x3E, 0x80]);
    assert_eq!(t.outcome, Outcome::Suppressed);
}

#[test]
fn a_suppressed_request_still_pairs_with_a_negative_response() {
    let mut tracker = Tracker::new();
    assert!(tracker.observe(Sender::Tester, &[0x10, 0x85], 0).is_empty());
    let t = transaction(tracker.observe(Sender::Ecu, &[0x7F, 0x10, 0x12], 500));
    assert!(matches!(
        t.outcome,
        Outcome::Answered {
            latency_us: 500,
            ..
        }
    ));
}

#[test]
fn a_new_request_before_the_old_one_resolved_supersedes_it() {
    let mut tracker = Tracker::new();
    assert!(
        tracker
            .observe(Sender::Tester, &[0x22, 0xF1, 0x90], 0)
            .is_empty()
    );
    let t = transaction(tracker.observe(Sender::Tester, &[0x22, 0xF1, 0x8C], 100));
    assert_eq!(t.request, [0x22, 0xF1, 0x90]);
    assert_eq!(t.outcome, Outcome::Superseded);
    let t = transaction(tracker.observe(Sender::Ecu, &[0x62, 0xF1, 0x8C, 0x01], 300));
    assert_eq!(t.request, [0x22, 0xF1, 0x8C]);
}

#[test]
fn a_response_with_no_open_request_or_to_another_service_is_unsolicited() {
    let mut tracker = Tracker::new();
    assert_eq!(
        tracker.observe(Sender::Ecu, &[0x7E, 0x00], 5),
        [Observed::Unsolicited {
            response: vec![0x7E, 0x00],
            at_us: 5
        }]
    );
    tracker.observe(Sender::Tester, &[0x22, 0xF1, 0x90], 10);
    assert!(matches!(
        tracker.observe(Sender::Ecu, &[0x50, 0x01], 20)[..],
        [Observed::Unsolicited { .. }]
    ));
    let t = transaction(tracker.observe(Sender::Ecu, &[0x62, 0xF1, 0x90], 30));
    assert!(matches!(
        t.outcome,
        Outcome::Answered { latency_us: 20, .. }
    ));
}

#[test]
fn a_request_quiet_past_the_timeout_since_its_last_pending_answer_times_out() {
    let mut tracker = Tracker::new().with_timeout_us(1_000);
    tracker.observe(Sender::Tester, &[0x31, 0x01, 0x02, 0x03], 0);
    tracker.observe(Sender::Ecu, &[0x7F, 0x31, 0x78], 900);
    assert_eq!(tracker.expire(1_500), None);
    let t = transaction(tracker.expire(1_900));
    assert_eq!(t.pending_responses, 1);
    assert_eq!(t.outcome, Outcome::TimedOut);
}

#[test]
fn the_end_of_a_capture_leaves_the_open_request_unfinished() {
    let mut tracker = Tracker::new();
    tracker.observe(Sender::Tester, &[0x22, 0xF1, 0x90], 0);
    assert_eq!(transaction(tracker.finish()).outcome, Outcome::Unfinished);
    assert_eq!(tracker.finish(), None);
}

#[test]
fn a_reply_that_does_not_echo_the_requested_did_is_unsolicited() {
    let mut tracker = Tracker::new();
    tracker.observe(Sender::Tester, &[0x22, 0xF1, 0x90], 0);
    assert!(matches!(
        tracker.observe(Sender::Ecu, &[0x62, 0xF1, 0x8C, 0x01], 10)[..],
        [Observed::Unsolicited { .. }]
    ));
    let t = transaction(tracker.observe(Sender::Ecu, &[0x62, 0xF1, 0x90, 0x01], 20));
    assert!(matches!(
        t.outcome,
        Outcome::Answered { latency_us: 20, .. }
    ));
}

#[test]
fn a_positive_answer_that_fails_strict_decoding_ends_the_transaction_malformed() {
    let mut tracker = Tracker::new();
    tracker.observe(Sender::Tester, &[0x10, 0x03], 0);
    let t = transaction(tracker.observe(Sender::Ecu, &[0x50, 0x03, 0x00], 40));
    assert_eq!(
        t.outcome,
        Outcome::Malformed {
            response: vec![0x50, 0x03, 0x00],
            latency_us: 40
        }
    );
}

#[test]
fn a_suppressed_request_to_an_unmodelled_sub_function_service_ends_suppressed() {
    let mut tracker = Tracker::new();
    tracker.observe(Sender::Tester, &[0x29, 0x80], 0);
    let t = transaction(tracker.observe(Sender::Tester, &[0x3E, 0x80], 100));
    assert_eq!(t.outcome, Outcome::Suppressed);
}

#[test]
fn silence_after_response_pending_times_out_even_when_suppressed() {
    let mut tracker = Tracker::new().with_timeout_us(1_000);
    tracker.observe(Sender::Tester, &[0x31, 0x81, 0x02, 0x03], 0);
    tracker.observe(Sender::Ecu, &[0x7F, 0x31, 0x78], 100);
    assert_eq!(
        transaction(tracker.expire(1_100)).outcome,
        Outcome::TimedOut
    );
}

#[test]
fn an_empty_message_is_ignored() {
    let mut tracker = Tracker::new();
    assert!(tracker.observe(Sender::Tester, &[], 0).is_empty());
    assert!(tracker.observe(Sender::Ecu, &[], 0).is_empty());
    assert_eq!(tracker.finish(), None);
}

#[test]
fn a_reply_after_the_timeout_ends_the_request_timed_out_and_is_itself_unsolicited() {
    let mut tracker = Tracker::new();
    tracker.observe(Sender::Tester, &[0x22, 0xF1, 0x90], 0);
    let seen = tracker.observe(Sender::Ecu, &[0x62, 0xF1, 0x90, 0x01], 60_000_000);
    let [Observed::Transaction(t), Observed::Unsolicited { .. }] = &seen[..] else {
        panic!("{seen:?}")
    };
    assert_eq!(t.outcome, Outcome::TimedOut);
}

#[test]
fn a_new_request_long_after_the_last_closes_it_timed_out_not_superseded() {
    let mut tracker = Tracker::new();
    tracker.observe(Sender::Tester, &[0x22, 0xF1, 0x90], 0);
    let t = transaction(tracker.observe(Sender::Tester, &[0x22, 0xF1, 0x8C], 60_000_000));
    assert_eq!(t.request, [0x22, 0xF1, 0x90]);
    assert_eq!(t.outcome, Outcome::TimedOut);
}

#[test]
fn a_keep_alive_tester_present_does_not_supersede_a_request_owed_a_response() {
    let mut tracker = Tracker::new();
    assert!(
        tracker
            .observe(Sender::Tester, &[0x31, 0x01, 0x02, 0x03], 0)
            .is_empty()
    );
    assert!(
        tracker
            .observe(Sender::Ecu, &[0x7F, 0x31, 0x78], 10_000)
            .is_empty()
    );
    let keep_alive = transaction(tracker.observe(Sender::Tester, &[0x3E, 0x80], 2_000_000));
    assert_eq!(keep_alive.request, [0x3E, 0x80]);
    assert_eq!(keep_alive.outcome, Outcome::Suppressed);
    let routine = transaction(tracker.observe(Sender::Ecu, &[0x71, 0x01, 0x02, 0x03], 3_000_000));
    assert_eq!(routine.request, [0x31, 0x01, 0x02, 0x03]);
    assert_eq!(routine.pending_responses, 1);
    assert_eq!(
        routine.outcome,
        Outcome::Answered {
            response: vec![0x71, 0x01, 0x02, 0x03],
            latency_us: 3_000_000
        }
    );
}
