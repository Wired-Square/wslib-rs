use wslib_uds::testing::{Ecu, TIMING};
use wslib_uds::{
    DEFAULT_SESSION, Nrc, PROGRAMMING_SESSION, Safety, SessionFinding, SessionScan, SessionVerdict,
    session_verdict,
};

fn run(scan: &mut SessionScan, ecu: &mut Ecu) -> Vec<(u8, bool)> {
    let mut sent = Vec::new();
    while let Some(probe) = scan.next_probe() {
        let class = match probe.session {
            PROGRAMMING_SESSION => Safety::Destructive,
            _ => Safety::StateChanging,
        };
        assert_eq!(probe.safety(), class);
        sent.push((probe.session, probe.restore));
        let reply = ecu.answer(&probe.request().encode()).pop();
        scan.report(reply.as_deref());
    }
    sent
}

#[test]
fn a_session_scan_skips_programming_and_returns_to_default_after_each_session_entered() {
    let mut ecu = Ecu::new()
        .with_session(0x03)
        .with_session(PROGRAMMING_SESSION);
    let mut scan = SessionScan::new(0x01..=0x04);
    let sent = run(&mut scan, &mut ecu);
    assert_eq!(
        sent,
        [(0x01, false), (0x03, false), (0x01, true), (0x04, false)]
    );
    assert_eq!(ecu.active_session(), DEFAULT_SESSION);
    let verdicts: Vec<_> = scan
        .findings()
        .iter()
        .map(|f| (f.session, f.verdict))
        .collect();
    let supported = SessionVerdict::Supported {
        timing: Some(TIMING),
    };
    assert_eq!(
        verdicts,
        [
            (0x01, supported),
            (0x03, supported),
            (0x04, SessionVerdict::Unsupported)
        ]
    );
    assert_eq!(scan.progress().found, 2);
}

#[test]
fn the_programming_session_is_probed_only_under_a_destructive_ceiling() {
    let mut ecu = Ecu::new().with_session(PROGRAMMING_SESSION);
    for highest in [Safety::ReadOnly, Safety::StateChanging] {
        let mut scan = SessionScan::up_to(0x01..=0x02, highest);
        let expected: &[(u8, bool)] = match highest {
            Safety::ReadOnly => &[],
            _ => &[(0x01, false)],
        };
        assert_eq!(run(&mut scan, &mut ecu), expected, "{highest:?}");
    }
    let mut scan = SessionScan::up_to(0x02..=0x02, Safety::Destructive);
    assert_eq!(run(&mut scan, &mut ecu), [(0x02, false), (0x01, true)]);
}

#[test]
#[allow(deprecated)]
fn including_programming_is_a_destructive_ceiling() {
    let mut ecu = Ecu::new().with_session(PROGRAMMING_SESSION);
    let mut scan = SessionScan::including_programming(0x02..=0x02);
    assert_eq!(run(&mut scan, &mut ecu), [(0x02, false), (0x01, true)]);
}

#[test]
fn session_verdicts_follow_the_refusal_code() {
    assert_eq!(
        session_verdict(0x40, Some(&[0x7F, 0x10, 0x7E])),
        SessionVerdict::NotFromThisSession
    );
    assert_eq!(
        session_verdict(0x40, Some(&[0x7F, 0x10, 0x22])),
        SessionVerdict::ConditionsNotCorrect
    );
    assert_eq!(
        session_verdict(0x40, Some(&[0x7F, 0x10, 0x33])),
        SessionVerdict::Locked
    );
    assert_eq!(
        session_verdict(0x40, Some(&[0x50, 0x41])),
        SessionVerdict::Inconclusive { code: None }
    );
    assert_eq!(
        session_verdict(0x40, Some(&[0x50, 0x40, 0x00])),
        SessionVerdict::Supported { timing: None }
    );
}

fn restores_after(reply: Option<&[u8]>) -> bool {
    let mut scan = SessionScan::new(0x40..=0x41);
    scan.report(reply);
    scan.next_probe().unwrap().restore
}

#[test]
fn the_default_session_is_restored_after_any_probe_that_did_not_end_in_a_definite_refusal() {
    assert!(restores_after(None));
    assert!(restores_after(Some(&[0x50, 0x40, 0x00])));
    assert!(restores_after(Some(&[0x50, 0x41])));
    assert!(restores_after(Some(&[0xAA])));
    assert!(restores_after(Some(&[0x7F, 0x10, 0x78])));
    assert!(restores_after(Some(&[0x50, 0x40, 0x00, 0x32, 0x01, 0xF4])));
    assert!(!restores_after(Some(&[0x7F, 0x10, 0x12])));
    assert!(!restores_after(Some(&[0x7F, 0x10, 0x22])));
}

#[test]
fn probing_the_default_session_needs_no_restore() {
    let mut scan = SessionScan::new(0x01..=0x01);
    scan.report(None);
    assert_eq!(scan.next_probe(), None);
}

fn after_restore_answered(reply: Option<&[u8]>) -> SessionScan {
    let mut scan = SessionScan::new(0x03..=0x05);
    scan.report(Some(&[0x50, 0x03, 0x00, 0x32, 0x01, 0xF4]));
    assert!(scan.next_probe().unwrap().restore);
    scan.report(reply);
    scan
}

#[test]
fn a_refused_or_silent_restore_stops_the_plan_with_the_session_the_ecu_may_still_be_in() {
    for (reply, code) in [
        (
            Some(&[0x7F, 0x10, 0x22][..]),
            Some(Nrc::CONDITIONS_NOT_CORRECT),
        ),
        (None, None),
        (Some(&[0x50, 0x03][..]), None),
    ] {
        let scan = after_restore_answered(reply);
        assert_eq!(scan.next_probe(), None);
        assert!(scan.progress().stopped_early);
        assert_eq!(scan.progress().done, 1);
        assert_eq!(
            scan.findings().last(),
            Some(&SessionFinding {
                session: 0x03,
                verdict: SessionVerdict::NotRestored { code }
            })
        );
    }
}

#[test]
fn a_restore_answered_positively_lets_the_plan_carry_on() {
    let scan = after_restore_answered(Some(&[0x50, 0x01, 0x00, 0x32, 0x01, 0xF4]));
    assert_eq!(scan.next_probe().unwrap().session, 0x04);
    assert!(!scan.progress().stopped_early);
}
