use std::num::NonZeroU32;
use std::path::Path;

use wslib_pairing::{OneTimeCode, PairingCode, Redemption, SpentBy, Status};

const THREE: NonZeroU32 = NonZeroU32::new(3).unwrap();

fn issue(path: &Path) -> (OneTimeCode, PairingCode) {
    OneTimeCode::issue(path, THREE).unwrap()
}

fn wrong(code: &PairingCode) -> PairingCode {
    let flipped = if code.expose().starts_with('A') {
        "B"
    } else {
        "A"
    };
    format!("{flipped}{}", &code.expose()[1..]).parse().unwrap()
}

fn reopened(path: &Path) -> OneTimeCode {
    OneTimeCode::open(path).unwrap().unwrap()
}

#[test]
fn the_right_code_is_accepted_once() {
    let dir = tempfile::tempdir().unwrap();
    let (issued, code) = issue(&dir.path().join("code"));
    assert_eq!(issued.redeem(&code).unwrap(), Redemption::Accepted);
    assert_eq!(issued.status().unwrap(), Status::Spent(SpentBy::Acceptance));
    assert_eq!(
        issued.redeem(&code).unwrap(),
        Redemption::Spent(SpentBy::Acceptance)
    );
}

#[test]
fn a_restart_cannot_revive_a_spent_code() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("code");
    let (issued, code) = issue(&path);
    assert_eq!(issued.redeem(&code).unwrap(), Redemption::Accepted);
    drop(issued);
    let restarted = reopened(&path);
    assert_eq!(
        restarted.redeem(&code).unwrap(),
        Redemption::Spent(SpentBy::Acceptance)
    );
}

#[test]
fn the_wrong_attempt_reaching_the_limit_answers_spent_by_lockout() {
    let dir = tempfile::tempdir().unwrap();
    let (issued, code) = issue(&dir.path().join("code"));
    let wrong = wrong(&code);
    assert_eq!(
        issued.redeem(&wrong).unwrap(),
        Redemption::Refused { remaining: 2 }
    );
    assert_eq!(
        issued.redeem(&wrong).unwrap(),
        Redemption::Refused { remaining: 1 }
    );
    assert_eq!(
        issued.redeem(&wrong).unwrap(),
        Redemption::Spent(SpentBy::Lockout)
    );
    assert_eq!(issued.status().unwrap(), Status::Spent(SpentBy::Lockout));
}

#[test]
fn the_right_code_after_spending_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let (issued, code) = issue(&dir.path().join("code"));
    for _ in 0..3 {
        let _ = issued.redeem(&wrong(&code)).unwrap();
    }
    assert_eq!(
        issued.redeem(&code).unwrap(),
        Redemption::Spent(SpentBy::Lockout)
    );
}

#[test]
fn wrong_attempts_count_across_a_restart() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("code");
    let (issued, code) = issue(&path);
    let _ = issued.redeem(&wrong(&code)).unwrap();
    let _ = issued.redeem(&wrong(&code)).unwrap();
    let restarted = reopened(&path);
    assert_eq!(
        restarted.redeem(&wrong(&code)).unwrap(),
        Redemption::Spent(SpentBy::Lockout)
    );
    assert_eq!(
        reopened(&path).redeem(&code).unwrap(),
        Redemption::Spent(SpentBy::Lockout)
    );
}

#[test]
fn reissuing_replaces_the_earlier_code() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("code");
    let (_, first) = issue(&path);
    let (second, _) = issue(&path);
    assert_eq!(
        second.redeem(&first).unwrap(),
        Redemption::Refused { remaining: 2 }
    );
}

#[test]
fn the_code_is_kept_only_as_its_hash_and_debug_hides_it() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("code");
    let (_, code) = issue(&path);
    let state = std::fs::read_to_string(&path).unwrap();
    assert!(!state.to_uppercase().contains(code.expose()));
    assert!(!format!("{code:?}").contains(code.expose()));
}

#[cfg(unix)]
#[test]
fn the_state_file_is_owner_only() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("code");
    let (issued, code) = issue(&path);
    let mode = || std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(), 0o600);
    let _ = issued.redeem(&code).unwrap();
    assert_eq!(mode(), 0o600);
}

#[test]
fn a_code_issued_by_another_holder_of_the_path_is_accepted() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("code");
    let (running, _) = issue(&path);
    let (_, reissued) = issue(&path);
    assert_eq!(running.redeem(&reissued).unwrap(), Redemption::Accepted);
    assert_eq!(
        reopened(&path).redeem(&reissued).unwrap(),
        Redemption::Spent(SpentBy::Acceptance)
    );
}

#[test]
fn concurrent_wrong_attempts_through_separate_handles_are_each_counted() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("code");
    let (_, code) = OneTimeCode::issue(&path, NonZeroU32::new(100).unwrap()).unwrap();
    let wrong = wrong(&code);
    std::thread::scope(|scope| {
        for _ in 0..8 {
            scope.spawn(|| {
                let handle = reopened(&path);
                for _ in 0..5 {
                    let _ = handle.redeem(&wrong).unwrap();
                }
            });
        }
    });
    assert_eq!(
        reopened(&path).status().unwrap(),
        Status::Pending {
            remaining: 60,
            limit: 100
        }
    );
}

#[test]
fn the_status_spends_no_attempt() {
    let dir = tempfile::tempdir().unwrap();
    let (issued, code) = issue(&dir.path().join("code"));
    let pending = Status::Pending {
        remaining: 3,
        limit: 3,
    };
    assert_eq!(issued.status().unwrap(), pending);
    assert_eq!(issued.status().unwrap(), pending);
    let _ = issued.redeem(&wrong(&code)).unwrap();
    assert_eq!(
        issued.status().unwrap(),
        Status::Pending {
            remaining: 2,
            limit: 3
        }
    );
}

#[test]
fn nothing_issued_opens_as_none() {
    let dir = tempfile::tempdir().unwrap();
    assert!(
        OneTimeCode::open(dir.path().join("code"))
            .unwrap()
            .is_none()
    );
}

#[test]
fn codes_are_26_base32_characters_and_differ() {
    let dir = tempfile::tempdir().unwrap();
    let (_, a) = issue(&dir.path().join("a"));
    let (_, b) = issue(&dir.path().join("b"));
    assert_eq!(a.expose().len(), 26);
    assert!(
        a.expose()
            .bytes()
            .all(|c| matches!(c, b'A'..=b'Z' | b'2'..=b'7'))
    );
    assert_ne!(a.expose(), b.expose());
}
