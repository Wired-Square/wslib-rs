use std::fs;
use std::io;
use std::path::{Path, PathBuf};

mod common;

use common::{Scratch, read};
use wslib_file_atomic::{
    CommitError, Options, Readers, RecordIdentity, Recovered, Refused, Transaction, recover,
    recover_expecting, recover_identified, replace_private,
};

const KEY: &str = "app.key";
const CERT: &str = "app.crt";
const STAGED_KEY: &str = "app.key.tls.txn";
const STAGED_CERT: &str = "app.crt.tls.txn";
const RECORD: &str = "tls.txn";

/// A directory holding the old pair.
fn pair(name: &str) -> Scratch {
    let dir = Scratch::new(name);
    fs::write(dir.join(KEY), b"old key").unwrap();
    fs::write(dir.join(CERT), b"old cert").unwrap();
    dir
}

fn record(state: &str, targets: &[PathBuf]) -> String {
    let lines: String = targets
        .iter()
        .map(|target| {
            format!(
                "{}\n",
                fs::canonicalize(target.parent().unwrap())
                    .unwrap()
                    .join(target.file_name().unwrap())
                    .display()
            )
        })
        .collect();
    format!("{state}\n{lines}")
}

fn write_record(dir: &Scratch, state: &str) {
    let contents = record(state, &[dir.join(KEY), dir.join(CERT)]);
    fs::write(dir.join(RECORD), contents).unwrap();
}

fn stage_by_hand(dir: &Scratch, staged: &[&str]) {
    for name in staged {
        fs::write(dir.join(name), format!("new {name}")).unwrap();
    }
}

fn assert_old_pair(dir: &Scratch) {
    assert_eq!(read(&dir.join(KEY)), b"old key");
    assert_eq!(read(&dir.join(CERT)), b"old cert");
}

fn assert_only(dir: &Scratch, names: &[&str]) {
    let mut left: Vec<_> = fs::read_dir(&dir.0)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect();
    left.sort();
    let mut names: Vec<_> = names.iter().map(|name| name.to_string()).collect();
    names.sort();
    assert_eq!(left, names);
}

fn stage_pair(dir: &Scratch) -> Transaction {
    let mut transaction = Transaction::begin(&dir.0, "tls").unwrap();
    transaction
        .stage(&dir.join(KEY), b"new key", &Options::new())
        .unwrap();
    transaction
        .stage(
            &dir.join(CERT),
            b"new cert",
            &Options::new().readers(Readers::Readable),
        )
        .unwrap();
    transaction
}

#[test]
fn hidden_staging_options_do_not_change_a_transaction_s_staged_names() {
    let dir = pair("txn-hidden");
    let mut transaction = Transaction::begin(&dir.0, "tls").unwrap();
    transaction
        .stage(
            &dir.join(KEY),
            b"new key",
            &Options::new().hidden_staging(true),
        )
        .unwrap();
    assert_eq!(read(&dir.join(STAGED_KEY)), b"new key");
    transaction.abort().unwrap();
    assert_old_pair(&dir);
}

#[test]
fn a_commit_replaces_every_file_and_leaves_nothing_else() {
    let dir = pair("txn-commit");
    stage_pair(&dir).commit().unwrap();
    assert_eq!(read(&dir.join(KEY)), b"new key");
    assert_eq!(read(&dir.join(CERT)), b"new cert");
    assert_only(&dir, &[KEY, CERT]);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = |name| fs::metadata(dir.join(name)).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(KEY), 0o600);
        assert_eq!(mode(CERT), 0o644);
    }
}

#[test]
fn staged_files_are_named_for_the_transaction_and_listed_pending() {
    let dir = pair("txn-names");
    let transaction = stage_pair(&dir);
    assert_eq!(read(&dir.join(STAGED_KEY)), b"new key");
    assert_eq!(read(&dir.join(STAGED_CERT)), b"new cert");
    assert_eq!(
        fs::read_to_string(dir.join(RECORD)).unwrap(),
        record("pending", &[dir.join(KEY), dir.join(CERT)])
    );
    transaction.abort().unwrap();
}

#[test]
fn a_failed_stage_rolls_the_transaction_back() {
    let dir = pair("txn-stage-fails");
    let mut transaction = Transaction::begin(&dir.0, "tls").unwrap();
    transaction
        .stage(&dir.join(KEY), b"new key", &Options::new())
        .unwrap();
    let failed = transaction.stage_with(&dir.join(CERT), &Options::new(), |_| {
        Err(io::Error::other("serialising failed"))
    });
    assert_eq!(failed.unwrap_err().to_string(), "serialising failed");
    assert_old_pair(&dir);
    assert_only(&dir, &[KEY, CERT]);
    assert!(transaction.commit().is_err(), "it was rolled back");
    assert_old_pair(&dir);
}

#[test]
fn abort_removes_the_staged_files_and_the_record() {
    let dir = pair("txn-abort");
    stage_pair(&dir).abort().unwrap();
    assert_old_pair(&dir);
    assert_only(&dir, &[KEY, CERT]);
}

#[test]
fn dropping_an_uncommitted_transaction_aborts_it() {
    let dir = pair("txn-drop");
    drop(stage_pair(&dir));
    assert_old_pair(&dir);
    assert_only(&dir, &[KEY, CERT]);
}

#[test]
fn begin_is_refused_while_a_record_is_there() {
    let dir = pair("txn-begin-refused");
    let first = stage_pair(&dir);
    let refused = Transaction::begin(&dir.0, "tls").unwrap_err();
    assert_eq!(refused.kind(), io::ErrorKind::AlreadyExists);
    assert_eq!(read(&dir.join(STAGED_KEY)), b"new key");
    first.commit().unwrap();
    Transaction::begin(&dir.0, "tls").unwrap().abort().unwrap();
}

/// A key and its certificate in directories of their own, the record in a third.
fn split_pair(name: &str) -> (Scratch, PathBuf, PathBuf) {
    let dir = Scratch::new(name);
    let (key, cert) = (dir.join("private").join(KEY), dir.join("certs").join(CERT));
    for path in [&key, &cert] {
        fs::create_dir(path.parent().unwrap()).unwrap();
        fs::write(path, b"old").unwrap();
    }
    fs::create_dir(dir.join("state")).unwrap();
    (dir, key, cert)
}

#[test]
fn a_commit_spans_directories() {
    let (dir, key, cert) = split_pair("txn-two-dirs");
    let mut transaction = Transaction::begin(&dir.join("state"), "tls").unwrap();
    transaction
        .stage(&key, b"new key", &Options::new())
        .unwrap();
    assert_eq!(read(&dir.join("private").join(STAGED_KEY)), b"new key");
    transaction
        .stage(&cert, b"new cert", &Options::new())
        .unwrap();
    transaction.commit().unwrap();
    assert_eq!(read(&key), b"new key");
    assert_eq!(read(&cert), b"new cert");
    assert_only(&dir, &["private", "certs", "state"]);
    assert_eq!(fs::read_dir(dir.join("state")).unwrap().count(), 0);
}

#[test]
fn a_committed_record_across_directories_is_rolled_forward_mid_renames() {
    let (dir, key, cert) = split_pair("txn-two-dirs-recover");
    let state = dir.join("state");
    fs::write(
        state.join(RECORD),
        record("committed", &[key.clone(), cert.clone()]),
    )
    .unwrap();
    fs::write(&key, b"new key").unwrap();
    fs::write(dir.join("certs").join(STAGED_CERT), b"new cert").unwrap();
    assert_eq!(recover(&state, "tls").unwrap(), Recovered::RolledForward);
    assert_eq!(read(&key), b"new key");
    assert_eq!(read(&cert), b"new cert");
    assert!(!dir.join("certs").join(STAGED_CERT).exists());
    assert!(!state.join(RECORD).exists());
}

#[test]
fn a_missing_parent_is_refused_unless_created() {
    let dir = Scratch::new("txn-parents");
    let mut transaction = Transaction::begin(&dir.0, "tls").unwrap();
    let path = dir.join("a/b").join(KEY);
    let missing = transaction.stage(&path, b"x", &Options::new()).unwrap_err();
    assert_eq!(missing.kind(), io::ErrorKind::NotFound);
    transaction
        .stage(&path, b"new key", &Options::new().create_parents(true))
        .unwrap();
    transaction.commit().unwrap();
    assert_eq!(read(&path), b"new key");
}

#[test]
fn the_record_create_new_and_a_second_stage_of_one_file_are_refused() {
    let dir = pair("txn-refusals");
    let mut transaction = Transaction::begin(&dir.0, "tls").unwrap();
    let record = transaction
        .stage(&dir.join(RECORD), b"x", &Options::new())
        .unwrap_err();
    assert_eq!(record.kind(), io::ErrorKind::InvalidInput);
    let create_new = transaction
        .stage(&dir.join(KEY), b"x", &Options::new().create_new(true))
        .unwrap_err();
    assert_eq!(create_new.kind(), io::ErrorKind::InvalidInput);
    transaction
        .stage(&dir.join(KEY), b"new key", &Options::new())
        .unwrap();
    let twice = transaction
        .stage(&dir.join(KEY), b"newer", &Options::new())
        .unwrap_err();
    assert_eq!(twice.kind(), io::ErrorKind::InvalidInput);
    transaction.commit().unwrap();
    assert_eq!(read(&dir.join(KEY)), b"new key");
}

#[test]
fn a_name_with_a_separator_or_a_tab_is_refused() {
    let dir = Scratch::new("txn-bad-name");
    for name in ["a/b", "a\tb", "a\nb", "..", ""] {
        let refused = Transaction::begin(&dir.0, name).unwrap_err();
        assert_eq!(refused.kind(), io::ErrorKind::InvalidInput, "{name:?}");
        assert_eq!(
            recover(&dir.0, name).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
    }
}

#[test]
fn a_plain_replace_of_a_target_leaves_the_transactions_staged_file() {
    let dir = pair("txn-plain-replace");
    let transaction = stage_pair(&dir);
    replace_private(&dir.join(KEY), b"interim key").unwrap();
    assert_eq!(read(&dir.join(STAGED_KEY)), b"new key");
    transaction.commit().unwrap();
    assert_eq!(read(&dir.join(KEY)), b"new key");
}

#[test]
fn recovering_with_no_record_touches_nothing() {
    let dir = pair("txn-recover-nothing");
    assert_eq!(recover(&dir.0, "tls").unwrap(), Recovered::Nothing);
    assert_old_pair(&dir);
    assert_only(&dir, &[KEY, CERT]);
}

#[test]
fn a_pending_record_is_rolled_back_whatever_was_staged() {
    for (case, staged) in [
        ("none", &[][..]),
        ("some", &[STAGED_KEY][..]),
        ("all", &[STAGED_KEY, STAGED_CERT][..]),
    ] {
        let dir = pair(&format!("txn-pending-{case}"));
        write_record(&dir, "pending");
        stage_by_hand(&dir, staged);
        assert_eq!(recover(&dir.0, "tls").unwrap(), Recovered::RolledBack);
        assert_old_pair(&dir);
        assert_only(&dir, &[KEY, CERT]);
    }
}

#[test]
fn a_pending_record_with_no_files_is_rolled_back() {
    let dir = pair("txn-pending-empty");
    std::mem::forget(Transaction::begin(&dir.0, "tls").unwrap());
    assert!(dir.join(RECORD).exists());
    assert_eq!(recover(&dir.0, "tls").unwrap(), Recovered::RolledBack);
    assert_only(&dir, &[KEY, CERT]);
}

#[test]
fn a_committed_record_is_rolled_forward_however_far_the_renames_got() {
    for (case, staged) in [
        ("none-renamed", &[STAGED_KEY, STAGED_CERT][..]),
        ("mid-renames", &[STAGED_CERT][..]),
        ("all-renamed", &[][..]),
    ] {
        let dir = pair(&format!("txn-committed-{case}"));
        write_record(&dir, "committed");
        stage_by_hand(&dir, &[STAGED_KEY, STAGED_CERT]);
        for name in [STAGED_KEY, STAGED_CERT] {
            if !staged.contains(&name) {
                let target = name.trim_end_matches(".tls.txn");
                fs::rename(dir.join(name), dir.join(target)).unwrap();
            }
        }
        assert_eq!(recover(&dir.0, "tls").unwrap(), Recovered::RolledForward);
        assert_eq!(read(&dir.join(KEY)), format!("new {STAGED_KEY}").as_bytes());
        assert_eq!(
            read(&dir.join(CERT)),
            format!("new {STAGED_CERT}").as_bytes()
        );
        assert_only(&dir, &[KEY, CERT]);
        assert_eq!(recover(&dir.0, "tls").unwrap(), Recovered::Nothing);
    }
}

#[test]
fn a_malformed_record_is_an_error_and_nothing_is_touched() {
    for (case, record) in [
        ("empty", &b""[..]),
        ("unknown-state", b"applied\n/app.key\n"),
        ("relative", b"committed\napp.key\n"),
        ("blank-line", b"pending\n\n"),
        ("no-file-name", b"pending\n/\n"),
        ("not-utf8", b"pending\n/\xff\n"),
    ] {
        let dir = pair(&format!("txn-malformed-{case}"));
        fs::write(dir.join(RECORD), record).unwrap();
        stage_by_hand(&dir, &[STAGED_KEY]);
        let refused = recover(&dir.0, "tls").unwrap_err();
        assert_eq!(refused.kind(), io::ErrorKind::InvalidData, "{case}");
        assert!(refusal(&refused).is_none(), "{case}");
        assert_old_pair(&dir);
        assert_only(&dir, &[KEY, CERT, STAGED_KEY, RECORD]);
    }
}

fn refusal(error: &io::Error) -> Option<&Refused> {
    error.get_ref()?.downcast_ref()
}

fn assert_refused(refused: &io::Error, path: &str) {
    assert_eq!(refused.kind(), io::ErrorKind::PermissionDenied, "{refused}");
    assert!(refused.to_string().contains(path), "{refused}");
    let refusal = refusal(refused).expect("a refusal carries Refused");
    assert_eq!(refusal.path().file_name().unwrap(), path, "{refused}");
}

fn assert_refused_untouched(dir: &Scratch, refused: io::Error) {
    assert_refused(&refused, RECORD);
    assert_old_pair(dir);
    assert_eq!(
        read(&dir.join(STAGED_KEY)),
        format!("new {STAGED_KEY}").as_bytes()
    );
}

fn committed_and_staged(name: &str) -> Scratch {
    let dir = pair(name);
    write_record(&dir, "committed");
    stage_by_hand(&dir, &[STAGED_KEY, STAGED_CERT]);
    dir
}

#[cfg(unix)]
#[test]
fn a_record_others_may_write_is_refused() {
    use std::os::unix::fs::PermissionsExt;
    for mode in [0o620, 0o602] {
        let dir = committed_and_staged(&format!("txn-writable-{mode:o}"));
        fs::set_permissions(dir.join(RECORD), fs::Permissions::from_mode(mode)).unwrap();
        assert_refused_untouched(&dir, recover(&dir.0, "tls").unwrap_err());
    }
}

#[cfg(unix)]
#[test]
fn a_symlinked_record_is_refused() {
    let dir = committed_and_staged("txn-symlinked");
    let planted = dir.join("planted");
    fs::rename(dir.join(RECORD), &planted).unwrap();
    std::os::unix::fs::symlink(&planted, dir.join(RECORD)).unwrap();
    assert_refused_untouched(&dir, recover(&dir.0, "tls").unwrap_err());
}

#[cfg(unix)]
#[test]
fn a_record_that_is_not_a_regular_file_is_refused() {
    let dir = committed_and_staged("txn-not-a-file");
    fs::remove_file(dir.join(RECORD)).unwrap();
    fs::create_dir(dir.join(RECORD)).unwrap();
    assert_refused_untouched(&dir, recover(&dir.0, "tls").unwrap_err());

    fs::remove_dir(dir.join(RECORD)).unwrap();
    let fifo = std::ffi::CString::new(dir.join(RECORD).into_os_string().into_encoded_bytes());
    // SAFETY: a NUL-terminated path.
    assert_eq!(unsafe { libc::mkfifo(fifo.unwrap().as_ptr(), 0o600) }, 0);
    assert_refused_untouched(&dir, recover(&dir.0, "tls").unwrap_err());
}

#[cfg(unix)]
#[test]
fn a_record_owned_by_someone_else_is_refused() {
    // SAFETY: a plain syscall with no arguments.
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("skipped: only root can give a file away");
        return;
    }
    let dir = committed_and_staged("txn-owned-by-another");
    std::os::unix::fs::chown(dir.join(RECORD), Some(65534), None).unwrap();
    assert_refused_untouched(&dir, recover(&dir.0, "tls").unwrap_err());
}

#[cfg(unix)]
#[test]
fn a_staged_file_others_may_write_is_not_renamed_over_its_target() {
    use std::os::unix::fs::PermissionsExt;
    let dir = pair("txn-planted-staged");
    write_record(&dir, "committed");
    fs::write(dir.join(KEY), b"new key").unwrap();
    stage_by_hand(&dir, &[STAGED_CERT]);
    fs::set_permissions(dir.join(STAGED_CERT), fs::Permissions::from_mode(0o664)).unwrap();

    assert_refused(&recover(&dir.0, "tls").unwrap_err(), STAGED_CERT);
    assert_eq!(read(&dir.join(CERT)), b"old cert");
}

/// Gives `path` to SYSTEM, which only an elevated process may do; false when
/// this one may not.
#[cfg(windows)]
fn give_to_system(path: &Path) -> bool {
    let given = std::process::Command::new("icacls")
        .arg(path)
        .args(["/setowner", "*S-1-5-18"])
        .output()
        .unwrap();
    if !given.status.success() {
        eprintln!("skipped: only an elevated process can give a file away");
    }
    given.status.success()
}

#[cfg(windows)]
fn owner_of(path: &Path) -> String {
    let script = format!("(Get-Acl -LiteralPath '{}').Owner", path.display());
    let read = std::process::Command::new("powershell.exe")
        .args(["-NoProfile", "-Command", &script])
        .output()
        .unwrap();
    String::from_utf8(read.stdout).unwrap().trim().to_string()
}

#[cfg(windows)]
#[test]
fn a_symlinked_record_is_refused() {
    let dir = committed_and_staged("txn-symlinked");
    let planted = dir.join("planted");
    fs::rename(dir.join(RECORD), &planted).unwrap();
    if let Err(e) = std::os::windows::fs::symlink_file(&planted, dir.join(RECORD)) {
        eprintln!("skipped: no symbolic link privilege: {e}");
        return;
    }
    let refused = recover(&dir.0, "tls").unwrap_err();
    assert!(
        refused.to_string().contains("not a regular file"),
        "{refused}"
    );
    assert_refused_untouched(&dir, refused);
    assert!(planted.exists());
}

#[cfg(windows)]
#[test]
fn a_record_that_is_a_junction_or_a_directory_is_refused() {
    let dir = committed_and_staged("txn-junction");
    let planted = dir.join("planted");
    fs::create_dir(&planted).unwrap();
    fs::remove_file(dir.join(RECORD)).unwrap();
    let made = std::process::Command::new("cmd")
        .args(["/C", "mklink", "/J"])
        .arg(dir.join(RECORD))
        .arg(&planted)
        .output()
        .unwrap();
    assert!(made.status.success(), "{made:?}");
    let refused = recover(&dir.0, "tls").unwrap_err();
    assert!(
        refused.to_string().contains("not a regular file"),
        "{refused}"
    );
    assert_refused_untouched(&dir, refused);

    fs::remove_dir(dir.join(RECORD)).unwrap();
    assert!(planted.exists(), "removing the junction left its target");
    fs::create_dir(dir.join(RECORD)).unwrap();
    let refused = recover(&dir.0, "tls").unwrap_err();
    assert!(
        refused.to_string().contains("not a regular file"),
        "{refused}"
    );
    assert_refused_untouched(&dir, refused);
}

#[cfg(windows)]
#[test]
fn a_record_owned_by_someone_else_is_refused() {
    let dir = committed_and_staged("txn-owned-by-another");
    if !give_to_system(&dir.join(RECORD)) {
        return;
    }
    let refused = recover(&dir.0, "tls").unwrap_err();
    assert!(
        refused.to_string().contains("owned by another user"),
        "{refused}"
    );
    assert_refused_untouched(&dir, refused);
}

/// An elevated process owns what it makes through Administrators, its token's
/// default owner; an unelevated one through its user.
#[cfg(windows)]
#[test]
fn a_record_this_process_made_is_recovered_whoever_owns_it_for_the_token() {
    let dir = committed_and_staged("txn-own-record");
    eprintln!("the record is owned by {}", owner_of(&dir.join(RECORD)));
    assert_eq!(recover(&dir.0, "tls").unwrap(), Recovered::RolledForward);
    assert_eq!(read(&dir.join(KEY)), format!("new {STAGED_KEY}").as_bytes());
    assert_only(&dir, &[KEY, CERT]);
}

#[cfg(windows)]
#[test]
fn a_staged_file_owned_by_someone_else_is_not_renamed_over_its_target() {
    let dir = pair("txn-planted-staged");
    write_record(&dir, "committed");
    fs::write(dir.join(KEY), b"new key").unwrap();
    stage_by_hand(&dir, &[STAGED_CERT]);
    if !give_to_system(&dir.join(STAGED_CERT)) {
        return;
    }

    assert_refused(&recover(&dir.0, "tls").unwrap_err(), STAGED_CERT);
    assert_eq!(read(&dir.join(CERT)), b"old cert");
}

#[test]
fn a_record_naming_a_target_outside_the_expected_set_is_refused() {
    let dir = committed_and_staged("txn-unexpected-target");
    let key = dir.join(KEY);
    let refused = recover_expecting(&dir.0, "tls", &[&key]).unwrap_err();
    assert_refused_untouched(&dir, refused);

    let expected = [key.as_path(), &dir.join(CERT)];
    let recovered = recover_expecting(&dir.0, "tls", &expected).unwrap();
    assert_eq!(recovered, Recovered::RolledForward);
    assert_only(&dir, &[KEY, CERT]);
}

fn occupy(path: &Path) {
    let _ = fs::remove_file(path);
    fs::create_dir(path).unwrap();
    fs::write(path.join("inside"), b"").unwrap();
}

#[test]
fn a_commit_failing_before_the_commit_point_is_rolled_back() {
    let dir = pair("txn-commit-rolled-back");
    let transaction = stage_pair(&dir);
    occupy(&dir.join("tls.txn.new"));
    let Err(CommitError::RolledBack(_)) = transaction.commit() else {
        panic!("the committed record could not be staged");
    };
    assert_old_pair(&dir);
    assert_only(&dir, &[KEY, CERT, "tls.txn.new"]);
}

#[test]
fn a_commit_failing_after_the_commit_point_is_left_for_recover() {
    let dir = pair("txn-commit-committed");
    let transaction = stage_pair(&dir);
    occupy(&dir.join(CERT));
    let Err(CommitError::Committed(_)) = transaction.commit() else {
        panic!("the certificate could not be renamed over a directory");
    };
    assert!(
        fs::read_to_string(dir.join(RECORD))
            .unwrap()
            .starts_with("committed\n")
    );

    fs::remove_dir_all(dir.join(CERT)).unwrap();
    assert_eq!(recover(&dir.0, "tls").unwrap(), Recovered::RolledForward);
    assert_eq!(read(&dir.join(KEY)), b"new key");
    assert_eq!(read(&dir.join(CERT)), b"new cert");
    assert_only(&dir, &[KEY, CERT]);
}

fn left_for_recovery(name: &str) -> (Scratch, RecordIdentity) {
    let dir = pair(name);
    let transaction = stage_pair(&dir);
    occupy(&dir.join(CERT));
    let Err((CommitError::Committed(_), Some(identity))) = transaction.commit_identified() else {
        panic!("the certificate could not be renamed over a directory");
    };
    fs::remove_dir_all(dir.join(CERT)).unwrap();
    (dir, identity)
}

#[test]
fn a_record_still_the_one_a_commit_left_is_finished_without_the_owner_checks() {
    let (dir, identity) = left_for_recovery("txn-identified");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(dir.join(RECORD), fs::Permissions::from_mode(0o666)).unwrap();
    }
    let targets = [dir.join(KEY), dir.join(CERT)];
    let targets = [targets[0].as_path(), &targets[1]];
    let recovered = recover_identified(&dir.0, "tls", &targets, &identity).unwrap();
    assert_eq!(recovered, Some(Recovered::RolledForward));
    assert_eq!(read(&dir.join(CERT)), b"new cert");
    assert_only(&dir, &[KEY, CERT]);
    let gone = recover_identified(&dir.0, "tls", &targets, &identity).unwrap();
    assert_eq!(gone, Some(Recovered::Nothing));
}

#[test]
fn a_record_swapped_for_another_file_is_passed_over_by_its_identity() {
    let (dir, identity) = left_for_recovery("txn-swapped");
    let swapped = dir.join("swapped");
    fs::copy(dir.join(RECORD), &swapped).unwrap();
    fs::rename(&swapped, dir.join(RECORD)).unwrap();
    let targets = [dir.join(KEY), dir.join(CERT)];
    let targets = [targets[0].as_path(), &targets[1]];
    let passed_over = recover_identified(&dir.0, "tls", &targets, &identity).unwrap();
    assert_eq!(passed_over, None);
    assert!(dir.join(STAGED_CERT).exists());
    assert_eq!(recover(&dir.0, "tls").unwrap(), Recovered::RolledForward);
}

#[test]
fn a_commit_error_says_which_side_and_keeps_its_kind() {
    let committed = CommitError::Committed(io::ErrorKind::PermissionDenied.into());
    assert!(
        committed.to_string().starts_with("committed"),
        "{committed}"
    );
    let error = io::Error::from(committed);
    assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    let rolled_back = CommitError::RolledBack(io::ErrorKind::NotFound.into());
    assert!(
        rolled_back.to_string().contains("rolled back"),
        "{rolled_back}"
    );
}

#[test]
fn an_empty_directory_is_the_current_one() {
    let name = "wslib-file-atomic-empty-dir";
    let transaction = Transaction::begin(Path::new(""), name).unwrap();
    let record = fs::canonicalize(".").unwrap().join(format!("{name}.txn"));
    assert_eq!(transaction.record(), record);
    transaction.abort().unwrap();
    assert!(!record.exists());
}
