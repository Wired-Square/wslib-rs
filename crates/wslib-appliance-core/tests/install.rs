//! The subscriber `Logs::feed` builds, observed from outside the process: a global
//! subscriber is once per process, and journal priorities are written only when
//! stdout is the stream `JOURNAL_STREAM` names, so the test runs itself again as
//! a child whose stdout is a pipe it names.
#![cfg(unix)]

use std::os::fd::AsFd;
use std::os::unix::fs::MetadataExt;
use std::process::Command;

use wslib_telemetry::{LogLevel, Telemetry};

const TEST: &str = "install_filters_ahead_of_an_untimed_journal_formatter_and_the_ring";
const CHILD: &str = "APPLIANCE_CORE_INSTALL_CHILD";

#[test]
fn install_filters_ahead_of_an_untimed_journal_formatter_and_the_ring() {
    if std::env::var_os(CHILD).is_some() {
        return child();
    }
    let out = Command::new(std::env::current_exe().expect("this test"))
        .args(["--exact", TEST, "--test-threads=1"])
        .env(CHILD, "1")
        .env_remove("RUST_LOG")
        .output()
        .expect("runs");
    let stdout = String::from_utf8(out.stdout).expect("text");
    assert!(
        out.status.success(),
        "{stdout}{}",
        String::from_utf8_lossy(&out.stderr)
    );

    // The harness's own `test … ` can lead the first line.
    let written: Vec<_> = stdout
        .lines()
        .filter_map(|line| line.find('<').map(|at| &line[at..]))
        .collect();
    let [first, second, elsewhere, audit] = written[..] else {
        panic!("four lines expected: {written:?}");
    };
    assert_eq!(
        [first, second, elsewhere],
        [
            "<4> WARN install: first",
            "<4>second",
            "<6> INFO elsewhere: written, not captured",
        ]
    );
    assert!(
        audit.starts_with("<6> INFO install: an audit line note=nnn")
            && audit.ends_with(r#" actor="admin" actor_id="an-id""#),
        "{audit}"
    );
    assert!(!stdout.contains('\u{1b}'), "no colour: {stdout:?}");
}

fn child() {
    let stdout = std::io::stdout()
        .as_fd()
        .try_clone_to_owned()
        .expect("stdout");
    let stdout = std::fs::File::from(stdout).metadata().expect("stdout");
    // SAFETY: before the subscriber, on the only test this process runs.
    unsafe {
        std::env::set_var(
            "JOURNAL_STREAM",
            format!("{}:{}", stdout.dev(), stdout.ino()),
        )
    };

    let logs = wslib_appliance_core::logs(&["install"]);
    logs.feed(Telemetry::new("info").journald()).init();
    tracing::warn!("first\nsecond");
    tracing::debug!("below the default filter");
    tracing::info!(target: "elsewhere", "written, not captured");
    tracing::info!(
        name: "audit",
        note = %"n".repeat(wslib_telemetry::log::LOG_TEXT_MAX),
        actor = "admin",
        actor_id = "an-id",
        "an audit line"
    );

    let snapshot = wslib_appliance_core::backend::ring(&logs).snapshot();
    let captured: Vec<_> = snapshot
        .records
        .iter()
        .map(|r| (r.level, r.target.as_str()))
        .collect();
    assert_eq!(
        captured,
        [(LogLevel::Warn, "install"), (LogLevel::Info, "install")],
        "the filter is ahead of the ring, which captures the named crate alone"
    );
    let audit = &snapshot.records[1].fields;
    for name in ["actor", "actor_id"] {
        assert!(
            audit.iter().any(|(k, _)| k == name),
            "{name} kept its own budget: {audit:?}"
        );
    }
}
