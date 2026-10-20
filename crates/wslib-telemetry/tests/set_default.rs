#![cfg(all(feature = "setup-core", feature = "ring"))]

use std::sync::Once;
use std::thread;

use wslib_telemetry::{LogLevel, Logs, Telemetry};

fn scoped(default_filter: &str, logs: &Logs) -> tracing::subscriber::DefaultGuard {
    static NO_RUST_LOG: Once = Once::new();
    // SAFETY: every test passes through here before anything reads the environment.
    NO_RUST_LOG.call_once(|| unsafe { std::env::remove_var("RUST_LOG") });
    Telemetry::cli(default_filter)
        .ansi(false)
        .with_ring(logs)
        .set_default()
}

fn messages(logs: &Logs) -> Vec<String> {
    let records = logs.snapshot().records;
    records.iter().map(|r| r.message.clone()).collect()
}

#[test]
fn a_scoped_install_captures_only_while_its_guard_lives() {
    let logs = Logs::new(&["scoped"]);
    tracing::info!(target: "scoped", "before");
    let guard = scoped("info", &logs);
    tracing::info!(target: "scoped", "during");
    tracing::debug!(target: "scoped", "below the filter");
    drop(guard);
    tracing::info!(target: "scoped", "after");

    assert_eq!(messages(&logs), ["during"]);
}

#[test]
fn a_scoped_install_leaves_other_threads_alone() {
    let logs = Logs::new(&["scoped"]);
    let _guard = scoped("info", &logs);
    thread::spawn(|| tracing::info!(target: "scoped", "elsewhere"))
        .join()
        .unwrap();
    tracing::info!(target: "scoped", "here");

    assert_eq!(messages(&logs), ["here"]);
}

#[test]
fn two_scoped_installs_in_one_process_each_capture_their_own() {
    let [first, second] = ["first", "second"].map(|name| {
        thread::spawn(move || {
            let logs = Logs::new(&["scoped"]);
            let _guard = scoped("info", &logs);
            tracing::info!(target: "scoped", "{name}");
            logs
        })
    });
    let [first, second] = [first, second].map(|t| t.join().unwrap());

    assert_eq!(messages(&first), ["first"]);
    assert_eq!(messages(&second), ["second"]);
}

#[test]
fn nested_scoped_installs_restore_the_outer_one() {
    let outer = Logs::new(&["scoped"]);
    let inner = Logs::new(&["scoped"]);
    let _outer = scoped("info", &outer);
    {
        let _inner = scoped("info", &inner);
        tracing::info!(target: "scoped", "inner");
    }
    tracing::info!(target: "scoped", "outer");

    assert_eq!(messages(&inner), ["inner"]);
    assert_eq!(messages(&outer), ["outer"]);
}

#[test]
fn a_default_filter_that_does_not_parse_is_warned_about_in_the_scoped_subscriber() {
    let logs = Logs::new(&["wslib_telemetry"]);
    let _guard = scoped("wslib_telemetry=loudest", &logs);

    let snapshot = logs.snapshot();
    let [warning] = &snapshot.records[..] else {
        panic!("expected the one warning, got {:?}", snapshot.records);
    };
    assert_eq!(warning.level, LogLevel::Warn);
    assert!(
        warning
            .fields
            .contains(&("default_filter".into(), "wslib_telemetry=loudest".into())),
        "{:?}",
        warning.fields
    );
}
