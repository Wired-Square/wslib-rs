//! A process of its own, since a global subscriber is once per process.
#![cfg(all(feature = "setup", feature = "ring"))]

use wslib_telemetry::{LogLevel, Logs, Telemetry};

#[test]
fn a_rust_log_that_does_not_parse_is_warned_about_once_installed_and_a_second_install_fails() {
    // SAFETY: the only test in this binary, so no other thread reads the environment.
    unsafe { std::env::set_var("RUST_LOG", "wslib_telemetry=loudest") };
    let logs = Logs::new(&["wslib_telemetry"]);

    Telemetry::cli("warn")
        .ansi(false)
        .with_ring(&logs)
        .try_init()
        .expect("the first install");
    tracing::info!("below the default filter");

    let snapshot = logs.snapshot();
    let [warning] = &snapshot.records[..] else {
        panic!("expected the one warning, got {:?}", snapshot.records);
    };
    assert_eq!(warning.level, LogLevel::Warn);
    assert!(
        warning
            .fields
            .contains(&("rust_log".into(), "wslib_telemetry=loudest".into())),
        "{:?}",
        warning.fields
    );

    assert!(Telemetry::new("info").try_init().is_err());
}
