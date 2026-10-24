//! A process of its own, since a global subscriber is once per process.
#![cfg(all(feature = "setup-core", feature = "ring"))]

use wslib_telemetry::{Logs, Telemetry};

struct Elsewhere;

impl log::Log for Elsewhere {
    fn enabled(&self, _: &log::Metadata<'_>) -> bool {
        false
    }

    fn log(&self, _: &log::Record<'_>) {}

    fn flush(&self) {}
}

#[test]
fn a_rejected_filter_is_warned_about_when_an_installed_log_logger_fails_the_install() {
    // SAFETY: the only test in this binary, so no other thread reads the environment.
    unsafe { std::env::set_var("RUST_LOG", "wslib_telemetry=loudest") };
    log::set_logger(&Elsewhere).unwrap();
    let logs = Logs::new(&["wslib_telemetry"]);

    let installed = Telemetry::cli("warn")
        .ansi(false)
        .with_ring(&logs)
        .try_init();
    assert!(installed.is_err(), "the log bridge could not be installed");

    let snapshot = logs.snapshot();
    let [warning] = &snapshot.records[..] else {
        panic!("expected the one warning, got {:?}", snapshot.records);
    };
    assert!(
        warning
            .fields
            .contains(&("rust_log".into(), "wslib_telemetry=loudest".into())),
        "{:?}",
        warning.fields
    );
}
