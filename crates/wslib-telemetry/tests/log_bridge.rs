//! A process of its own, since a global subscriber is once per process.
#![cfg(all(feature = "setup-core", feature = "ring"))]

use wslib_telemetry::{Logs, Telemetry};

#[test]
fn a_log_record_reaches_the_ring_under_its_own_target_through_the_same_filter() {
    // SAFETY: the only test in this binary, so no other thread reads the environment.
    unsafe { std::env::set_var("RUST_LOG", "foo=debug") };
    let logs = Logs::new(&["foo", "bar"]);
    Telemetry::cli("info").ansi(false).with_ring(&logs).init();

    log::debug!(target: "foo", "shown");
    log::trace!(target: "foo", "below foo's level");
    log::info!(target: "bar", "below the global level");

    let snapshot = logs.snapshot();
    let [record] = &snapshot.records[..] else {
        panic!("expected the one record, got {:?}", snapshot.records);
    };
    assert_eq!(
        (record.message.as_str(), record.target.as_str()),
        ("shown", "foo")
    );
    assert_eq!(record.fields, []);
}
