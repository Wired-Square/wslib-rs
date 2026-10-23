//! A process of its own, since a global subscriber is once per process.
#![cfg(all(feature = "setup-core", feature = "ring"))]

use wslib_telemetry::{Logs, Telemetry};

#[test]
fn a_log_record_reaches_the_subscriber_through_the_same_filter() {
    // SAFETY: the only test in this binary, so no other thread reads the environment.
    unsafe { std::env::set_var("RUST_LOG", "foo=debug") };
    let logs = Logs::new(&["foo", "bar"]);
    Telemetry::cli("info").ansi(false).with_ring(&logs).init();

    log::debug!(target: "foo", "shown");
    log::trace!(target: "foo", "below foo's level");
    log::info!(target: "bar", "below the global level");

    let records = logs.snapshot().records;
    let messages: Vec<_> = records.iter().map(|r| r.message.as_str()).collect();
    assert_eq!(messages, ["shown"]);
}
