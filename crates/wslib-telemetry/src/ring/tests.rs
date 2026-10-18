use super::*;

const AUDIT: &str = "audit";

fn captured(logs: &Logs, body: impl FnOnce()) {
    tracing::subscriber::with_default(logs.subscriber(), body);
}

fn this_crate() -> Logs {
    Logs::new(&["wslib_telemetry"])
}

fn one(logs: &Logs) -> Arc<LogRecord> {
    let snapshot = logs.snapshot();
    let [record] = &snapshot.records[..] else {
        panic!("expected one record, got {:?}", snapshot.records);
    };
    Arc::clone(record)
}

fn field<'a>(record: &'a LogRecord, name: &str) -> &'a str {
    record
        .fields
        .iter()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.as_str())
        .unwrap_or_else(|| panic!("no field {name} in {:?}", record.fields))
}

fn drained(tap: &mut Tap) -> Vec<Arc<LogRecord>> {
    std::iter::from_fn(|| tap.rx.try_recv().ok()).collect()
}

fn messages(records: &[Arc<LogRecord>]) -> Vec<&str> {
    records.iter().map(|r| r.message.as_str()).collect()
}

#[test]
fn an_event_from_a_captured_crate_is_captured_with_its_fields_in_order() {
    let logs = this_crate();
    captured(&logs, || {
        tracing::warn!(device = "bench", failures = 3, "poll failed");
    });

    let record = one(&logs);
    assert_eq!(record.seq, 1, "sequence numbers start at 1");
    assert_eq!(record.level, LogLevel::Warn);
    assert_eq!(record.message, "poll failed");
    assert_eq!(
        record.fields,
        [
            ("device".to_string(), "bench".to_string()),
            ("failures".to_string(), "3".to_string()),
        ],
        "a string is not quoted"
    );
    assert!(
        record.target.starts_with("wslib_telemetry"),
        "{}",
        record.target
    );
}

/// What a SQLite round-trip of the timestamp gives back.
#[test]
fn a_timestamp_carries_microseconds_and_no_finer() {
    let logs = this_crate();
    captured(&logs, || tracing::info!("tick"));
    assert_eq!(one(&logs).at.timestamp_subsec_nanos() % 1_000, 0);
}

/// The containment, asserted: `hyper` at `trace` logs `Cookie:` headers.
#[test]
fn a_foreign_crate_is_not_captured_and_a_named_crate_or_prefix_is() {
    let logs = Logs::new(&["myappliance_core", "appliance_*"]);
    captured(&logs, || {
        tracing::error!(target: "hyper::proto::h1", "connection closed");
        tracing::error!(target: "sqlx::query", "slow statement");
        tracing::error!(target: "myappliance_corex::thing", "a crate whose name merely starts the same");
        tracing::info!(target: "myappliance_core::poller", "polled");
        tracing::info!(target: "myappliance_core", "the crate root");
        tracing::info!(target: "appliance_server::serve", "matched by prefix");
        tracing::info!(target: "wslib_telemetry", "named by nobody");
    });

    let snapshot = logs.snapshot();
    let targets: Vec<_> = snapshot.records.iter().map(|r| r.target.as_str()).collect();
    assert_eq!(
        targets,
        [
            "myappliance_core::poller",
            "myappliance_core",
            "appliance_server::serve"
        ]
    );
}

#[test]
fn a_field_named_like_a_secret_or_as_the_caller_names_is_redacted() {
    let logs = Logs::builder(&["wslib_telemetry"]).redact(&["pin"]).build();
    captured(&logs, || {
        tracing::info!(
            username = "alex",
            password = "hunter2",
            operator_password = "hunter2",
            api_key = "hunter2",
            pin = "1234",
            key = "branding.logo",
            "signed in"
        );
    });

    let record = one(&logs);
    assert_eq!(field(&record, "username"), "alex");
    assert_eq!(field(&record, "password"), "[redacted]");
    assert_eq!(field(&record, "operator_password"), "[redacted]", "suffix");
    assert_eq!(field(&record, "api_key"), "[redacted]", "suffix");
    assert_eq!(field(&record, "pin"), "[redacted]", "the caller's");
    assert_eq!(field(&record, "key"), "branding.logo");
}

#[test]
fn the_ring_is_bounded_and_seq_shows_what_it_evicted() {
    let logs = this_crate();
    captured(&logs, || {
        for i in 0..LOG_RING + 5 {
            tracing::info!(i, "tick");
        }
    });

    let snapshot = logs.snapshot();
    assert_eq!(snapshot.records.len(), LOG_RING);
    assert_eq!(snapshot.records[0].seq, 6, "the oldest five went");
    assert_eq!(
        snapshot.records.last().unwrap().seq as usize - snapshot.records.len(),
        5,
        "which is what a client counts from the newest seq"
    );
}

#[test]
fn a_long_message_is_cut_and_marked_and_fields_share_a_second_budget() {
    let logs = this_crate();
    captured(&logs, || {
        tracing::info!(
            first = %"a".repeat(LOG_TEXT_MAX - 10),
            second = %"b".repeat(100),
            third = "never rendered",
            "{}",
            "x".repeat(10_000)
        );
    });

    let record = one(&logs);
    assert!(record.message.ends_with(TRUNCATED), "a cut line says so");
    assert!(record.message.len() <= LOG_TEXT_MAX + TRUNCATED.len());
    assert_eq!(field(&record, "first").len(), LOG_TEXT_MAX - 10);
    assert!(field(&record, "second").ends_with(TRUNCATED));
    assert!(
        !record.fields.iter().any(|(k, _)| k == "third"),
        "a field past the budget is dropped: {:?}",
        record.fields
    );
}

#[test]
fn a_long_field_ahead_of_one_with_its_own_budget_does_not_spend_it() {
    let logs = Logs::builder(&["wslib_telemetry"])
        .own_budget(&["actor", "actor_id"])
        .build();
    let long = "x".repeat(LOG_TEXT_MAX + 1);
    captured(&logs, || {
        tracing::warn!(note = %"n".repeat(LOG_TEXT_MAX), actor = "admin", actor_id = "an-id", "refused");
        tracing::warn!(actor = "admin", actor_id = %long, "refused");
    });

    let snapshot = logs.snapshot();
    assert_eq!(field(&snapshot.records[0], "actor"), "admin");
    assert_eq!(field(&snapshot.records[0], "actor_id"), "an-id");
    assert!(
        field(&snapshot.records[1], "actor_id").ends_with(TRUNCATED),
        "an own budget is still a budget, and a consumer can tell it was cut"
    );
}

#[test]
fn the_feed_carries_what_the_ring_holds() {
    let logs = this_crate();
    let mut rx = logs.subscribe();
    captured(&logs, || tracing::warn!("something happened"));

    let record = rx.try_recv().expect("the feed carried the event");
    assert_eq!(record.message, "something happened");
    assert_eq!(record.seq, 1);
}

/// A name carrying a newline would forge a line wherever the ring is
/// rendered as text; a field an author called `message` is not the
/// event's sentence.
#[test]
fn a_control_character_is_escaped_and_the_first_message_is_the_sentence() {
    let logs = this_crate();
    captured(&logs, || {
        tracing::warn!(
            actor = "admin\nWARN forged",
            message = "not the sentence",
            "the sentence"
        );
    });

    let record = one(&logs);
    assert_eq!(record.message, "the sentence");
    assert_eq!(field(&record, "actor"), "admin\\nWARN forged");
    assert_eq!(field(&record, "message"), "not the sentence");
}

/// A fault that names somebody is not that person acting: only the
/// declared name is tapped.
#[test]
fn only_events_with_the_tapped_name_are_tapped() {
    let logs = this_crate();
    let mut tap = logs.tap(AUDIT, 64).expect("a free name");
    captured(&logs, || {
        tracing::warn!(name: "audit", actor = "mallory", "sign-in refused");
        tracing::info!(name: "audit", actor = "admin", username = "root", "authorised a key");
        tracing::error!(actor = "mallory", "a stored password hash is unreadable");
        tracing::warn!(name: "auditor", "a name that merely starts the same");
    });

    let tapped = drained(&mut tap);
    assert_eq!(messages(&tapped), ["sign-in refused", "authorised a key"]);
    assert_eq!(tapped[1].fields[1], ("username".into(), "root".into()));
    assert_eq!(logs.snapshot().records.len(), 4, "the ring holds them all");
}

#[test]
fn an_uncaptured_target_is_never_tapped() {
    let logs = this_crate();
    let mut tap = logs.tap(AUDIT, 64).unwrap();
    captured(&logs, || {
        tracing::warn!(name: "audit", target: "elsewhere", actor = "mallory", "not captured");
    });
    assert!(drained(&mut tap).is_empty());
}

#[test]
fn a_second_tap_on_one_name_is_refused_until_the_first_closes() {
    let logs = this_crate();
    let _first = logs.tap(AUDIT, 64).expect("a free name");
    assert!(
        logs.tap(AUDIT, 64).is_none(),
        "refused, and the caller can tell"
    );
    assert!(logs.tap("other", 64).is_some(), "names are separate");
    logs.close_tap(AUDIT);
    assert!(logs.tap(AUDIT, 64).is_some());
}

#[tokio::test]
async fn the_drain_receives_what_was_emitted_before_it_ran_and_ends_once_closed() {
    let logs = this_crate();
    captured(&logs, || tracing::warn!(name: "audit", "before the tap"));
    let mut tap = logs.tap(AUDIT, 64).unwrap();
    captured(
        &logs,
        || tracing::warn!(name: "audit", "before the first poll"),
    );

    let drain = tokio::spawn(async move {
        let mut seen = Vec::new();
        while let Some(record) = tap.rx.recv().await {
            seen.push(record.message.clone());
        }
        seen
    });
    captured(
        &logs,
        || tracing::warn!(name: "audit", "queued at the close"),
    );
    logs.close_tap(AUDIT);
    captured(&logs, || tracing::warn!(name: "audit", "after the close"));

    let seen = drain.await.expect("the drain ends");
    assert_eq!(seen, ["before the first poll", "queued at the close"]);
}

#[test]
fn a_full_tap_loses_the_record_and_counts_it() {
    let logs = this_crate();
    let mut tap = logs.tap(AUDIT, 1).unwrap();
    captured(&logs, || {
        for i in 0..3 {
            tracing::warn!(name: "audit", i, "did a thing");
        }
    });
    assert_eq!(tap.lost.swap(0, Ordering::Relaxed), 2);
    assert_eq!(drained(&mut tap).len(), 1);
    assert_eq!(logs.snapshot().records.len(), 3, "the ring lost none");
}

#[test]
fn a_credential_in_a_url_is_stripped_from_the_message_and_every_field() {
    let logs = this_crate();
    let url = "postgres://app:hunter2@db.invalid/x";
    captured(&logs, || {
        tracing::warn!(url = %url, debugged = ?url, plain = url, "connect to {url} failed");
    });

    let record = one(&logs);
    assert_eq!(
        record.message,
        "connect to postgres://redacted@db.invalid/x failed"
    );
    assert_eq!(field(&record, "url"), "postgres://redacted@db.invalid/x");
    assert_eq!(field(&record, "plain"), "postgres://redacted@db.invalid/x");
    assert_eq!(
        field(&record, "debugged"),
        "\"postgres://redacted@db.invalid/x\""
    );
}

#[test]
fn a_url_without_userinfo_and_an_address_past_the_path_are_unchanged() {
    let logs = this_crate();
    let text = "posted https://example.invalid/contact?to=user@example.invalid";
    captured(&logs, || {
        tracing::info!(target_url = "https://example.invalid/x", "{text}")
    });

    let record = one(&logs);
    assert_eq!(record.message, text);
    assert_eq!(field(&record, "target_url"), "https://example.invalid/x");
}

#[test]
fn every_url_in_one_line_is_stripped() {
    let logs = this_crate();
    captured(&logs, || {
        tracing::info!("tried https://a:1@one.invalid/x then https://b:2@two.invalid/y");
    });
    assert_eq!(
        one(&logs).message,
        "tried https://redacted@one.invalid/x then https://redacted@two.invalid/y"
    );
}

#[test]
fn a_url_straddling_the_budget_leaves_no_credential_before_the_marker() {
    let logs = this_crate();
    let pad = "p".repeat(LOG_TEXT_MAX - "postgres://app:hun".len());
    captured(&logs, || {
        tracing::warn!("{pad}postgres://app:hunter2@db.invalid/x");
    });

    let message = one(&logs).message.clone();
    assert!(message.ends_with(TRUNCATED), "{message}");
    assert!(!message.contains("app:"), "{message}");
}

#[test]
fn a_field_named_like_a_secret_is_redacted_whole_even_holding_a_url() {
    let logs = this_crate();
    captured(&logs, || {
        tracing::info!(password = "postgres://app:hunter2@db.invalid/x", "rotated");
    });
    assert_eq!(field(&one(&logs), "password"), "[redacted]");
}
