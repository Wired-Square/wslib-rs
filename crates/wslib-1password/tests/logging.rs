//! Alone in its binary: tracing caches a callsite's interest process-wide, and
//! a test elsewhere hitting the callsite first can hide it from this subscriber.

use std::fmt;
use std::sync::{Arc, Mutex};

use wslib_1password::testing::FakeRunner;
use wslib_1password::{Assignment, FieldType, ItemRef, Op, Output, VaultInfo};

#[derive(Clone, Default)]
struct Logged(Arc<Mutex<Vec<String>>>);

impl tracing::Subscriber for Logged {
    fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
        true
    }
    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }
    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
    fn event(&self, event: &tracing::Event<'_>) {
        let mut line = event.metadata().level().to_string();
        event.record(
            &mut |field: &tracing::field::Field, value: &dyn fmt::Debug| {
                line += &format!(" {field}={value:?}");
            },
        );
        self.0.lock().unwrap().push(line);
    }
    fn enter(&self, _: &tracing::span::Id) {}
    fn exit(&self, _: &tracing::span::Id) {}
}

#[test]
fn a_failure_logs_ops_stderr_at_warn_with_values_redacted() {
    let fake = FakeRunner::new();
    fake.respond(Output::fail("[ERROR] invalid value hunter2"));
    let logged = Logged::default();
    tracing::subscriber::with_default(logged.clone(), || {
        let edit = [Assignment::set("pw", FieldType::Password, "hunter2")];
        Op::new(fake.clone(), "ops")
            .vault(VaultInfo {
                id: "v1".into(),
                name: "Deploy".into(),
            })
            .edit_item(&ItemRef::title("CA"), &edit)
    })
    .unwrap_err();
    let lines = logged.0.lock().unwrap();
    assert_eq!(lines.len(), 1);
    assert!(lines[0].starts_with("WARN"), "{lines:?}");
    assert!(
        lines[0].contains(r#"stderr="[ERROR] invalid value <redacted>""#),
        "{lines:?}"
    );
    assert!(!lines[0].contains("hunter2"), "{lines:?}");
}
