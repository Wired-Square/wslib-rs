//! Alone in its binary: tracing caches a callsite's interest process-wide, and
//! a test elsewhere hitting the callsite first can hide it from this subscriber.

use std::fmt;
use std::sync::{Arc, Mutex};

use wslib_http_error::ApiError;

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
        let mut line = String::new();
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
fn a_cause_is_logged_without_its_url_credentials() {
    let logged = Logged::default();
    tracing::subscriber::with_default(logged.clone(), || {
        let cause = "error sending request for url (https://user:pass@host.invalid/hook)";
        ApiError::internal("notify", cause);
        ApiError::unavailable("notify", cause);
    });
    let lines = logged.0.lock().unwrap();
    assert_eq!(lines.len(), 2, "{lines:?}");
    for line in lines.iter() {
        assert!(
            line.contains("https://redacted@host.invalid/hook"),
            "{line}"
        );
        assert!(!line.contains("pass"), "{line}");
    }
}
