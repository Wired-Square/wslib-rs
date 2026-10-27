//! Which crates the daemon's log ring captures, and the bridge that turns an
//! event named `audit` into a durable row. The ring holds this appliance's own
//! events only; nothing here reads the journal. Audit rows leave the logger
//! through a bounded tap [`write_audit_rows`] drains: the layer never touches
//! the store, and a full queue costs a counted row rather than a stalled logger.

use std::future::Future;
use std::path::Path;
use std::sync::atomic::Ordering;

use tracing_subscriber::Layer;
use tracing_subscriber::registry::LookupSpan;
use wslib_appliance_store::Store;
use wslib_appliance_types::AuditRecord;
use wslib_telemetry::log::TRUNCATED;
use wslib_telemetry::{LogRecord, LogsBuilder, Tap, Telemetry};

/// Every `wslib_appliance_*` crate, `wslib_db_sqlite`, `wslib_http_server` and
/// `wslib_tls`: an audit event from a target neither here nor in the product's
/// `crates` is dropped silently.
const FAMILY_CRATES: &[&str] = &[
    "wslib_appliance_*",
    "wslib_db_sqlite",
    "wslib_http_server",
    "wslib_tls",
];

/// How many audit rows may wait for the store before one is lost.
const AUDIT_QUEUE_DEPTH: usize = 64;

/// The event name that makes a line an audit row: declared, never inferred from
/// fields, so an account a fault mentions is never recorded as acting.
const AUDIT_NAME: &str = "audit";

const ACTOR_FIELD: &str = "actor";

const ACTOR_ID_FIELD: &str = "actor_id";

/// The daemon's log ring, capturing the family's crates and the product's
/// `crates`, spelt as `tracing` spells a target: `myappliance_server`.
pub fn logs(crates: &[&str]) -> Logs {
    Logs(ring(crates).build())
}

/// [`logs`], with the Logs screen naming `file` as where the rest went.
pub fn logs_writing_to(crates: &[&str], file: &Path) -> Logs {
    Logs(ring(crates).writing_to(file).build())
}

fn ring(crates: &[&str]) -> LogsBuilder {
    let captures = [FAMILY_CRATES, crates].concat();
    wslib_telemetry::Logs::builder(&captures).own_budget(&[ACTOR_FIELD, ACTOR_ID_FIELD])
}

/// The ring the audit rows and log screen read. Install one from [`logs`] with
/// [`feed`](Self::feed); one from `wslib_appliance_service::install_logs` is
/// installed already, and a `Telemetry` `init` after it panics.
#[derive(Clone, Debug)]
pub struct Logs(wslib_telemetry::Logs);

impl Logs {
    /// `telemetry`, filling this ring too: `logs.feed(Telemetry::new("info").journald()).init()`.
    pub fn feed(&self, telemetry: Telemetry) -> Telemetry {
        telemetry.with_ring(&self.0)
    }

    /// The layer that fills this ring, for a subscriber of the product's own.
    pub fn layer<S>(&self) -> impl Layer<S> + Send + Sync + 'static
    where
        S: tracing::Subscriber + for<'a> LookupSpan<'a>,
    {
        self.0.layer()
    }

    pub(crate) fn ring(&self) -> &wslib_telemetry::Logs {
        &self.0
    }
}

/// Write audit rows to the store until the queue is [closed](close_audit_queue)
/// and empty. The queue opens when this is called, not when the future first
/// runs; it ignores the shutdown token, since listeners answer through their grace period.
/// A failed write is logged and dropped: retrying an unanswering database is a loop.
pub(crate) fn write_audit_rows(
    logs: &wslib_telemetry::Logs,
    store: Store,
) -> impl Future<Output = ()> + Send + 'static {
    let tap = logs.tap(AUDIT_NAME, AUDIT_QUEUE_DEPTH);
    async move {
        let Some(Tap { mut rx, lost }) = tap else {
            tracing::error!("the audit bridge was started twice; the second is ignored");
            return;
        };
        let report_lost = || {
            let lost = lost.swap(0, Ordering::Relaxed);
            if lost > 0 {
                tracing::warn!(lost, "audit rows were lost: the queue was full");
            }
        };
        while let Some(record) = rx.recv().await {
            if let Some(row) = as_audit(&record) {
                crate::audit::write(&store, &row).await;
            }
            report_lost();
        }
        report_lost();
    }
}

/// Stop taking rows: the drain writes what is queued and returns, and a line
/// logged after this is no row.
pub fn close_audit_queue(logs: &Logs) {
    logs.0.close_tap(AUDIT_NAME);
}

/// The row an event named `audit` becomes, or `None` if it names no actor. An
/// `actor_id` that is empty or was truncated is no id, and stays a field.
fn as_audit(record: &LogRecord) -> Option<AuditRecord> {
    let field = |name: &str| {
        record
            .fields
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v)
    };
    let actor = field(ACTOR_FIELD)?;
    let actor_id = field(ACTOR_ID_FIELD).filter(|id| !id.is_empty() && !id.ends_with(TRUNCATED));
    Some(AuditRecord {
        at: record.at,
        level: record.level.as_str().to_string(),
        actor: actor.clone(),
        actor_id: actor_id.cloned(),
        target: record.target.clone(),
        message: record.message.clone(),
        fields: record
            .fields
            .iter()
            .filter(|(k, _)| k != ACTOR_FIELD && !(k == ACTOR_ID_FIELD && actor_id.is_some()))
            .cloned()
            .collect(),
    })
}

#[cfg(test)]
mod tests {
    use tracing::instrument::WithSubscriber;
    use wslib_telemetry::log::LOG_TEXT_MAX;

    use super::*;
    use crate::testing::captured;

    #[test]
    fn the_family_and_a_named_product_crate_are_captured_and_nothing_else() {
        let logs = logs(&["myappliance_core"]);
        captured(&logs, || {
            tracing::error!(target: "hyper::proto::h1", "connection closed");
            tracing::error!(target: "myappliance_corex::thing", "a crate whose name merely starts the same");
            tracing::info!(target: "myappliance_core::poller", "polled");
            tracing::info!(target: "wslib_appliance_server::serve", "the family's own");
            tracing::warn!(target: "wslib_db_sqlite::settings", "the store's database");
            tracing::info!(target: "wslib_http_server", "listening");
            tracing::info!(target: "wslib_http_server::redirect", "redirecting to https");
            tracing::warn!(target: "wslib_tls::serving", "the pair was replaced");
        });

        let snapshot = logs.ring().snapshot();
        let targets: Vec<_> = snapshot.records.iter().map(|r| r.target.as_str()).collect();
        assert_eq!(
            targets,
            [
                "myappliance_core::poller",
                "wslib_appliance_server::serve",
                "wslib_db_sqlite::settings",
                "wslib_http_server",
                "wslib_http_server::redirect",
                "wslib_tls::serving"
            ]
        );
    }

    fn audit_rows(emit: impl FnOnce()) -> Vec<AuditRecord> {
        let logs = logs(&[]);
        let mut tap = logs
            .ring()
            .tap(AUDIT_NAME, AUDIT_QUEUE_DEPTH)
            .expect("open");
        captured(&logs, emit);
        std::iter::from_fn(|| tap.rx.try_recv().ok())
            .filter_map(|record| as_audit(&record))
            .collect()
    }

    #[test]
    fn only_declared_events_become_audit_rows() {
        let rows = audit_rows(|| {
            tracing::warn!(name: "audit", actor = "mallory", "sign-in refused");
            tracing::info!(name: "audit", actor = "admin", username = "root", "authorised a key");
            tracing::warn!(name: "audit", "somebody did something");
            tracing::error!(actor = "mallory", "a stored password hash is unreadable");
            tracing::warn!(device = "bench", "poll failed");
        });

        let named: Vec<_> = rows
            .iter()
            .map(|r| (r.actor.as_str(), r.message.as_str(), r.level.as_str()))
            .collect();
        assert_eq!(
            named,
            [
                ("mallory", "sign-in refused", "WARN"),
                ("admin", "authorised a key", "INFO"),
            ]
        );
        assert_eq!(
            rows[1].fields,
            [("username".to_string(), "root".to_string())],
            "the actor field went; the other stays"
        );
    }

    #[test]
    fn an_actor_id_is_lifted_into_the_row_and_a_user_id_is_not() {
        let rows = audit_rows(|| {
            tracing::warn!(name: "audit", actor = "admin", actor_id = "an-id", what = "reset", "refused");
            tracing::warn!(name: "audit", actor = "admin", user_id = "an-id", "sign-in refused");
            tracing::warn!(name: "audit", actor = "admin", actor_id = 7, "refused");
        });

        assert_eq!(rows[0].actor_id.as_deref(), Some("an-id"));
        assert_eq!(
            rows[0].fields,
            [("what".to_string(), "reset".to_string())],
            "the actor_id is a column and is not repeated"
        );
        assert_eq!(rows[1].actor_id, None, "a user_id names the target");
        assert_eq!(
            rows[1].fields,
            [("user_id".to_string(), "an-id".to_string())]
        );
        assert_eq!(rows[2].actor_id.as_deref(), Some("7"));
    }

    #[test]
    fn an_actor_id_that_is_empty_or_truncated_stays_a_field_and_the_row_is_kept() {
        let long = "x".repeat(LOG_TEXT_MAX + 1);
        let rows = audit_rows(|| {
            tracing::warn!(name: "audit", actor = "admin", actor_id = "", "refused");
            tracing::warn!(name: "audit", actor = "admin", actor_id = %long, "refused");
        });

        assert_eq!(rows.len(), 2);
        for row in &rows {
            assert_eq!(row.actor, "admin");
            assert_eq!(row.actor_id, None);
            assert_eq!(row.fields[0].0, "actor_id", "{:?}", row.fields);
        }
        assert!(rows[1].fields[0].1.ends_with(TRUNCATED));
    }

    #[test]
    fn a_long_field_ahead_of_the_actor_does_not_spend_its_budget() {
        let rows = audit_rows(|| {
            tracing::warn!(
                name: "audit",
                note = %"n".repeat(LOG_TEXT_MAX),
                actor = "admin",
                actor_id = "an-id",
                "refused"
            );
        });

        assert_eq!(rows[0].actor, "admin");
        assert_eq!(rows[0].actor_id.as_deref(), Some("an-id"));
    }

    async fn ends<T>(drain: impl Future<Output = T>) -> T {
        tokio::time::timeout(std::time::Duration::from_secs(10), drain)
            .await
            .expect("the drain ends once its queue is closed")
    }

    async fn audited(store: &Store) -> Vec<String> {
        let page = store.audit(100, None).await.expect("read");
        page.items.into_iter().map(|row| row.actor).collect()
    }

    #[tokio::test]
    async fn the_drain_writes_queued_rows_and_finishes_them_once_the_queue_closes() {
        let store = Store::open_in_memory(None).await.expect("store");
        let logs = logs(&[]);
        let drain = tokio::spawn(write_audit_rows(logs.ring(), store.clone()));

        captured(&logs, || {
            tracing::warn!(name: "audit", actor = "mallory", "sign-in refused: no such account");
        });
        close_audit_queue(&logs);
        ends(drain).await.expect("the drain ran");

        let page = store.audit(10, None).await.expect("read");
        assert_eq!(page.items.len(), 1);
        assert_eq!(page.items[0].actor, "mallory");
        assert_eq!(page.items[0].level, "WARN");
        assert!(
            page.items[0]
                .target
                .starts_with("wslib_appliance_core::logs")
        );
    }

    #[tokio::test]
    async fn a_sign_in_the_auth_crate_refuses_is_an_audit_row() {
        let store = Store::open_in_memory(None).await.expect("store");
        let logs = logs(&[]);
        let drain = tokio::spawn(write_audit_rows(logs.ring(), store.clone()));

        let refused = wslib_appliance_auth::authenticate(&store, "mallory", "a guess")
            .with_subscriber(logs.ring().subscriber())
            .await;
        assert!(refused.is_err());
        close_audit_queue(&logs);
        ends(drain).await.expect("the drain ran");

        let page = store.audit(10, None).await.expect("read");
        assert_eq!(page.items.len(), 1);
        assert_eq!(page.items[0].actor, "mallory");
        assert!(page.items[0].target.starts_with("wslib_appliance_auth"));
    }

    #[tokio::test]
    async fn the_queue_opens_when_the_drain_is_called_not_when_it_first_runs() {
        let store = Store::open_in_memory(None).await.expect("store");
        let logs = logs(&[]);
        let drain = write_audit_rows(logs.ring(), store.clone());

        captured(&logs, || {
            tracing::warn!(name: "audit", actor = "early", "before the drain first ran");
        });
        close_audit_queue(&logs);
        ends(drain).await;

        assert_eq!(audited(&store).await, ["early"]);
    }

    #[tokio::test]
    async fn a_second_drain_is_refused_and_the_first_keeps_draining() {
        let store = Store::open_in_memory(None).await.expect("store");
        let logs = logs(&[]);
        let ring = logs.ring();
        let first = write_audit_rows(ring, store.clone());
        ends(write_audit_rows(ring, store.clone()).with_subscriber(ring.subscriber())).await;

        captured(&logs, || {
            tracing::warn!(name: "audit", actor = "admin", "did a thing");
        });
        close_audit_queue(&logs);
        ends(first).await;

        assert_eq!(audited(&store).await, ["admin"], "written once");
        assert!(
            ring.snapshot()
                .records
                .iter()
                .any(|r| r.message.contains("started twice")),
            "the second says why it did nothing"
        );
    }

    /// The count is the layer's, the warning the drain's: a warning from inside
    /// the layer would be captured by the layer emitting it.
    #[tokio::test]
    async fn a_full_queue_loses_rows_and_the_drain_reports_how_many() {
        let store = Store::open_in_memory(None).await.expect("store");
        let logs = logs(&[]);
        let ring = logs.ring();
        let drain = write_audit_rows(ring, store.clone());

        captured(&logs, || {
            for i in 0..AUDIT_QUEUE_DEPTH + 2 {
                tracing::warn!(name: "audit", actor = "admin", i, "did a thing");
            }
        });
        let before = ring.snapshot().records.len();
        close_audit_queue(&logs);
        ends(drain.with_subscriber(ring.subscriber())).await;

        assert_eq!(audited(&store).await.len(), AUDIT_QUEUE_DEPTH);
        let reported: Vec<_> = ring.snapshot().records[before..]
            .iter()
            .filter(|r| r.message.contains("were lost"))
            .map(|r| r.fields.clone())
            .collect();
        assert_eq!(
            reported,
            [vec![("lost".to_string(), "2".to_string())]],
            "reported once, by the drain"
        );
    }
}
