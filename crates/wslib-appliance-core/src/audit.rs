//! The durable audit record. Call [`audit!`](crate::audit!), not [`record`]; a failed
//! write is logged at `ERROR` and does not fail the request, whose change usually stands.

use wslib_appliance_types::AuditRecord;

use crate::state::ApplianceState;

/// Record one event under the caller's `module_path!()`: `audit!(&app, &who, "msg", "k" => v)`.
#[macro_export]
macro_rules! audit {
    ($app:expr, $who:expr, $message:expr $(, $key:expr => $value:expr)* $(,)?) => {
        $crate::__audit($app, $who, module_path!(), $message, &[$(($key, $value)),*])
    };
}

/// Who [`audit!`](crate::audit!) records as having done something.
pub trait Actor {
    fn actor(&self) -> &str;

    /// The permanent id of the account behind it, when there is one.
    fn actor_id(&self) -> Option<&str> {
        None
    }
}

/// Machinery behind [`audit!`](crate::audit!), exported only as `__audit`.
pub async fn record(
    app: &ApplianceState,
    who: &(impl Actor + ?Sized),
    target: &str,
    message: impl Into<String>,
    fields: &[(&str, &str)],
) {
    let record = AuditRecord {
        at: wslib_appliance_store::now(),
        level: "INFO".to_string(),
        actor: who.actor().to_string(),
        actor_id: who.actor_id().map(str::to_string),
        target: target.to_string(),
        message: message.into(),
        fields: fields
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect(),
    };
    write(&app.store, &record).await;
}

/// Append one row; if the store refuses it, the log line carries the record instead.
pub(crate) async fn write(store: &wslib_appliance_store::Store, record: &AuditRecord) {
    if let Err(e) = store.record_audit(record).await {
        tracing::error!(
            error = %crate::redact::foreign(&e),
            actor = %record.actor,
            recorded = %record.message,
            "could not write an audit record; what it records stands"
        );
    }
}
