//! What a person asked this appliance to do, kept past a restart, unlike the
//! in-memory [`log`](crate::log) ring.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// One audited event; a client pages with [`Page`](crate::Page)'s cursor, not an id.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts", ts(export))]
pub struct AuditRecord {
    pub at: DateTime<Utc>,

    /// The severity as the logging layer spelt it, `INFO`, `WARN` or `ERROR`,
    /// and any a later build adds.
    pub level: String,

    /// A username, or whatever the emitting event called the actor.
    pub actor: String,

    /// The permanent id of the account `actor` names, if it names one.
    pub actor_id: Option<String>,

    /// The emitting module, e.g. `myappliance_server::api::host`.
    pub target: String,

    pub message: String,

    /// The event's other non-empty fields, in the order they were emitted.
    pub fields: Vec<(String, String)>,
}
