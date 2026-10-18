//! What the daemon has said since it started, as the Logs screen reads it.
//!
//! The ring is in memory and starts empty on every start; nothing here is
//! durable.
//!
//! **Ordered by `seq`, never by `at`.** A box with no real-time clock boots in
//! 1970 and its clock jumps when NTP lands, so a list sorted by timestamp
//! shuffles the lines either side of the jump. `seq` is also what a client
//! reconciles a snapshot against its live feed on.

use std::sync::Arc;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// How many records the ring holds.
///
/// With [`LOG_TEXT_MAX`] bounding each record's message and its fields
/// separately, a full ring is about 4 MiB, which is the stated ceiling in
/// place of a byte accountant. A browser holding the list trims it to the same
/// length, so a tab left open all week does not grow past what the daemon
/// itself keeps.
pub const LOG_RING: usize = 1000;

/// The most bytes one record's message may carry, and separately its fields
/// together — an `actor` counted on its own, so an audit line always keeps
/// it. Past it, the text is cut on a character boundary and ends
/// `… [truncated]`.
pub const LOG_TEXT_MAX: usize = 2048;

/// What a message or field cut at [`LOG_TEXT_MAX`] ends with.
pub const TRUNCATED: &str = "… [truncated]";

/// How loud one captured event was, quietest first.
///
/// Ordered so "at least a warning" is `>=`, which is how a client filters:
/// one rank table, not a set per level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(rename_all = "lowercase")]
#[cfg_attr(feature = "ts", ts(export))]
pub enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

impl LogLevel {
    /// Every level, quietest first. Position is rank, and the browser's copy
    /// is generated from this so a filter there cannot hold a different order.
    pub const LADDER: [Self; 5] = [
        Self::Trace,
        Self::Debug,
        Self::Info,
        Self::Warn,
        Self::Error,
    ];

    /// The level as the logging layer spells it — `WARN`, not `warn` — which
    /// is the form an audit row's `level` carries.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Trace => "TRACE",
            Self::Debug => "DEBUG",
            Self::Info => "INFO",
            Self::Warn => "WARN",
            Self::Error => "ERROR",
        }
    }
}

/// One captured event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts", ts(export))]
pub struct LogRecord {
    /// Monotonic within one run of the daemon, from 1. The order of the list
    /// and the key a client deduplicates on — see the module doc.
    #[cfg_attr(feature = "ts", ts(type = "number"))]
    pub seq: u64,

    pub at: DateTime<Utc>,

    pub level: LogLevel,

    /// The emitting module, e.g. `myappliance_server::api::host`.
    pub target: String,

    pub message: String,

    /// The event's structured fields, rendered, in the order they were written.
    /// A field whose name says it holds a credential reads `[redacted]`.
    pub fields: Vec<(String, String)>,
}

/// The ring's contents, for seeding a Logs screen when its feed opens.
///
/// `seq` is contiguous from 1, so the newest record's less the count held is
/// what the ring has evicted — a screen says so rather than omitting quietly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts", ts(export))]
pub struct LogSnapshot {
    /// When this run of the daemon began capturing. Everything before it went
    /// to the daemon's own log (`log_file` where one is named, the system
    /// journal on an appliance) and is not here, and `seq` restarts with it.
    /// `now − uptime`, so a record captured before NTP landed is stamped
    /// before it.
    pub started_at: DateTime<Utc>,

    /// Oldest first. Shared with the ring that holds them, so answering a
    /// thousand of them copies none.
    pub records: Vec<Arc<LogRecord>>,

    /// The file `install_logs` writes a local backend's whole log to; `None`
    /// on an appliance, whose log is the system journal, and for a service
    /// whose subscriber is its own.
    pub log_file: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_level_is_a_lowercase_word_on_the_wire_and_ranks_quietest_first() {
        assert_eq!(serde_json::to_string(&LogLevel::Warn).unwrap(), "\"warn\"");
        assert!(
            LogLevel::Error >= LogLevel::Warn,
            "'at least a warning' is >="
        );
        assert!(
            LogLevel::LADDER.windows(2).all(|pair| pair[0] < pair[1]),
            "the ladder is the derived order, so the browser's rank table is too"
        );
    }
}
