//! The live log feed's heartbeat. The log records themselves are
//! `wslib-telemetry`'s.

/// How often the live feed says `heartbeat` when it has nothing else to say.
pub const FEED_HEARTBEAT_S: u64 = 15;

/// `#[ts(export)]` writes only from the defining crate's tests, so these are
/// written here.
#[cfg(all(test, feature = "ts"))]
mod export {
    use ts_rs::TS;
    use wslib_telemetry::{LogLevel, LogRecord, LogSnapshot};

    #[test]
    fn export_bindings_log_records() {
        LogLevel::export_all().expect("LogLevel.ts");
        LogRecord::export_all().expect("LogRecord.ts");
        LogSnapshot::export_all().expect("LogSnapshot.ts");
    }
}
