//! One `tracing` setup for daemons and command lines, and an in-memory ring of
//! a service's own log for a browser to read.
//!
//! ```no_run
//! # #[cfg(feature = "setup")]
//! wslib_telemetry::Telemetry::new("myapp=info,warn").init();
//! ```
//!
//! Features: `setup` (the default, with `ansi`) is [`Telemetry`]; `json` and
//! `journald` add its other outputs. `types` is the ring's records alone, with
//! serde and chrono and no `tracing`; `ring` adds the ring itself, `ts` their
//! TypeScript, and `test-support` a subscriber of nothing but a ring.

#[cfg(feature = "journald")]
mod journald;
#[cfg(feature = "types")]
pub mod log;
#[cfg(feature = "ring")]
mod redact;
#[cfg(feature = "ring")]
mod ring;
#[cfg(feature = "setup")]
mod setup;

#[cfg(feature = "types")]
pub use log::{LogLevel, LogRecord, LogSnapshot};
#[cfg(feature = "ring")]
pub use redact::{strip_userinfo, truncate};
#[cfg(feature = "ring")]
pub use ring::{Logs, LogsBuilder, Tap};
#[cfg(feature = "setup")]
pub use setup::Telemetry;
#[cfg(feature = "setup")]
pub use tracing_subscriber::util::TryInitError;
