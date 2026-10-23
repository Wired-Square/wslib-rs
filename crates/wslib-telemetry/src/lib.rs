//! One `tracing` setup for daemons and command lines, and an in-memory ring of
//! a service's own log for a browser to read.
//!
//! ```no_run
//! # #[cfg(feature = "setup-core")]
//! wslib_telemetry::Telemetry::new("myapp=info,warn").init();
//! ```
//!
//! A `RUST_LOG` that parses replaces the default filter rather than adding to it.
//!
//! Features: `setup` (the default, with `ansi`) is [`Telemetry`]; `json` and
//! `journald` add its other outputs. `setup-core` is [`Telemetry`] filtering by
//! target and level only, without `tracing-subscriber`'s regex engine. `types`
//! is the ring's records alone, with serde and chrono and no `tracing`; `ring`
//! adds the ring itself, `ts` their TypeScript, and `test-support` a subscriber
//! of nothing but a ring. [`foreign_error`], [`strip_userinfo`] and [`truncate`]
//! need no feature.

#[cfg(feature = "journald")]
mod journald;
#[cfg(feature = "types")]
pub mod log;
mod redact;
#[cfg(feature = "ring")]
mod ring;
#[cfg(feature = "setup-core")]
mod setup;

#[cfg(feature = "types")]
pub use log::{LogLevel, LogRecord, LogSnapshot};
pub use redact::{foreign_error, strip_userinfo, truncate};
#[cfg(feature = "ring")]
pub use ring::{Logs, LogsBuilder, Tap};
#[cfg(feature = "setup-core")]
pub use setup::Telemetry;
#[cfg(feature = "setup-core")]
pub use tracing_subscriber::util::TryInitError;
