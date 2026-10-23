//! A service's own log, captured in memory so a browser can read it, and the
//! taps that hand events of a declared name to a drain of the caller's.
//!
//! A [`tracing_subscriber::Layer`] beside the formatter, feeding a bounded ring,
//! a broadcast feed and any open taps, from the targets its maker names and no
//! others.
//!
//! # Two rules this file keeps
//!
//! **`on_event` never emits a `tracing` event and never touches a store.** It
//! runs inside the logger, on whatever thread emitted; an event emitted here
//! would be captured here, which is recursion rather than a slow path, and a
//! write from here would block that thread on the store and log its own
//! failure back into this ring. A tap is a bounded queue drained on the
//! runtime, and a queue that is full costs a counted record rather than a
//! stalled logger.
//!
//! **`std::sync::Mutex`, never tokio's.** `on_event` is synchronous. No lock
//! is held past a push and a pop, a `try_send`, or a snapshot's clone of the
//! ring's handles, and a poisoned one is recovered: a lost log line is not a
//! reason to take the daemon down.

use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use chrono::{DateTime, SubsecRound, Utc};
use tokio::sync::{broadcast, mpsc};
use tracing::field::{Field, Visit};
use tracing_log::NormalizeEvent;
use tracing_subscriber::layer::Context;
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::{Layer, filter};

use crate::log::{LOG_RING, LOG_TEXT_MAX, LogLevel, LogRecord, LogSnapshot, TRUNCATED};
use crate::redact::{is_secret, strip_userinfo, truncate};

/// How many records a slow feed client may fall behind before the oldest it
/// has not read is skipped.
const FEED_DEPTH: usize = 512;

/// The captured log: a bounded ring, a feed of what is arriving, and the taps.
///
/// Cloning shares one buffer. Made once at the top of `main`, before the
/// subscriber, and handed to whatever serves it.
#[derive(Clone)]
pub struct Logs(Arc<Inner>);

struct Inner {
    started: Instant,
    captures: Vec<String>,
    own_budget: Vec<String>,
    redact: Vec<String>,
    file: Option<String>,
    ring: Mutex<VecDeque<Arc<LogRecord>>>,
    feed: broadcast::Sender<Arc<LogRecord>>,
    taps: Mutex<HashMap<String, Tapped>>,
}

struct Tapped {
    tx: mpsc::Sender<Arc<LogRecord>>,
    lost: Arc<AtomicU64>,
}

/// The receiving end of [`Logs::tap`].
pub struct Tap {
    /// The tapped records, oldest first; it ends once the tap is closed.
    pub rx: mpsc::Receiver<Arc<LogRecord>>,
    /// Records the queue had no room for. The logger only adds to it; the
    /// drain swaps it to zero and reports it, from outside the logger.
    pub lost: Arc<AtomicU64>,
}

/// How a [`Logs`] is made, from [`Logs::builder`].
#[derive(Debug, Default)]
pub struct LogsBuilder {
    captures: Vec<String>,
    own_budget: Vec<String>,
    redact: Vec<String>,
    file: Option<String>,
}

fn owned(names: &[&str]) -> Vec<String> {
    names.iter().map(|name| (*name).to_string()).collect()
}

impl LogsBuilder {
    /// Names the file the rest of the log goes to, which
    /// [`LogSnapshot::log_file`] reports.
    pub fn writing_to(mut self, file: &Path) -> Self {
        self.file = Some(file.display().to_string());
        self
    }

    /// Gives each of these fields a [`LOG_TEXT_MAX`] budget of its own, so the
    /// fields ahead of it cannot crowd it out.
    pub fn own_budget(mut self, fields: &[&str]) -> Self {
        self.own_budget.extend(owned(fields));
        self
    }

    /// Redacts fields with these exact names too, besides the built-in
    /// credential names.
    pub fn redact(mut self, fields: &[&str]) -> Self {
        self.redact.extend(owned(fields));
        self
    }

    /// The ring, empty, its uptime counted from now.
    pub fn build(self) -> Logs {
        Logs(Arc::new(Inner {
            started: Instant::now(),
            captures: self.captures,
            own_budget: self.own_budget,
            redact: self.redact,
            file: self.file,
            ring: Mutex::new(VecDeque::with_capacity(LOG_RING)),
            feed: broadcast::Sender::new(FEED_DEPTH),
            taps: Mutex::new(HashMap::new()),
        }))
    }
}

impl Logs {
    /// A ring capturing `captures` and nothing else.
    ///
    /// Each is a crate or module as `tracing` spells a target, `myapp_server`,
    /// matching it and its submodules; one ending `*` matches every target
    /// that starts with the rest, `myapp_*`.
    ///
    /// **Only those.** `hyper` at `trace` logs request headers, `Cookie:`
    /// included; `sqlx` logs statements. The *level* is still the
    /// subscriber's filter to choose, ahead of every layer, so
    /// `RUST_LOG=myapp_core=debug` fills the ring and `RUST_LOG=hyper=trace`
    /// fills the output alone.
    pub fn new(captures: &[&str]) -> Self {
        Self::builder(captures).build()
    }

    /// [`new`](Self::new), with the options of [`LogsBuilder`].
    pub fn builder(captures: &[&str]) -> LogsBuilder {
        LogsBuilder {
            captures: owned(captures),
            ..LogsBuilder::default()
        }
    }

    /// The layer that fills this ring, for a subscriber.
    ///
    /// Filtered per callsite, so an event from a target not captured never
    /// reaches this layer at all rather than being inspected and dropped.
    pub fn layer<S>(&self) -> impl Layer<S> + Send + Sync + 'static
    where
        S: tracing::Subscriber + for<'a> LookupSpan<'a>,
    {
        let logs = self.clone();
        CaptureLayer(self.clone())
            .with_filter(filter::filter_fn(move |meta| logs.captures(meta.target())))
    }

    /// A subscriber of nothing but this ring, for a test that wants what a
    /// closure or a future says captured and nothing else.
    #[cfg(any(test, feature = "test-support"))]
    pub fn subscriber(&self) -> impl tracing::Subscriber + Send + Sync {
        use tracing_subscriber::layer::SubscriberExt;

        // With one dispatcher alive, tracing caches a callsite's interest from
        // whichever thread hits it first, so a parallel test with none would
        // silence it here; a second, permanent one makes it ask them all.
        static ANOTHER: std::sync::LazyLock<tracing::Dispatch> = std::sync::LazyLock::new(|| {
            tracing::Dispatch::new(tracing::subscriber::NoSubscriber::default())
        });
        std::sync::LazyLock::force(&ANOTHER);
        tracing_subscriber::registry().with(self.layer())
    }

    /// Every record from now on, as it is captured.
    pub fn subscribe(&self) -> broadcast::Receiver<Arc<LogRecord>> {
        self.0.feed.subscribe()
    }

    /// Since the ring was made.
    pub fn uptime(&self) -> Duration {
        self.0.started.elapsed()
    }

    /// `now − uptime`, to the second — never a stamp taken at start, which on a
    /// box that boots in 1970 and jumps when NTP lands would stay 1970.
    pub fn started_at(&self) -> DateTime<Utc> {
        (Utc::now() - chrono::Duration::from_std(self.uptime()).unwrap_or_default())
            .trunc_subsecs(0)
    }

    /// Everything held, oldest first, sharing the ring's records rather than
    /// copying them.
    pub fn snapshot(&self) -> LogSnapshot {
        LogSnapshot {
            started_at: self.started_at(),
            records: self.lock().iter().map(Arc::clone).collect(),
            log_file: self.0.file.clone(),
        }
    }

    /// Opens a queue of up to `depth` captured records whose event is named
    /// `name`, as in `tracing::warn!(name: "audit", …)`; `None` if a tap of
    /// that name is already open.
    ///
    /// The queue opens at the call, not when the drain first polls, so a
    /// record emitted in between is queued. A record that finds it full is
    /// dropped and counted in [`Tap::lost`].
    pub fn tap(&self, name: &str, depth: usize) -> Option<Tap> {
        let mut taps = self.taps();
        if taps.contains_key(name) {
            return None;
        }
        let (tx, rx) = mpsc::channel(depth.max(1));
        let lost = Arc::new(AtomicU64::new(0));
        let lost_too = Arc::clone(&lost);
        taps.insert(name.to_string(), Tapped { tx, lost: lost_too });
        Some(Tap { rx, lost })
    }

    /// Drops the tap's sender: its drain receives what is queued, then ends.
    /// A record emitted after this is not tapped.
    pub fn close_tap(&self, name: &str) {
        self.taps().remove(name);
    }

    fn captures(&self, target: &str) -> bool {
        self.0
            .captures
            .iter()
            .any(|name| match name.strip_suffix('*') {
                Some(prefix) => target.starts_with(prefix),
                None => target
                    .strip_prefix(name.as_str())
                    .is_some_and(|rest| rest.is_empty() || rest.starts_with("::")),
            })
    }

    /// Poisoning means another thread panicked mid-push and the `VecDeque` is
    /// still sound; a log line is not worth the daemon.
    fn lock(&self) -> MutexGuard<'_, VecDeque<Arc<LogRecord>>> {
        self.0.ring.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn taps(&self) -> MutexGuard<'_, HashMap<String, Tapped>> {
        self.0.taps.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// `Arc`, so the ring, the feed and a tap share one copy rather than
    /// cloning two `String`s and a `Vec` under the lock for a copy nobody may
    /// be watching.
    fn push(&self, mut record: LogRecord, name: &str) {
        let record = {
            let mut ring = self.lock();
            record.seq = ring.back().map_or(0, |last| last.seq) + 1;
            let record = Arc::new(record);
            if ring.len() >= LOG_RING {
                ring.pop_front();
            }
            ring.push_back(Arc::clone(&record));
            record
        };

        // Err is nobody watching, which is the ordinary case.
        let _ = self.0.feed.send(Arc::clone(&record));

        if let Some(tap) = self.taps().get(name)
            && tap.tx.try_send(record).is_err()
        {
            tap.lost.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// Counts the ring rather than printing it: a derived `Debug` would put a
/// thousand lines into any log line that formats the state.
impl fmt::Debug for Logs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Logs")
            .field("records", &self.lock().len())
            .finish()
    }
}

struct CaptureLayer(Logs);

impl<S: tracing::Subscriber> Layer<S> for CaptureLayer {
    fn on_event(&self, event: &tracing::Event<'_>, _: Context<'_, S>) {
        let normalised = event.normalized_metadata();
        let meta = normalised.as_ref().unwrap_or_else(|| event.metadata());
        let mut visitor = Capture::new(&self.0.0, normalised.is_some());
        event.record(&mut visitor);

        let record = LogRecord {
            seq: 0,
            at: Utc::now().trunc_subsecs(6),
            level: level_of(meta.level()),
            target: meta.target().to_string(),
            message: visitor.message,
            fields: visitor.fields,
        };
        self.0.push(record, meta.name());
    }
}

fn level_of(level: &tracing::Level) -> LogLevel {
    match *level {
        tracing::Level::TRACE => LogLevel::Trace,
        tracing::Level::DEBUG => LogLevel::Debug,
        tracing::Level::INFO => LogLevel::Info,
        tracing::Level::WARN => LogLevel::Warn,
        tracing::Level::ERROR => LogLevel::Error,
    }
}

/// Renders an event's fields, redacting by name and truncating by budget.
///
/// The message has a budget of its own, so a verbose field cannot starve the
/// sentence somebody wrote.
struct Capture<'a> {
    logs: &'a Inner,
    message: String,
    fields: Vec<(String, String)>,
    spent: usize,
    from_log: bool,
}

impl<'a> Capture<'a> {
    fn new(logs: &'a Inner, from_log: bool) -> Self {
        Self {
            logs,
            message: String::new(),
            fields: Vec::new(),
            spent: 0,
            from_log,
        }
    }

    /// The budget is decided *before* the value is formatted: a secret is
    /// replaced by a constant and a field past the budget is dropped, and
    /// neither pays for a `format!` whose output is thrown away.
    ///
    /// The event's own sentence is the *first* `message` visited — the macro
    /// declares its own ahead of the author's fields — so a field an author
    /// happened to call `message` stays a field. A control character is
    /// escaped rather than kept — a name carrying a newline would otherwise
    /// forge a line wherever the ring is rendered as text.
    fn record(&mut self, field: &Field, value: impl FnOnce() -> String) {
        let name = field.name();
        if self.from_log && name.starts_with("log.") {
            return;
        }
        let is_message = name == "message" && self.message.is_empty();
        let own_budget = is_message || self.logs.own_budget.iter().any(|f| f == name);
        let budget = if own_budget {
            LOG_TEXT_MAX
        } else {
            LOG_TEXT_MAX.saturating_sub(self.spent)
        };
        if budget == 0 {
            return;
        }
        let value = if is_secret(name) || self.logs.redact.iter().any(|f| f == name) {
            "[redacted]".to_string()
        } else {
            truncate(escape_control(without_userinfo(value())), budget, TRUNCATED)
        };
        if is_message {
            self.message = value;
        } else {
            self.spent += value.len();
            self.fields.push((name.to_string(), value));
        }
    }
}

/// Before truncation, so a cut cannot leave half a credential behind the
/// marker; before escaping, so an escaped newline still ends the authority.
fn without_userinfo(value: String) -> String {
    if value.contains("://") {
        strip_userinfo(&value)
    } else {
        value
    }
}

fn escape_control(value: String) -> String {
    if !value.chars().any(char::is_control) {
        return value;
    }
    let mut out = String::with_capacity(value.len() + 8);
    for c in value.chars() {
        if c.is_control() {
            out.extend(c.escape_default());
        } else {
            out.push(c);
        }
    }
    out
}

impl Visit for Capture<'_> {
    /// `%x`, `?x` and the message all arrive here, which is why redaction has
    /// only the field's name to go on.
    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        self.record(field, || format!("{value:?}"));
    }

    /// Without this a `&str` field forwards to `record_debug` and every string
    /// on the screen carries quotes.
    fn record_str(&mut self, field: &Field, value: &str) {
        self.record(field, || value.to_string());
    }
}

#[cfg(test)]
mod tests;
