use std::borrow::Cow;
use std::ffi::OsStr;
use std::io::{self, IsTerminal};

use tracing::subscriber::DefaultGuard;

#[cfg(feature = "setup")]
use tracing_subscriber::EnvFilter;
#[cfg(any(test, not(feature = "setup")))]
use tracing_subscriber::filter::Targets;
use tracing_subscriber::fmt::writer::BoxMakeWriter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::util::{SubscriberInitExt, TryInitError};
use tracing_subscriber::{Layer, fmt};

#[cfg(feature = "ring")]
use crate::Logs;

/// The process's subscriber, or a thread's: `RUST_LOG`, or the caller's default
/// filter when it is unset or does not parse, ahead of a formatter.
#[derive(Debug)]
#[must_use = "nothing is installed until `init` or `set_default`"]
pub struct Telemetry {
    default_filter: String,
    output: Output,
    #[cfg(feature = "json")]
    json: bool,
    time: bool,
    target: bool,
    ansi: Option<bool>,
    #[cfg(feature = "ring")]
    ring: Option<Logs>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Output {
    Stdout,
    Stderr,
    #[cfg(feature = "journald")]
    Journald,
}

impl Telemetry {
    /// Text to stdout, with time and target, filtered by `default_filter`
    /// unless `RUST_LOG` says otherwise: the daemon style. A `RUST_LOG` that
    /// parses replaces `default_filter` rather than adding to it.
    pub fn new(default_filter: &str) -> Self {
        Self {
            default_filter: default_filter.to_string(),
            output: Output::Stdout,
            #[cfg(feature = "json")]
            json: false,
            time: true,
            target: true,
            ansi: None,
            #[cfg(feature = "ring")]
            ring: None,
        }
    }

    /// Text to stderr without time or target: the command-line style.
    pub fn cli(default_filter: &str) -> Self {
        Self::new(default_filter)
            .stderr()
            .without_time()
            .without_target()
    }

    /// Writes to stderr instead of stdout.
    pub fn stderr(mut self) -> Self {
        self.output = Output::Stderr;
        self
    }

    /// One JSON object per line.
    #[cfg(feature = "json")]
    pub fn json(mut self) -> Self {
        self.json = true;
        self
    }

    /// Leaves the timestamp off each line.
    pub fn without_time(mut self) -> Self {
        self.time = false;
        self
    }

    /// Leaves the emitting module off each line.
    pub fn without_target(mut self) -> Self {
        self.target = false;
        self
    }

    /// Overrides the colour default, which is on only when the output is a
    /// terminal and `NO_COLOR` is unset or empty. Always off without the
    /// `ansi` feature.
    pub fn ansi(mut self, ansi: bool) -> Self {
        self.ansi = Some(ansi);
        self
    }

    /// Stdout with each line at its event's journal priority when stdout is a
    /// journal stream, and without time or colour whatever else is set:
    /// journald stamps every line it receives and stores escape codes
    /// literally.
    #[cfg(feature = "journald")]
    pub fn journald(mut self) -> Self {
        self.output = Output::Journald;
        self
    }

    /// Feeds `logs` too, behind the same filter.
    #[cfg(feature = "ring")]
    pub fn with_ring(mut self, logs: &Logs) -> Self {
        self.ring = Some(logs.clone());
        self
    }

    /// Installs the subscriber as the global default, and the `log` bridge.
    ///
    /// # Panics
    ///
    /// If a global subscriber or a `log` logger is already installed.
    pub fn init(self) {
        self.try_init()
            .expect("a global subscriber or log logger is already installed");
    }

    /// [`init`](Self::init), failing rather than panicking when a global
    /// subscriber or a `log` logger is already installed.
    pub fn try_init(self) -> Result<(), TryInitError> {
        let (subscriber, rejected) = self.subscriber();
        subscriber.try_init()?;
        rejected.warn();
        Ok(())
    }

    /// Installs the subscriber for this thread until the guard drops, leaving
    /// the global default and the `log` bridge alone.
    pub fn set_default(self) -> DefaultGuard {
        let (subscriber, rejected) = self.subscriber();
        // Not `SubscriberInitExt::set_default`, which installs the `log` bridge
        // whenever another crate turns on `tracing-log`.
        let guard = tracing::subscriber::set_default(subscriber);
        rejected.warn();
        guard
    }

    fn subscriber(self) -> (impl tracing::Subscriber + Send + Sync, Rejected) {
        let rust_log = std::env::var_os("RUST_LOG");
        let (filter, rejected) = choose_filter::<Filter>(&self.default_filter, rust_log.as_deref());

        let subscriber = tracing_subscriber::registry()
            .with(filter)
            .with(self.formatter());
        #[cfg(feature = "ring")]
        let subscriber = subscriber.with(self.ring.as_ref().map(|logs| logs.layer().boxed()));
        (subscriber, rejected)
    }

    fn formatter<S>(&self) -> Box<dyn Layer<S> + Send + Sync>
    where
        S: tracing::Subscriber + for<'a> LookupSpan<'a>,
    {
        let (writer, journald) = match self.output {
            Output::Stdout => (BoxMakeWriter::new(io::stdout), false),
            Output::Stderr => (BoxMakeWriter::new(io::stderr), false),
            #[cfg(feature = "journald")]
            Output::Journald => (BoxMakeWriter::new(crate::journald::stdout()), true),
        };
        let ansi = cfg!(feature = "ansi")
            && !journald
            && self.ansi.unwrap_or_else(|| {
                let terminal = match self.output {
                    Output::Stderr => io::stderr().is_terminal(),
                    _ => io::stdout().is_terminal(),
                };
                colour_by_default(terminal, std::env::var_os("NO_COLOR").as_deref())
            });
        let time = self.time && !journald;
        let layer = fmt::layer()
            .with_writer(writer)
            .with_ansi(ansi)
            .with_target(self.target);

        #[cfg(feature = "json")]
        if self.json {
            let layer = layer.json();
            return if time {
                layer.boxed()
            } else {
                layer.without_time().boxed()
            };
        }
        if time {
            layer.boxed()
        } else {
            layer.without_time().boxed()
        }
    }
}

fn colour_by_default(terminal: bool, no_color: Option<&OsStr>) -> bool {
    terminal && no_color.is_none_or(OsStr::is_empty)
}

#[cfg(feature = "setup")]
type Filter = EnvFilter;
#[cfg(not(feature = "setup"))]
type Filter = Targets;

trait Directives: Sized {
    fn parse(directives: &str) -> Result<Self, String>;
    fn with_own_warnings(self) -> Self;
}

#[cfg(feature = "setup")]
impl Directives for EnvFilter {
    fn parse(directives: &str) -> Result<Self, String> {
        Self::try_new(directives).map_err(|e| e.to_string())
    }

    fn with_own_warnings(self) -> Self {
        self.add_directive(
            concat!(env!("CARGO_CRATE_NAME"), "=warn")
                .parse()
                .expect("a valid directive"),
        )
    }
}

#[cfg(any(test, not(feature = "setup")))]
impl Directives for Targets {
    fn parse(directives: &str) -> Result<Self, String> {
        directives.parse::<Self>().map_err(|e| e.to_string())
    }

    fn with_own_warnings(self) -> Self {
        self.with_target(env!("CARGO_CRATE_NAME"), tracing::Level::WARN)
    }
}

/// Bare, tracing reads `warning` as a target at `trace`, which logs nothing.
fn warning_as_warn(directive: &str) -> Cow<'_, str> {
    match directive.rsplit_once('=') {
        Some((target, level)) if level.eq_ignore_ascii_case("warning") => {
            format!("{target}=warn").into()
        }
        None if directive.eq_ignore_ascii_case("warning") => "warn".into(),
        _ => directive.into(),
    }
}

fn directives(filter: &str) -> impl Iterator<Item = Cow<'_, str>> {
    filter
        .split(',')
        .map(str::trim)
        .filter(|d| !d.is_empty())
        .map(warning_as_warn)
}

fn parse<F: Directives>(filter: &str) -> Result<F, String> {
    let directives: Vec<_> = directives(filter).collect();
    if directives.is_empty() {
        return Err("it has no directives".into());
    }
    F::parse(&directives.join(","))
}

/// The directives that parse, or `info` when none does.
fn parse_lossy<F: Directives>(filter: &str) -> F {
    let parseable: Vec<_> = directives(filter).filter(|d| F::parse(d).is_ok()).collect();
    let directives = if parseable.is_empty() {
        "info".into()
    } else {
        parseable.join(",")
    };
    parse(&directives).expect("directives that each parse")
}

/// The filters that did not parse, and why.
#[derive(Default)]
struct Rejected {
    default: Option<(String, String)>,
    rust_log: Option<(String, String)>,
}

impl Rejected {
    fn warn(self) {
        if let Some((value, error)) = self.rust_log {
            tracing::warn!(rust_log = %value, %error, "RUST_LOG did not parse; using the default filter");
        }
        if let Some((value, error)) = self.default {
            tracing::warn!(default_filter = %value, %error, "the default filter did not parse; using what of it does");
        }
    }
}

/// `RUST_LOG` when it has directives and they parse; otherwise the default, or
/// what of it parses. What was rejected is kept for a warning once there is a
/// subscriber to take one.
fn choose_filter<F: Directives>(default: &str, rust_log: Option<&OsStr>) -> (F, Rejected) {
    let mut rejected = Rejected::default();
    let has_directives = |v: &&OsStr| v.to_str().is_none_or(|v| directives(v).next().is_some());
    if let Some(value) = rust_log.filter(has_directives) {
        let parsed = value
            .to_str()
            .ok_or_else(|| "not valid Unicode".to_string())
            .and_then(parse);
        match parsed {
            Ok(filter) => return (filter, rejected),
            Err(error) => rejected.rust_log = Some((value.to_string_lossy().into_owned(), error)),
        }
    }
    let filter = parse(default).unwrap_or_else(|error| {
        rejected.default = Some((default.to_string(), error));
        parse_lossy(default)
    });
    if rejected.default.is_none() && rejected.rust_log.is_none() {
        return (filter, rejected);
    }
    // A default with no global level would otherwise drop the warning.
    (filter.with_own_warnings(), rejected)
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEFAULT: &str = "foo=info,warn";

    type Chosen = (String, Vec<String>);

    fn chosen<F: Directives + std::fmt::Display>(default: &str, rust_log: Option<&str>) -> Chosen {
        let (filter, rejected) = choose_filter::<F>(default, rust_log.map(OsStr::new));
        let rejected = [rejected.default, rejected.rust_log].into_iter().flatten();
        (
            filter.to_string(),
            rejected.map(|(value, _)| value).collect(),
        )
    }

    fn sorted(filter: &str) -> Vec<&str> {
        let mut directives: Vec<_> = filter.split(',').collect();
        directives.sort();
        directives
    }

    fn each_filter() -> Vec<fn(&str, Option<&str>) -> Chosen> {
        vec![
            #[cfg(feature = "setup")]
            chosen::<EnvFilter>,
            chosen::<Targets>,
        ]
    }

    #[test]
    fn rust_log_wins_when_it_parses() {
        for chosen in each_filter() {
            assert_eq!(
                chosen(DEFAULT, Some("bar=debug")),
                ("bar=debug".into(), vec![])
            );
        }
    }

    #[test]
    fn an_unset_or_empty_rust_log_is_the_default_without_a_warning() {
        for chosen in each_filter() {
            for rust_log in [None, Some(""), Some(" , ")] {
                let (filter, rejected) = chosen(DEFAULT, rust_log);
                assert!(rejected.is_empty());
                assert!(filter.contains("foo=info"), "{filter}");
            }
        }
    }

    #[test]
    fn a_rust_log_that_does_not_parse_falls_back_and_says_what_it_was() {
        for chosen in each_filter() {
            let (filter, rejected) = chosen(DEFAULT, Some("bar=loudest"));
            assert!(filter.contains("foo=info"), "{filter}");
            assert!(filter.contains("wslib_telemetry=warn"), "{filter}");
            assert_eq!(rejected, ["bar=loudest"]);
        }
    }

    #[test]
    fn a_default_filter_that_does_not_parse_is_warned_about() {
        for chosen in each_filter() {
            let (filter, rejected) = chosen("foo=loudest,warn", None);
            assert!(filter.contains("wslib_telemetry=warn"), "{filter}");
            assert_eq!(rejected, ["foo=loudest,warn"]);
        }
    }

    #[test]
    fn warning_in_any_case_is_warn() {
        for chosen in each_filter() {
            assert_eq!(chosen("WARNING", None), ("warn".into(), vec![]));
            assert_eq!(chosen("foo=Warning", None), ("foo=warn".into(), vec![]));
        }
    }

    #[test]
    fn empty_directives_are_skipped() {
        for chosen in each_filter() {
            let (filter, rejected) = chosen("foo=info, ,warn,", None);
            assert_eq!(
                (sorted(&filter), rejected),
                (vec!["foo=info", "warn"], vec![])
            );
            assert_eq!(
                chosen(DEFAULT, Some("bar=debug,")),
                ("bar=debug".into(), vec![])
            );
        }
    }

    #[test]
    fn an_empty_default_is_info_with_a_warning() {
        for chosen in each_filter() {
            for default in ["", " ", ","] {
                let (filter, rejected) = chosen(default, None);
                assert_eq!(
                    (sorted(&filter), rejected),
                    (
                        vec!["info", "wslib_telemetry=warn"],
                        vec![default.to_string()]
                    )
                );
            }
        }
    }

    #[test]
    fn a_default_that_partly_parses_keeps_what_does() {
        for chosen in each_filter() {
            let (filter, _) = chosen("foo=info,bar=loudest,warn", None);
            assert!(filter.contains("foo=info"), "{filter}");
            assert!(filter.split(',').any(|d| d == "warn"), "{filter}");
            assert!(!filter.contains("bar"), "{filter}");
        }
    }

    #[test]
    fn a_default_of_which_nothing_parses_is_info() {
        for chosen in each_filter() {
            let (filter, _) = chosen("foo=loudest", None);
            assert!(filter.split(',').any(|d| d == "info"), "{filter}");
        }
    }

    #[test]
    fn colour_needs_a_terminal_and_no_no_color() {
        assert!(colour_by_default(true, None));
        assert!(colour_by_default(true, Some(OsStr::new(""))));
        assert!(!colour_by_default(true, Some(OsStr::new("1"))));
        assert!(!colour_by_default(false, None));
    }
}
