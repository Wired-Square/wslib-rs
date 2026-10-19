use std::ffi::OsStr;
use std::io::{self, IsTerminal};

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

/// The process's one subscriber: `RUST_LOG`, or the caller's default filter
/// when it is unset or does not parse, ahead of a formatter.
#[derive(Debug)]
#[must_use = "nothing is installed until `init`"]
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
    /// unless `RUST_LOG` says otherwise: the daemon style.
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

    /// Installs the subscriber as the global default.
    ///
    /// # Panics
    ///
    /// If a global subscriber is already installed.
    pub fn init(self) {
        self.try_init()
            .expect("a global subscriber is already installed");
    }

    /// [`init`](Self::init), failing rather than panicking when a global
    /// subscriber is already installed.
    pub fn try_init(self) -> Result<(), TryInitError> {
        let rust_log = std::env::var_os("RUST_LOG");
        let (filter, rejected) = choose_filter::<Filter>(&self.default_filter, rust_log.as_deref());

        let subscriber = tracing_subscriber::registry()
            .with(filter)
            .with(self.formatter());
        #[cfg(feature = "ring")]
        let subscriber = subscriber.with(self.ring.as_ref().map(|logs| logs.layer()));
        subscriber.try_init()?;

        if let Some((value, error)) = rejected {
            tracing::warn!(rust_log = %value, %error, "RUST_LOG did not parse; using the default filter");
        }
        Ok(())
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
    /// Skips the directives that do not parse.
    fn parse_lossy(directives: &str) -> Self;
    fn with_own_warnings(self) -> Self;
}

#[cfg(feature = "setup")]
impl Directives for EnvFilter {
    fn parse(directives: &str) -> Result<Self, String> {
        Self::try_new(directives).map_err(|e| e.to_string())
    }

    fn parse_lossy(directives: &str) -> Self {
        Self::builder().parse_lossy(directives)
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

    fn parse_lossy(directives: &str) -> Self {
        directives
            .split(',')
            .filter(|d| d.parse::<Self>().is_ok())
            .collect::<Vec<_>>()
            .join(",")
            .parse()
            .unwrap_or_default()
    }

    fn with_own_warnings(self) -> Self {
        self.with_target(env!("CARGO_CRATE_NAME"), tracing::Level::WARN)
    }
}

/// `RUST_LOG` when it is set and parses; otherwise the default, and what was
/// rejected with why, for a warning once there is a subscriber to take one.
fn choose_filter<F: Directives>(
    default: &str,
    rust_log: Option<&OsStr>,
) -> (F, Option<(String, String)>) {
    let Some(value) = rust_log.filter(|v| !v.is_empty()) else {
        return (F::parse_lossy(default), None);
    };
    let parsed = value
        .to_str()
        .ok_or_else(|| "not valid Unicode".to_string())
        .and_then(F::parse);
    match parsed {
        Ok(filter) => (filter, None),
        Err(error) => (
            // A default with no global level would otherwise drop the warning.
            F::parse_lossy(default).with_own_warnings(),
            Some((value.to_string_lossy().into_owned(), error)),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type Chosen = (String, Option<String>);

    fn chosen<F: Directives + std::fmt::Display>(rust_log: Option<&str>) -> Chosen {
        let (filter, rejected) = choose_filter::<F>("foo=info,warn", rust_log.map(OsStr::new));
        (filter.to_string(), rejected.map(|(value, _)| value))
    }

    fn each_filter() -> Vec<fn(Option<&str>) -> Chosen> {
        vec![
            #[cfg(feature = "setup")]
            chosen::<EnvFilter>,
            chosen::<Targets>,
        ]
    }

    #[test]
    fn rust_log_wins_when_it_parses() {
        for chosen in each_filter() {
            assert_eq!(chosen(Some("bar=debug")), ("bar=debug".into(), None));
        }
    }

    #[test]
    fn an_unset_or_empty_rust_log_is_the_default_without_a_warning() {
        for chosen in each_filter() {
            for rust_log in [None, Some("")] {
                let (filter, rejected) = chosen(rust_log);
                assert_eq!(rejected, None);
                assert!(filter.contains("foo=info"), "{filter}");
            }
        }
    }

    #[test]
    fn a_rust_log_that_does_not_parse_falls_back_and_says_what_it_was() {
        for chosen in each_filter() {
            let (filter, rejected) = chosen(Some("bar=loudest"));
            assert!(filter.contains("foo=info"), "{filter}");
            assert!(filter.contains("wslib_telemetry=warn"), "{filter}");
            assert_eq!(rejected.as_deref(), Some("bar=loudest"));
        }
    }

    #[test]
    fn a_default_that_partly_parses_keeps_what_does() {
        let filter = Targets::parse_lossy("foo=info,bar=loudest,warn");
        assert_eq!(filter.to_string(), "foo=info,warn");
    }

    #[test]
    fn colour_needs_a_terminal_and_no_no_color() {
        assert!(colour_by_default(true, None));
        assert!(colour_by_default(true, Some(OsStr::new(""))));
        assert!(!colour_by_default(true, Some(OsStr::new("1"))));
        assert!(!colour_by_default(false, None));
    }
}
