//! Reads the systemd journal through `journalctl --output=json`: a bounded
//! query, newest entry first, parsed into [`Entry`]s.
//!
//! ```no_run
//! use wslib_systemd_journal::{Priority, Query, Source};
//! # async fn run() -> Result<(), wslib_systemd_journal::Error> {
//! let excerpt = Query::default()
//!     .with_source(Source::Units(vec!["sshd.service".into()]))
//!     .with_priority(Priority::Warning)
//!     .with_lines(50)
//!     .read()
//!     .await?;
//! for entry in &excerpt.entries {
//!     println!("{:?} {}", entry.priority, entry.message);
//! }
//! # Ok(())
//! # }
//! ```
//!
//! `journalctl` is run directly, never through a shell, and every argument is
//! built from a typed field or a checked unit name, so a query cannot name a
//! file, a command or another machine's journal.

mod entry;

use std::fmt;
use std::io;
use std::path::PathBuf;
use std::process::{ExitStatus, Stdio};
use std::time::Duration;

use tokio::io::AsyncReadExt;
use tokio::process::Command;

pub use entry::{Entry, Priority};

/// Whose entries a query reads.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum Source {
    #[default]
    All,
    /// The kernel's ring buffer, this boot only (`--dmesg`).
    Kernel,
    /// Any of these units; a name may hold journalctl's `*`, `?` and `[]` globs.
    Units(Vec<String>),
}

/// How far back a query reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum Since {
    #[default]
    Boot,
    /// This long before now, to the second.
    Ago(Duration),
}

/// A bounded read of the journal; the defaults are this boot, every priority,
/// 200 entries, 10 s and 8 MiB of output.
#[derive(Debug, Clone)]
pub struct Query {
    program: PathBuf,
    source: Source,
    priority: Priority,
    since: Since,
    lines: u32,
    timeout: Duration,
    max_output: u64,
    max_message: usize,
}

impl Default for Query {
    fn default() -> Self {
        Self {
            program: Self::PROGRAM.into(),
            source: Source::All,
            priority: Priority::Debug,
            since: Since::Boot,
            lines: 200,
            timeout: Duration::from_secs(10),
            max_output: 8 << 20,
            max_message: 4096,
        }
    }
}

/// What a query read, newest first.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Excerpt {
    pub entries: Vec<Entry>,
    /// The journal held more than the line or output bound let through.
    pub truncated: bool,
}

impl Query {
    pub const PROGRAM: &str = "/usr/bin/journalctl";

    /// Runs `program` in place of [`Query::PROGRAM`].
    pub fn with_program(mut self, program: impl Into<PathBuf>) -> Self {
        self.program = program.into();
        self
    }

    pub fn with_source(mut self, source: Source) -> Self {
        self.source = source;
        self
    }

    /// Entries at `priority` or more urgent.
    pub fn with_priority(mut self, priority: Priority) -> Self {
        self.priority = priority;
        self
    }

    pub fn with_since(mut self, since: Since) -> Self {
        self.since = since;
        self
    }

    /// At most `lines` entries; 0 is refused when the query runs.
    pub fn with_lines(mut self, lines: u32) -> Self {
        self.lines = lines;
        self
    }

    /// How long journalctl has to answer before it is killed.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// How many bytes of journalctl's output are read before it is killed.
    pub fn with_max_output(mut self, bytes: u64) -> Self {
        self.max_output = bytes;
        self
    }

    /// How many bytes of an entry's message are kept.
    pub fn with_max_message(mut self, bytes: usize) -> Self {
        self.max_message = bytes;
        self
    }

    pub async fn read(&self) -> Result<Excerpt, Error> {
        let args = self.args()?;
        let mut child = Command::new(&self.program)
            .args(&args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .map_err(|e| match e.kind() {
                io::ErrorKind::NotFound => Error::NotInstalled,
                _ => Error::Io(e),
            })?;
        let stdout = child.stdout.take().expect("piped");
        let mut out = Vec::new();
        let finished = async {
            stdout
                .take(self.max_output)
                .read_to_end(&mut out)
                .await
                .map_err(Error::Io)?;
            // Cut at the bound, journalctl is killed, and its status says nothing.
            if out.len() as u64 == self.max_output {
                return Ok(true);
            }
            match child.wait().await.map_err(Error::Io)? {
                status if status.success() => Ok(false),
                status => Err(Error::Exited(status)),
            }
        };
        let cut = tokio::time::timeout(self.timeout, finished)
            .await
            .map_err(|_| Error::Timeout)??;
        let mut entries = entry::parse(&out, self.max_message);
        let over = entries.len() > self.lines as usize;
        entries.truncate(self.lines as usize);
        Ok(Excerpt {
            entries,
            truncated: cut || over,
        })
    }

    fn args(&self) -> Result<Vec<String>, Error> {
        if self.lines == 0 {
            return Err(Error::Lines);
        }
        let mut args: Vec<String> = [
            "--output=json",
            "--output-fields=MESSAGE,PRIORITY,_SYSTEMD_UNIT,UNIT,SYSLOG_IDENTIFIER,_PID",
            "--no-pager",
            "--quiet",
            "--reverse",
        ]
        .map(String::from)
        .into();
        // One more than wanted, so that a journal holding more is told from one that doesn't.
        args.push(format!("--lines={}", self.lines.saturating_add(1)));
        args.push(format!("--priority={}", self.priority.number()));
        args.push(match self.since {
            Since::Boot => "--boot".into(),
            Since::Ago(ago) => format!("--since=-{}s", ago.as_secs()),
        });
        match &self.source {
            Source::All => {}
            Source::Kernel => args.push("--dmesg".into()),
            Source::Units(units) => {
                for unit in units {
                    if !is_unit_pattern(unit) {
                        return Err(Error::Unit(unit.clone()));
                    }
                    args.push(format!("--unit={unit}"));
                }
            }
        }
        Ok(args)
    }
}

/// systemd's unit name characters, its 255-byte limit, and journalctl's globs.
fn is_unit_pattern(unit: &str) -> bool {
    (1..=255).contains(&unit.len())
        && unit
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b":-_.\\@*?[]".contains(&b))
}

/// Why a query failed.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// Nothing at the program's path.
    NotInstalled,
    Io(io::Error),
    Exited(ExitStatus),
    Timeout,
    /// A line bound of 0.
    Lines,
    /// A unit name with a character no unit name or glob has.
    Unit(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotInstalled => f.write_str("journalctl is not installed"),
            Self::Io(e) => write!(f, "could not run journalctl: {e}"),
            Self::Exited(status) => write!(f, "journalctl failed: {status}"),
            Self::Timeout => f.write_str("journalctl did not answer in time"),
            Self::Lines => f.write_str("a query must allow at least one line"),
            Self::Unit(unit) => write!(f, "{unit:?} is not a unit name"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn has(args: &[String], wanted: &str) -> bool {
        args.iter().any(|a| a == wanted)
    }

    #[test]
    fn the_defaults_are_this_boot_at_every_priority_two_hundred_newest_first() {
        let args = Query::default().args().unwrap();
        for wanted in ["--reverse", "--lines=201", "--priority=7", "--boot"] {
            assert!(has(&args, wanted), "{wanted} missing from {args:?}");
        }
        assert!(!args.iter().any(|a| a.starts_with("--unit")));
    }

    #[test]
    fn each_setting_becomes_one_fixed_argument() {
        let args = Query::default()
            .with_source(Source::Units(vec![
                "sshd@*.service".into(),
                "sshd.socket".into(),
            ]))
            .with_priority(Priority::Warning)
            .with_since(Since::Ago(Duration::from_secs(86_400)))
            .with_lines(5)
            .args()
            .unwrap();
        for wanted in [
            "--lines=6",
            "--priority=4",
            "--since=-86400s",
            "--unit=sshd@*.service",
            "--unit=sshd.socket",
        ] {
            assert!(has(&args, wanted), "{wanted} missing from {args:?}");
        }
        assert!(!has(&args, "--boot"));
        let kernel = Query::default().with_source(Source::Kernel).args().unwrap();
        assert!(has(&kernel, "--dmesg"));
    }

    #[test]
    fn a_bad_query_is_refused_before_journalctl_runs() {
        assert!(matches!(
            Query::default().with_lines(0).args(),
            Err(Error::Lines)
        ));
        for bad in [
            "",
            "../etc/shadow",
            "a b.service",
            "x\n--file=/etc",
            &"a".repeat(256),
        ] {
            let units = Source::Units(vec!["sshd.service".into(), bad.into()]);
            assert!(
                matches!(Query::default().with_source(units).args(), Err(Error::Unit(u)) if u == bad),
                "{bad:?}"
            );
        }
    }
}
