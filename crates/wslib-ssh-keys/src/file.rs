use std::fmt;
use std::io;
use std::path::Path;

use chrono::{DateTime, Utc};

use crate::{Fingerprint, Key};

/// Who added a key and when, kept as a `# added by <who> on <RFC 3339>` comment above it.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Provenance {
    pub by: String,
    pub at: Option<DateTime<Utc>>,
}

impl Provenance {
    pub fn new(by: impl Into<String>, at: Option<DateTime<Utc>>) -> Self {
        Self { by: by.into(), at }
    }

    fn parse(comment: &str) -> Option<Self> {
        let rest = comment.strip_prefix("added by ")?;
        // From the right: a name may hold " on " and an RFC 3339 stamp cannot.
        let stamped = rest.rsplit_once(" on ").and_then(|(by, at)| {
            let at = DateTime::parse_from_rfc3339(at.trim()).ok()?;
            Some(Self::new(by.trim(), Some(at.with_timezone(&Utc))))
        });
        Some(stamped.unwrap_or_else(|| Self::new(rest.trim(), None)))
    }
}

impl fmt::Display for Provenance {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let by: String = self
            .by
            .chars()
            .map(|c| if c.is_control() { ' ' } else { c })
            .collect();
        write!(f, "added by {by}")?;
        match self.at {
            Some(at) => write!(f, " on {}", at.to_rfc3339()),
            None => Ok(()),
        }
    }
}

/// A key and, when known, who added it.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Entry {
    pub key: Key,
    pub provenance: Option<Provenance>,
}

impl Entry {
    pub fn new(key: Key) -> Self {
        Self {
            key,
            provenance: None,
        }
    }

    pub fn with_provenance(mut self, provenance: Provenance) -> Self {
        self.provenance = Some(provenance);
        self
    }
}

impl From<Key> for Entry {
    fn from(key: Key) -> Self {
        Self::new(key)
    }
}

/// An `authorized_keys` file: its keys, and the lines that are not keys this crate reads.
///
/// Parsing keeps every key, and every other non-comment line verbatim, since
/// sshd may honour a line this crate refuses. Comments are dropped, except a
/// provenance comment directly above a key; writing puts the header first.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AuthorisedKeys {
    header: Option<String>,
    entries: Vec<Entry>,
    unparsed: Vec<String>,
}

impl AuthorisedKeys {
    pub fn parse(text: &str) -> Self {
        let mut file = Self::default();
        let mut provenance = None;
        for line in text.lines() {
            let trimmed = line.trim();
            if let Some(comment) = trimmed.strip_prefix('#') {
                provenance = Provenance::parse(comment.trim());
                continue;
            }
            let above = provenance.take();
            if trimmed.is_empty() {
                continue;
            }
            match Key::parse(trimmed) {
                Ok(key) => file.entries.push(Entry {
                    key,
                    provenance: above,
                }),
                Err(_) => file.unparsed.push(line.to_string()),
            }
        }
        file
    }

    /// The file at `path`; one that does not exist is empty.
    pub fn read(path: &Path) -> io::Result<Self> {
        match std::fs::read_to_string(path) {
            Ok(text) => Ok(Self::parse(&text)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(e),
        }
    }

    /// Replace the file whole, `0644`: sshd opens it as the account logging in.
    ///
    /// The caller serialises writers to one path, and keeps the directories
    /// above it as `StrictModes` requires.
    pub fn write(&self, path: &Path) -> io::Result<()> {
        wslib_file_atomic::replace_readable(path, self.to_string().as_bytes())
    }

    /// Comment lines written at the top, each prefixed `# `.
    pub fn with_header(mut self, header: impl Into<String>) -> Self {
        self.header = Some(header.into());
        self
    }

    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    /// Lines kept verbatim that are neither blank, a comment, nor a key this crate accepts.
    pub fn unparsed(&self) -> &[String] {
        &self.unparsed
    }

    pub fn get(&self, fingerprint: &Fingerprint) -> Option<&Entry> {
        self.entries
            .iter()
            .find(|e| e.key.fingerprint() == *fingerprint)
    }

    /// Append a key, or `false` when one with its fingerprint is already here.
    pub fn add(&mut self, entry: Entry) -> bool {
        let fresh = self.get(&entry.key.fingerprint()).is_none();
        if fresh {
            self.entries.push(entry);
        }
        fresh
    }

    pub fn remove(&mut self, fingerprint: &Fingerprint) -> Option<Entry> {
        let at = self
            .entries
            .iter()
            .position(|e| e.key.fingerprint() == *fingerprint)?;
        Some(self.entries.remove(at))
    }
}

impl fmt::Display for AuthorisedKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut first = true;
        for line in self.header.iter().flat_map(|h| h.lines()) {
            writeln!(f, "{}", format!("# {line}").trim_end())?;
            first = false;
        }
        for Entry { key, provenance } in &self.entries {
            if !std::mem::take(&mut first) {
                writeln!(f)?;
            }
            if let Some(provenance) = provenance {
                writeln!(f, "# {provenance}")?;
            }
            writeln!(f, "{key}")?;
        }
        self.unparsed
            .iter()
            .try_for_each(|line| writeln!(f, "{line}"))
    }
}
