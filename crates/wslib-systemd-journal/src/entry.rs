use std::fmt;
use std::str::FromStr;
use std::time::{Duration, SystemTime};

use serde_json::Value;

/// syslog's priority, from 0 (`Emergency`) to 7 (`Debug`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
#[repr(u8)]
pub enum Priority {
    Emergency,
    Alert,
    Critical,
    Error,
    Warning,
    Notice,
    Info,
    #[default]
    Debug,
}

impl Priority {
    const ALL: [Self; 8] = [
        Self::Emergency,
        Self::Alert,
        Self::Critical,
        Self::Error,
        Self::Warning,
        Self::Notice,
        Self::Info,
        Self::Debug,
    ];

    /// The priority with syslog's number, or `None` above 7.
    pub fn from_number(number: u8) -> Option<Self> {
        Self::ALL.get(usize::from(number)).copied()
    }

    /// syslog's number for it.
    pub fn number(self) -> u8 {
        self as u8
    }

    /// journalctl's short name for it: `emerg`, `alert`, `crit`, `err`,
    /// `warning`, `notice`, `info` or `debug`.
    pub fn name(self) -> &'static str {
        [
            "emerg", "alert", "crit", "err", "warning", "notice", "info", "debug",
        ][self as usize]
    }
}

impl FromStr for Priority {
    type Err = UnknownPriority;

    /// Reads [`Priority::name`]'s names, and nothing else.
    fn from_str(name: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|p| p.name() == name)
            .ok_or_else(|| UnknownPriority(name.to_owned()))
    }
}

/// A name [`Priority`]'s `FromStr` refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownPriority(pub String);

impl fmt::Display for UnknownPriority {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?} is not a journal priority", self.0)
    }
}

impl std::error::Error for UnknownPriority {}

#[cfg(feature = "serde")]
impl serde::Serialize for Priority {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.name())
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for Priority {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}

/// One journal entry.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Entry {
    pub at: SystemTime,
    /// `Info` when the entry has none.
    pub priority: Priority,
    /// `_SYSTEMD_UNIT`, or `UNIT` for systemd's messages about a unit.
    pub unit: Option<String>,
    pub identifier: Option<String>,
    pub pid: Option<u32>,
    /// Cut at a character boundary and ended with `…` past the query's message bound.
    pub message: String,
}

pub(crate) fn parse(out: &[u8], max_message: usize) -> Vec<Entry> {
    out.split(|&b| b == b'\n')
        .filter_map(|line| serde_json::from_slice::<Value>(line).ok())
        .filter_map(|fields| entry_from(&fields, max_message))
        .collect()
}

fn entry_from(fields: &Value, max_message: usize) -> Option<Entry> {
    let text = |name: &str| field(fields, name);
    let micros: u64 = text("__REALTIME_TIMESTAMP")?.parse().ok()?;
    let mut message = text("MESSAGE").unwrap_or_default();
    if message.len() > max_message {
        let cut = (0..=max_message)
            .rev()
            .find(|&i| message.is_char_boundary(i))
            .unwrap_or(0);
        message.truncate(cut);
        message.push('…');
    }
    Some(Entry {
        at: SystemTime::UNIX_EPOCH.checked_add(Duration::from_micros(micros))?,
        priority: text("PRIORITY")
            .and_then(|p| p.parse().ok())
            .and_then(Priority::from_number)
            .unwrap_or(Priority::Info),
        unit: text("_SYSTEMD_UNIT").or_else(|| text("UNIT")),
        identifier: text("SYSLOG_IDENTIFIER"),
        pid: text("_PID").and_then(|p| p.parse().ok()),
        message,
    })
}

/// journalctl writes a field that is not UTF-8 as an array of bytes, and one
/// repeated in an entry as an array of values; the first is kept.
fn field(fields: &Value, name: &str) -> Option<String> {
    match fields.get(name)? {
        Value::String(s) => Some(s.clone()),
        Value::Array(items) if items.iter().all(Value::is_u64) => {
            let bytes: Vec<u8> = items
                .iter()
                .filter_map(|b| b.as_u64().and_then(|b| u8::try_from(b).ok()))
                .collect();
            Some(String::from_utf8_lossy(&bytes).into_owned())
        }
        Value::Array(items) => items.first().and_then(Value::as_str).map(str::to_owned),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entries_are_read_whatever_shape_a_field_takes() {
        let out = br#"{"__REALTIME_TIMESTAMP":"1760100000000000","PRIORITY":"3","_SYSTEMD_UNIT":"widget.service","SYSLOG_IDENTIFIER":"widget","_PID":"412","MESSAGE":"could not reach the store"}
{"__REALTIME_TIMESTAMP":"1760100001000000","UNIT":"sshd@1.service","SYSLOG_IDENTIFIER":"systemd","MESSAGE":[104,105,255]}
{"__REALTIME_TIMESTAMP":"1760100002000000","MESSAGE":["first","second"],"PRIORITY":"9"}
not json
{"MESSAGE":"no time, so dropped"}
"#;
        let entries = parse(out, 4096);
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].priority, Priority::Error);
        assert_eq!(entries[0].pid, Some(412));
        assert_eq!(entries[0].unit.as_deref(), Some("widget.service"));
        assert_eq!(entries[0].identifier.as_deref(), Some("widget"));
        assert_eq!(
            entries[0].at,
            SystemTime::UNIX_EPOCH + Duration::from_secs(1_760_100_000)
        );
        assert_eq!(entries[1].unit.as_deref(), Some("sshd@1.service"));
        assert_eq!(entries[1].message, "hi\u{fffd}");
        assert_eq!(entries[1].priority, Priority::Info, "none is info");
        assert_eq!(entries[2].message, "first");
        assert_eq!(entries[2].priority, Priority::Info, "out of range is info");
    }

    #[test]
    fn a_long_message_is_cut_at_a_character_boundary() {
        let line = format!(
            r#"{{"__REALTIME_TIMESTAMP":"1","MESSAGE":"{}"}}"#,
            "é".repeat(10)
        );
        let entry = &parse(line.as_bytes(), 5)[0];
        assert_eq!(entry.message, "éé…");
    }

    #[test]
    fn priorities_round_trip_through_syslogs_numbers() {
        for number in 0..=7 {
            assert_eq!(Priority::from_number(number).unwrap().number(), number);
        }
        assert_eq!(Priority::from_number(8), None);
        assert!(Priority::Error < Priority::Warning);
    }

    #[test]
    fn priorities_are_read_by_journalctls_short_names_only() {
        for priority in Priority::ALL {
            assert_eq!(priority.name().parse(), Ok(priority));
        }
        assert_eq!(Priority::Critical.name(), "crit");
        for bad in ["3", "error", "ERR", ""] {
            assert_eq!(bad.parse::<Priority>(), Err(UnknownPriority(bad.into())));
        }
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serde_uses_the_short_names() {
        assert_eq!(
            serde_json::to_string(&Priority::Warning).unwrap(),
            r#""warning""#
        );
        assert_eq!(
            serde_json::from_str::<Priority>(r#""emerg""#).unwrap(),
            Priority::Emergency
        );
        assert!(serde_json::from_str::<Priority>("3").is_err());
        assert!(serde_json::from_str::<Priority>(r#""warn""#).is_err());
    }
}
