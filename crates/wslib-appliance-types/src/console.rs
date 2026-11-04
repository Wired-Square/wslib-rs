//! Who a console says is calling, as the one header a proxied app reads from it.
//!
//! The value is `v1; id=…; user=…; role=…`, with `; reauth=<unix seconds>` when
//! the account last proved its password. `id` and `user` are percent-encoded
//! UTF-8: every byte outside `A-Za-z0-9-._~` is `%XX`. The keys come once each,
//! in any order after `v1`; anything else is malformed.

use std::fmt;
use std::str::FromStr;

use chrono::{DateTime, TimeDelta, Utc};

use crate::{Role, unreserved};

/// The header a console asserts the caller in.
pub const IDENTITY_HEADER: &str = "appliance-identity";

/// The longest `id` or `user`, in bytes once decoded.
const MAX_FIELD: usize = 256;

/// The caller a console vouches for on one request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsoleIdentity {
    /// The console's permanent id for the account.
    pub id: String,
    pub username: String,
    pub role: Role,
    /// Written to the second, a fraction dropped; a time before 1970 is not
    /// written, so it reads back as none and fails closed.
    pub reauthenticated_at: Option<DateTime<Utc>>,
}

/// Why a header value is not a [`ConsoleIdentity`]; never names the value.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("the Appliance-Identity header is malformed: {0}")]
pub struct MalformedIdentity(&'static str);

impl MalformedIdentity {
    /// For a refusal of the header made outside its grammar; `why` must not
    /// quote the value.
    #[doc(hidden)]
    pub fn because(why: &'static str) -> Self {
        Self(why)
    }
}

impl ConsoleIdentity {
    /// Whether the account proved its password no longer than `window` before `now`, and not after it.
    pub fn reauthenticated_within(&self, window: TimeDelta, now: DateTime<Utc>) -> bool {
        self.reauthenticated_at.is_some_and(|at| {
            let age = now - at;
            age >= TimeDelta::zero() && age <= window
        })
    }
}

impl fmt::Display for ConsoleIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "v1; id={}; user={}; role={}",
            Encoded(&self.id),
            Encoded(&self.username),
            self.role
        )?;
        match self.reauthenticated_at.map(|at| at.timestamp()) {
            Some(seconds) if seconds >= 0 => write!(f, "; reauth={seconds}"),
            _ => Ok(()),
        }
    }
}

impl FromStr for ConsoleIdentity {
    type Err = MalformedIdentity;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let mut parts = value.split(';').map(|part| part.trim_matches([' ', '\t']));
        if parts.next() != Some("v1") {
            return Err(MalformedIdentity("not version v1"));
        }
        let (mut id, mut username, mut role, mut reauth) = (None, None, None, None);
        for part in parts {
            let (key, raw) = part
                .split_once('=')
                .ok_or(MalformedIdentity("a part has no value"))?;
            let slot = match key {
                "id" => &mut id,
                "user" => &mut username,
                "role" => &mut role,
                "reauth" => &mut reauth,
                _ => return Err(MalformedIdentity("an unknown key")),
            };
            if slot.replace(raw).is_some() {
                return Err(MalformedIdentity("a repeated key"));
            }
        }
        let reauthenticated_at = reauth.map(seconds).transpose()?;
        Ok(Self {
            id: decoded(id.ok_or(MalformedIdentity("no id"))?)?,
            username: decoded(username.ok_or(MalformedIdentity("no user"))?)?,
            role: role
                .ok_or(MalformedIdentity("no role"))?
                .parse()
                .map_err(|_| MalformedIdentity("an unknown role"))?,
            reauthenticated_at,
        })
    }
}

fn seconds(raw: &str) -> Result<DateTime<Utc>, MalformedIdentity> {
    raw.bytes()
        .all(|b| b.is_ascii_digit())
        .then(|| raw.parse().ok())
        .flatten()
        .and_then(|seconds| DateTime::from_timestamp(seconds, 0))
        .ok_or(MalformedIdentity("reauth is not a time in unix seconds"))
}

struct Encoded<'a>(&'a str);

impl fmt::Display for Encoded<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0.bytes() {
            match unreserved(byte) {
                true => write!(f, "{}", byte as char)?,
                false => write!(f, "%{byte:02X}")?,
            }
        }
        Ok(())
    }
}

/// A non-empty field of at most [`MAX_FIELD`] bytes, with no control, format,
/// line or paragraph separator character and no whitespace at either end.
fn decoded(raw: &str) -> Result<String, MalformedIdentity> {
    const BAD: MalformedIdentity = MalformedIdentity("a field is not percent-encoded UTF-8");
    let mut bytes = Vec::with_capacity(raw.len());
    let mut rest = raw.as_bytes();
    while let Some((&byte, after)) = rest.split_first() {
        rest = after;
        if unreserved(byte) {
            bytes.push(byte);
            continue;
        }
        let hex = rest
            .get(..2)
            .filter(|hex| byte == b'%' && hex.iter().all(u8::is_ascii_hexdigit))
            .ok_or(BAD)?;
        let hex = std::str::from_utf8(hex).map_err(|_| BAD)?;
        bytes.push(u8::from_str_radix(hex, 16).map_err(|_| BAD)?);
        rest = &rest[2..];
    }
    let field = String::from_utf8(bytes).map_err(|_| BAD)?;
    if field.is_empty() || field.len() > MAX_FIELD {
        return Err(MalformedIdentity("a field is empty or too long"));
    }
    if field
        .chars()
        .any(|c| c.is_control() || format_or_line_break(c))
        || field.trim() != field
    {
        return Err(MalformedIdentity(
            "a field holds a control, format, line or paragraph separator character, or \
             edge whitespace",
        ));
    }
    Ok(field)
}

/// Unicode's Cf (format: bidi controls, zero-width characters), Zl and Zp.
fn format_or_line_break(c: char) -> bool {
    matches!(
        c,
        '\u{AD}'
            | '\u{600}'..='\u{605}'
            | '\u{61C}'
            | '\u{6DD}'
            | '\u{70F}'
            | '\u{890}'..='\u{891}'
            | '\u{8E2}'
            | '\u{180E}'
            | '\u{200B}'..='\u{200F}'
            | '\u{2028}'..='\u{202E}'
            | '\u{2060}'..='\u{2064}'
            | '\u{2066}'..='\u{206F}'
            | '\u{FEFF}'
            | '\u{FFF9}'..='\u{FFFB}'
            | '\u{110BD}'
            | '\u{110CD}'
            | '\u{13430}'..='\u{1343F}'
            | '\u{1BCA0}'..='\u{1BCA3}'
            | '\u{1D173}'..='\u{1D17A}'
            | '\u{E0001}'
            | '\u{E0020}'..='\u{E007F}'
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity() -> ConsoleIdentity {
        ConsoleIdentity {
            id: "4f1c-9a".to_string(),
            username: "Zoë O'Brien; admin=yes".to_string(),
            role: Role::Operator,
            reauthenticated_at: DateTime::from_timestamp(1_760_000_000, 0),
        }
    }

    #[test]
    fn a_written_identity_reads_back_as_itself() {
        let written = identity().to_string();
        assert_eq!(
            written,
            "v1; id=4f1c-9a; user=Zo%C3%AB%20O%27Brien%3B%20admin%3Dyes; role=operator; \
             reauth=1760000000"
        );
        assert_eq!(written.parse(), Ok(identity()));
        let without = ConsoleIdentity {
            reauthenticated_at: None,
            ..identity()
        };
        assert_eq!(without.to_string().parse(), Ok(without));
    }

    #[test]
    fn the_keys_may_come_in_any_order_and_spacing() {
        let read: ConsoleIdentity = "v1;role=admin ;\tuser=a;id=b".parse().unwrap();
        assert_eq!((read.id.as_str(), read.username.as_str()), ("b", "a"));
        assert_eq!(read.role, Role::Admin);
    }

    #[test]
    fn anything_else_is_malformed_and_the_refusal_never_repeats_it() {
        for value in [
            "",
            "v1",
            "v2; id=a; user=a; role=admin",
            "id=a; user=a; role=admin",
            "v1; id=a; user=a",
            "v1; id=a; role=admin",
            "v1; user=a; role=admin",
            "v1; id=a; user=a; role=root",
            "v1; id=a; user=a; role=Admin",
            "v1; id=a; id=b; user=a; role=admin",
            "v1; id=a; user=a; role=admin; extra=1",
            "v1; id=a; user=a; role=admin; reauth",
            "v1; id=a; user=a; role=admin; reauth=-5",
            "v1; id=a; user=a; role=admin; reauth=1.5",
            "v1; id=a; user=a; role=admin; reauth=99999999999999999999",
            "v1; id=a; user=a; role=admin; reauth=9223372036854775807",
            "v1; id=; user=a; role=admin",
            "v1; id=a b; user=a; role=admin",
            "v1; id=%4; user=a; role=admin",
            "v1; id=%zz; user=a; role=admin",
            "v1; id=%FF; user=a; role=admin",
            "v1; id=%0A; user=a; role=admin",
            "v1; id=%C3%; user=a; role=admin",
            "v1; id=é; user=a; role=admin",
            "v1; id=a; user=ad%E2%80%AEnim; role=admin",
            "v1; id=a; user=ad%E2%80%8Bmin; role=admin",
            "v1; id=a; user=ad%C2%ADmin; role=admin",
            "v1; id=a; user=a%E2%80%A8b; role=admin",
            "v1; id=a; user=a%E2%80%A9b; role=admin",
            "v1; id=%EF%BB%BFa; user=a; role=admin",
            "v1; id=a; user=%20admin; role=admin",
            "v1; id=a; user=admin%C2%A0; role=admin",
            "v1; id=a%E3%80%80; user=a; role=admin",
            &format!("v1; id={}; user=a; role=admin", "a".repeat(MAX_FIELD + 1)),
        ] {
            let refused = value.parse::<ConsoleIdentity>().unwrap_err().to_string();
            assert!(!refused.contains(['=', '%', ';']), "{value:?}: {refused}");
        }
    }

    #[test]
    fn a_reauth_before_1970_is_not_written_and_reads_back_as_none() {
        let early = ConsoleIdentity {
            reauthenticated_at: DateTime::from_timestamp(-1, 0),
            ..identity()
        };
        let written = early.to_string();
        assert!(!written.contains("reauth"), "{written}");
        let read: ConsoleIdentity = written.parse().unwrap();
        assert_eq!(read.reauthenticated_at, None);
        assert_eq!(read.to_string(), written);
    }

    #[test]
    fn the_reauthentication_window_is_recent_and_never_in_the_future() {
        let at = identity().reauthenticated_at.unwrap();
        let window = TimeDelta::minutes(5);
        let within = |now| identity().reauthenticated_within(window, now);
        assert!(within(at));
        assert!(within(at + window));
        assert!(!within(at + window + TimeDelta::seconds(1)));
        assert!(!within(at - TimeDelta::seconds(1)));
        let never = ConsoleIdentity {
            reauthenticated_at: None,
            ..identity()
        };
        assert!(!never.reauthenticated_within(window, at));
    }

    #[test]
    fn a_name_with_inner_spaces_and_accents_is_kept() {
        let read: ConsoleIdentity = "v1; id=a; user=Zo%C3%AB%20O%27Brien; role=viewer"
            .parse()
            .unwrap();
        assert_eq!(read.username, "Zoë O'Brien");
    }

    #[test]
    fn a_field_at_the_cap_is_kept() {
        let id = "a".repeat(MAX_FIELD);
        let read: ConsoleIdentity = format!("v1; id={id}; user=a; role=viewer").parse().unwrap();
        assert_eq!(read.id, id);
    }
}
