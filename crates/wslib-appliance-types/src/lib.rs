//! The wire contract: types shared by the daemon, the browser and any other
//! client of an appliance, both what a client reads and the request bodies it
//! sends. Serde only. A request body carrying a `Secret` has no `PartialEq` and derives both serde
//! halves; an integer wider than 32 bits is `#[ts(type = "number")]`.
//!
//! With `ts`, every type a browser reads or sends derives `ts_rs::TS`, and a
//! test run writes each, and `constants.ts`, into `TS_RS_EXPORT_DIR`.

use std::fmt;
use std::str::FromStr;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

pub mod about;
pub mod account;
pub mod audit;
pub mod backup;
pub mod branding;
pub mod console;
pub mod hooks;
pub mod host;
pub mod log;
pub mod manifest;
pub mod passkey;
pub mod pending;
pub mod session;
pub mod tls;
pub mod totp;
pub mod trust;

pub use about::AboutView;
pub use audit::AuditRecord;
pub use branding::Branding;
pub use trust::{TrustedCa, TrustedCert};

/// The shortest password an appliance accepts; there is no composition rule.
pub const MIN_PASSWORD_LEN: usize = 12;

/// The longest password an appliance accepts, in bytes of UTF-8.
pub const MAX_PASSWORD_BYTES: usize = 1024;

/// The longest a username may be.
pub const MAX_USERNAME_LEN: usize = 64;

/// How a 403 for a password not confirmed recently begins, which a screen
/// behind a console answers by sending the caller there to re-authenticate.
pub const STALE_PROOF: &str = "this needs the password confirmed";

/// The longest an app's name may be, in bytes.
pub const MAX_APP_LEN: usize = 64;

/// Whether `name` may name an app: one path segment, at most [`MAX_APP_LEN`] bytes.
pub fn is_app_name(name: &str) -> bool {
    name.len() <= MAX_APP_LEN && is_segment(name)
}

/// Letters, digits, `-`, `.`, `_` and `~`, not `.` or `..`: no escaping needed in a URL or a path.
pub(crate) fn is_segment(segment: &str) -> bool {
    !segment.is_empty() && segment != "." && segment != ".." && segment.bytes().all(unreserved)
}

pub(crate) fn unreserved(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"-._~".contains(&byte)
}

/// The most audit records one page may carry; a server caps `limit` at it.
pub const MAX_AUDIT_PAGE: u32 = 500;

/// Who is asking, as a ladder: a requirement is "at least", by declaration order.
/// Operator is a Viewer who can acknowledge, configuration is Admin's, and
/// HostAdmin administers the box as well, which the control socket never reaches.
// Not `#[non_exhaustive]`: a new rung must break every consumer's `match`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(rename_all = "lowercase")]
#[cfg_attr(feature = "ts", ts(export))]
pub enum Role {
    Viewer,
    Operator,
    Admin,
    HostAdmin,
}

impl Role {
    /// Every role, lowest first. Position is rank.
    pub const LADDER: [Role; 4] = [Role::Viewer, Role::Operator, Role::Admin, Role::HostAdmin];

    /// Whether this role satisfies a requirement for `needed`.
    pub fn allows(self, needed: Role) -> bool {
        self >= needed
    }

    /// The lowercase slug, matching the serde representation.
    pub fn as_str(self) -> &'static str {
        match self {
            Role::Viewer => "viewer",
            Role::Operator => "operator",
            Role::Admin => "admin",
            Role::HostAdmin => "hostadmin",
        }
    }
}

impl fmt::Display for Role {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A stored role no build knows how to read.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("unknown role: {0:?}")]
pub struct UnknownRole(pub String);

/// The inverse of [`Role::as_str`].
impl FromStr for Role {
    type Err = UnknownRole;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Role::LADDER
            .into_iter()
            .find(|role| role.as_str() == s)
            .ok_or_else(|| UnknownRole(s.to_string()))
    }
}

/// Whether an optional subsystem is usable here, through what, or why not.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(tag = "state", rename_all = "snake_case")]
#[cfg_attr(feature = "ts", ts(export))]
pub enum Availability {
    /// Present and usable, through `via`.
    Ready { via: String },
    /// Not usable here, for a reason an operator can read.
    Unsupported { because: String },
}

impl Availability {
    pub fn ready(via: impl Into<String>) -> Self {
        Availability::Ready { via: via.into() }
    }

    pub fn unsupported(because: impl Into<String>) -> Self {
        Availability::Unsupported {
            because: because.into(),
        }
    }

    pub fn is_ready(&self) -> bool {
        matches!(self, Availability::Ready { .. })
    }

    /// The reason this is unavailable, if it is.
    pub fn because(&self) -> Option<&str> {
        match self {
            Availability::Unsupported { because } => Some(because),
            Availability::Ready { .. } => None,
        }
    }
}

/// The body every `ApiError` response carries, unless the request names
/// `text/html`. A code refused because the box's clock and the browser's
/// disagree carries a [`ClockSkew`](totp::ClockSkew) in `extra["clock_skew"]`.
pub use wslib_http_error::ApiErrorBody;

#[cfg(all(test, feature = "ts"))]
#[test]
fn the_error_body_and_the_clock_skew_it_carries_are_generated_here() {
    use ts_rs::TS;
    ApiErrorBody::export_all().expect("ApiErrorBody.ts");
    totp::ClockSkew::export_all().expect("ClockSkew.ts");
}

/// An account, as a client sees it: never its password hash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts", ts(export))]
pub struct User {
    pub id: String,
    pub username: String,
    pub role: Role,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
    /// `None` means never signed in, to be shown as "never".
    pub last_login_at: Option<DateTime<Utc>>,
}

/// An account as `GET /api/users` lists it: its second factors beside it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts", ts(export))]
pub struct ListedUser {
    #[serde(flatten)]
    #[cfg_attr(feature = "ts", ts(flatten))]
    pub user: User,
    /// A confirmed TOTP key; an enrolment waiting for its first code is not one.
    pub totp: bool,
    pub passkeys: u32,
    /// Must enrol TOTP at its next password sign-in.
    pub totp_required: bool,
}

/// One account's role in one app the box runs, beside its own [`Role`] on the
/// box. Never `hostadmin`: a host admin is Admin in every app without a row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts", ts(export))]
pub struct AppRole {
    pub user_id: String,
    pub app: String,
    pub role: Role,
}

/// One page of a cursor-paged listing; `next` is present exactly when there is more.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts", ts(export))]
pub struct Page<T> {
    pub items: Vec<T>,
    pub next: Option<String>,
}

/// The constants a browser needs; one added above is not added here by itself.
#[cfg(all(test, feature = "ts"))]
mod export_constants {
    use super::*;

    #[test]
    fn export_bindings_constants() {
        let dir = std::path::PathBuf::from(
            std::env::var("TS_RS_EXPORT_DIR").unwrap_or_else(|_| "bindings".into()),
        );
        std::fs::create_dir_all(&dir).expect("create export dir");

        let ladder = Role::LADDER
            .iter()
            .map(|r| format!("\"{r}\""))
            .collect::<Vec<_>>()
            .join(", ");
        let levels = wslib_telemetry::LogLevel::LADDER
            .iter()
            .map(|l| serde_json::to_string(l).expect("a level is a string"))
            .collect::<Vec<_>>()
            .join(", ");

        let body = format!(
            "// This file was generated by wslib-appliance-types. Do not edit this file manually.\n\
             \n\
             /** The prefix every themeable CSS custom property shares. */\n\
             export const TOKEN_PREFIX = {prefix:?};\n\
             \n\
             /** The most tokens one theme may carry. */\n\
             export const MAX_TOKENS = {max_tokens};\n\
             \n\
             /** The longest a single token value may be, in bytes. */\n\
             export const MAX_VALUE_LEN = {max_value_len};\n\
             \n\
             /** Every role, lowest first. Position is rank. */\n\
             export const ROLE_LADDER = [{ladder}] as const;\n\
             \n\
             /** The shortest password the appliance accepts. */\n\
             export const MIN_PASSWORD_LEN = {min_password_len};\n\
             \n\
             /** The longest password the appliance accepts, in bytes of UTF-8. */\n\
             export const MAX_PASSWORD_BYTES = {max_password_bytes};\n\
             \n\
             /** The longest a username may be. */\n\
             export const MAX_USERNAME_LEN = {max_username_len};\n\
             \n\
             /** The longest a passkey's name may be. */\n\
             export const MAX_PASSKEY_NAME_LEN = {max_passkey_name_len};\n\
             \n\
             /** How a 403 for a password not confirmed recently begins. */\n\
             export const STALE_PROOF = {stale_proof:?};\n\
             \n\
             /** The most audit records one page may carry. */\n\
             export const MAX_AUDIT_PAGE = {max_audit_page};\n\
             \n\
             /** The longest PEM this appliance will read, in bytes. */\n\
             export const MAX_PEM_LEN = {max_pem_len};\n\
             \n\
             /** The largest backup bundle anything will read, in bytes. */\n\
             export const MAX_BUNDLE_LEN = {max_bundle_len};\n\
             \n\
             /** The shortest passphrase a backup may be sealed with. */\n\
             export const MIN_PASSPHRASE_LEN = {min_passphrase_len};\n\
             \n\
             /** The shortest and longest intervals a backup schedule may run at, in hours. */\n\
             export const MIN_EVERY_HOURS = {min_every_hours};\n\
             export const MAX_EVERY_HOURS = {max_every_hours};\n\
             \n\
             /** The fewest and most scheduled backups a box may keep. */\n\
             export const MIN_KEEP = {min_keep};\n\
             export const MAX_KEEP = {max_keep};\n\
             \n\
             /** How many log records the daemon keeps in memory, and a screen should. */\n\
             export const LOG_RING = {log_ring};\n\
             \n\
             /** Every log level, quietest first. Position is rank. */\n\
             export const LOG_LEVELS = [{levels}] as const;\n\
             \n\
             /** How often the log feed says `heartbeat` when idle, in seconds. */\n\
             export const FEED_HEARTBEAT_S = {feed_heartbeat_s};\n",
            prefix = branding::PREFIX,
            max_tokens = branding::MAX_TOKENS,
            max_value_len = branding::MAX_VALUE_LEN,
            ladder = ladder,
            min_password_len = MIN_PASSWORD_LEN,
            max_password_bytes = MAX_PASSWORD_BYTES,
            max_username_len = MAX_USERNAME_LEN,
            max_passkey_name_len = passkey::MAX_PASSKEY_NAME_LEN,
            stale_proof = STALE_PROOF,
            max_audit_page = MAX_AUDIT_PAGE,
            max_pem_len = tls::MAX_PEM_LEN,
            max_bundle_len = backup::MAX_BUNDLE_LEN,
            min_passphrase_len = backup::MIN_PASSPHRASE_LEN,
            min_every_hours = backup::MIN_EVERY_HOURS,
            max_every_hours = backup::MAX_EVERY_HOURS,
            min_keep = backup::MIN_KEEP,
            max_keep = backup::MAX_KEEP,
            log_ring = wslib_telemetry::log::LOG_RING,
            levels = levels,
            feed_heartbeat_s = log::FEED_HEARTBEAT_S,
        );
        std::fs::write(dir.join("constants.ts"), body).expect("write constants.ts");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_ladder_holds_every_role_in_ascending_order() {
        // A new variant stops this compiling, at the definition of `LADDER`.
        for role in Role::LADDER {
            match role {
                Role::Viewer | Role::Operator | Role::Admin | Role::HostAdmin => {}
            }
        }
        assert!(
            Role::LADDER.windows(2).all(|w| w[0] < w[1]),
            "LADDER must be ascending; it is what the browser reads rank from"
        );
    }

    #[test]
    fn the_role_ladder_is_ordered_viewer_to_host_admin() {
        assert!(Role::Viewer < Role::Operator);
        assert!(Role::Operator < Role::Admin);
        assert!(Role::Admin < Role::HostAdmin);
    }

    #[test]
    fn allows_is_at_least_not_exactly() {
        assert!(Role::Admin.allows(Role::Viewer));
        assert!(Role::Admin.allows(Role::Admin));
        assert!(!Role::Viewer.allows(Role::Operator));
    }

    #[test]
    fn a_role_survives_the_round_trip_through_its_column() {
        for role in Role::LADDER {
            assert_eq!(Role::from_str(role.as_str()).unwrap(), role);
        }
        assert_eq!(
            Role::from_str("root"),
            Err(UnknownRole("root".to_string())),
            "and the error names what it could not read"
        );
    }

    #[test]
    fn a_roles_slug_and_its_serde_form_agree() {
        for role in Role::LADDER {
            let json = serde_json::to_string(&role).unwrap();
            assert_eq!(json, format!("\"{}\"", role.as_str()));
        }
    }

    #[test]
    fn availability_is_tagged_so_a_client_can_switch_on_it() {
        let json = serde_json::to_value(Availability::unsupported("no D-Bus")).unwrap();
        assert_eq!(json["state"], "unsupported");
        assert_eq!(json["because"], "no D-Bus");
    }

    #[test]
    fn a_ready_capability_has_no_reason_to_give() {
        assert_eq!(Availability::ready("NetworkManager").because(), None);
    }
}
