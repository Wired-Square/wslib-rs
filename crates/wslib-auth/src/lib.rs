//! Browser sessions kept server-side: an opaque token in a cookie, only its
//! SHA-256 at rest, so one session or all of a user's can be ended.
//!
//! [`Sessions`] issues, looks up, re-stamps and ends them over a
//! [`SessionStore`]; with the `sqlite` or `postgres` feature, a ready store on
//! a sqlx pool. [`SessionCookie`] builds the `Set-Cookie` values and reads the
//! token back. [`Attempts`] limits wrong passwords or codes per key.
//!
//! A session vouches only for who signed in and when: whether the account is
//! still enabled, or was signed in before its sessions were last invalidated,
//! is the caller's check on each lookup.
//!
//! Take a [`Proof`] with [`Proof::begin`] before checking any credential, and
//! pass it to [`Sessions::issue`] or [`Sessions::reauthenticated`]. In a
//! two-step sign-in, take it at the step that re-reads the account (the code
//! step), not at the first. On each lookup, checking [`Session::proved_since`]
//! against the instant the account's sessions were last invalidated refuses a
//! sign-in that raced a password change.

mod attempts;
mod cookie;
mod session;
#[cfg(any(feature = "sqlite", feature = "postgres"))]
mod sql;
mod token;

pub use attempts::{Attempt, Attempts, TooManyAttempts};
pub use cookie::{SameSite, SessionCookie};
pub use session::{
    Proof, REAUTHENTICATION_WINDOW, SESSION_LIFETIME, Session, SessionError, SessionStore,
    Sessions, now,
};
#[cfg(feature = "postgres")]
pub use sql::PgSessionStore;
#[cfg(feature = "sqlite")]
pub use sql::SqliteSessionStore;
#[cfg(any(feature = "sqlite", feature = "postgres"))]
pub use sql::{InvalidTableName, SqlSessionStore, TableName, parse_stamp, stamp};
pub use token::{SessionToken, TokenHash};
