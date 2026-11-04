use std::fmt;
use std::future::Future;

use chrono::{DateTime, SecondsFormat, SubsecRound, TimeDelta, Utc};

use crate::token::{SessionToken, TokenHash};

/// How long a session lasts from its issue unless set otherwise.
pub const SESSION_LIFETIME: TimeDelta = TimeDelta::hours(12);

/// How recently a session must have proved its credentials again for a sensitive action.
pub const REAUTHENTICATION_WINDOW: TimeDelta = TimeDelta::minutes(5);

/// How many bound secrets a session keeps; binding another drops the oldest.
pub const BOUND_SECRETS_KEPT: usize = 16;

/// A signed-in browser, as its store row holds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Session<U> {
    pub user_id: U,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    /// When the sign-in's credential check began: its [`Proof`].
    pub proved_at: DateTime<Utc>,
    pub reauthenticated_at: DateTime<Utc>,
}

impl<U> Session<U> {
    /// Whether the sign-in's credentials were proved at or after `cutoff`, as
    /// the instant the account's sessions were last invalidated. Stamp that
    /// cutoff after the new credential is committed, not before the write: a
    /// check that begins in between reads the old one. Equal instants pass.
    pub fn proved_since(&self, cutoff: DateTime<Utc>) -> bool {
        self.proved_at >= cutoff
    }

    /// Whether the session re-authenticated no longer than `window` before `now`, and not after it.
    pub fn reauthenticated_within(&self, window: TimeDelta, now: DateTime<Utc>) -> bool {
        let age = now - self.reauthenticated_at;
        age >= TimeDelta::zero() && age <= window
    }
}

/// Where sessions are kept, keyed by [`TokenHash`].
pub trait SessionStore: Send + Sync {
    type UserId: Send + Sync;
    type Error: std::error::Error + Send + Sync + 'static;

    fn insert(
        &self,
        hash: &TokenHash,
        session: &Session<Self::UserId>,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// The session under `hash` if it expires after `now`.
    fn find(
        &self,
        hash: &TokenHash,
        now: DateTime<Utc>,
    ) -> impl Future<Output = Result<Option<Session<Self::UserId>>, Self::Error>> + Send;

    /// Whether a session was under `hash` to stamp.
    fn set_reauthenticated_at(
        &self,
        hash: &TokenHash,
        at: DateTime<Utc>,
    ) -> impl Future<Output = Result<bool, Self::Error>> + Send;

    /// Whether a session was under `hash` to remove.
    fn remove(&self, hash: &TokenHash) -> impl Future<Output = Result<bool, Self::Error>> + Send;

    /// Whether `user_id` had any session to remove.
    fn remove_user(
        &self,
        user_id: &Self::UserId,
    ) -> impl Future<Output = Result<bool, Self::Error>> + Send;

    /// Removes every session that expires at or before `now`.
    fn remove_expired(
        &self,
        now: DateTime<Utc>,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;
}

/// A [`SessionStore`] that also keeps secrets bound to a session, keyed by its
/// [`TokenHash`]. Every removal of a session row removes its secrets with it.
pub trait BoundSecretStore: SessionStore {
    /// Stores `secret` for the session under `session` if it expires after
    /// `at`, keeping it and the newest of the rest, `keep` in all; false if
    /// there is no such session.
    fn bind_secret(
        &self,
        session: &TokenHash,
        secret: &TokenHash,
        at: DateTime<Utc>,
        keep: usize,
    ) -> impl Future<Output = Result<bool, Self::Error>> + Send;

    fn bound_secrets(
        &self,
        session: &TokenHash,
    ) -> impl Future<Output = Result<Vec<TokenHash>, Self::Error>> + Send;
}

/// The instant a credential check began, taken before the check so a session
/// issued on it cannot outlive a password change that raced it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Proof(DateTime<Utc>);

impl Proof {
    /// Call before checking any password, passkey or code, or after the write
    /// when the request itself moves the account's cutoff.
    pub fn begin() -> Self {
        Self(now())
    }

    pub fn at(self) -> DateTime<Utc> {
        self.0
    }
}

/// Sessions over a [`SessionStore`]: issue, look up, re-stamp and end them.
///
/// A session says only who signed in and when. Whether that account may still
/// act (enabled, or signed in after its sessions were last invalidated) is the
/// caller's check on every lookup, against its own account record.
#[derive(Debug, Clone)]
pub struct Sessions<S> {
    store: S,
    lifetime: TimeDelta,
}

/// An instant as the sqlx stores keep it, for a store or schema of your own: fixed-width RFC 3339, UTC, six
/// subsecond digits, so stamps compare as text in time order.
pub fn stamp(at: DateTime<Utc>) -> String {
    at.to_rfc3339_opts(SecondsFormat::Micros, true)
}

/// A [`stamp`] read back.
pub fn parse_stamp(stamp: &str) -> Result<DateTime<Utc>, chrono::ParseError> {
    DateTime::parse_from_rfc3339(stamp).map(|at| at.with_timezone(&Utc))
}

/// The current instant at the microsecond precision a store keeps.
pub fn now() -> DateTime<Utc> {
    Utc::now().trunc_subsecs(6)
}

impl<S: SessionStore> Sessions<S> {
    /// Sessions in `store` lasting [`SESSION_LIFETIME`].
    pub fn new(store: S) -> Self {
        Self {
            store,
            lifetime: SESSION_LIFETIME,
        }
    }

    pub fn with_lifetime(self, lifetime: TimeDelta) -> Self {
        Self { lifetime, ..self }
    }

    pub fn store(&self) -> &S {
        &self.store
    }

    /// A new session for `user_id`, whose credentials `proof` covers. Expired sessions go first.
    pub async fn issue(
        &self,
        user_id: S::UserId,
        proof: Proof,
    ) -> Result<(SessionToken, Session<S::UserId>), SessionError<S::Error>> {
        let token = SessionToken::generate().map_err(SessionError::Random)?;
        let at = now();
        let session = Session {
            user_id,
            created_at: at,
            expires_at: at + self.lifetime,
            proved_at: proof.at(),
            reauthenticated_at: proof.at(),
        };
        self.store.remove_expired(at).await?;
        self.store.insert(&token.hash(), &session).await?;
        Ok((token, session))
    }

    /// The unexpired session `token` names.
    pub async fn lookup(
        &self,
        token: &SessionToken,
    ) -> Result<Option<Session<S::UserId>>, SessionError<S::Error>> {
        Ok(self.store.find(&token.hash(), now()).await?)
    }

    /// Records that `token`'s holder proved their credentials again, as `proof`
    /// covers; false if `token` names no session.
    pub async fn reauthenticated(
        &self,
        token: &SessionToken,
        proof: Proof,
    ) -> Result<bool, SessionError<S::Error>> {
        Ok(self
            .store
            .set_reauthenticated_at(&token.hash(), proof.at())
            .await?)
    }

    /// Ends `token`'s session; false if there was none.
    pub async fn end(&self, token: &SessionToken) -> Result<bool, SessionError<S::Error>> {
        Ok(self.store.remove(&token.hash()).await?)
    }

    /// Ends every session of `user_id`, as on a password change; false if there were none.
    pub async fn end_all(&self, user_id: &S::UserId) -> Result<bool, SessionError<S::Error>> {
        Ok(self.store.remove_user(user_id).await?)
    }

    pub async fn purge_expired(&self) -> Result<(), SessionError<S::Error>> {
        Ok(self.store.remove_expired(now()).await?)
    }
}

impl<S: BoundSecretStore> Sessions<S> {
    /// A new secret bound to `token`'s unexpired session, which
    /// [`lookup_bound`](Self::lookup_bound) then asks for; `None` if there is no
    /// session. The session keeps its newest [`BOUND_SECRETS_KEPT`].
    pub async fn bind(
        &self,
        token: &SessionToken,
    ) -> Result<Option<SessionToken>, SessionError<S::Error>> {
        let secret = SessionToken::generate().map_err(SessionError::Random)?;
        let bound = self
            .store
            .bind_secret(&token.hash(), &secret.hash(), now(), BOUND_SECRETS_KEPT)
            .await?;
        Ok(bound.then_some(secret))
    }

    /// [`lookup`](Self::lookup), but `None` when the session has a bound secret
    /// and `secret` is not one of them. A session with none is found as before.
    pub async fn lookup_bound(
        &self,
        token: &SessionToken,
        secret: Option<&SessionToken>,
    ) -> Result<Option<Session<S::UserId>>, SessionError<S::Error>> {
        let hash = token.hash();
        let Some(session) = self.store.find(&hash, now()).await? else {
            return Ok(None);
        };
        let bound = self.store.bound_secrets(&hash).await?;
        let admitted =
            bound.is_empty() || secret.is_some_and(|secret| bound.contains(&secret.hash()));
        Ok(admitted.then_some(session))
    }
}

/// Why a [`Sessions`] call failed.
#[derive(Debug)]
pub enum SessionError<E> {
    Random(getrandom::Error),
    Store(E),
}

impl<E> From<E> for SessionError<E> {
    fn from(e: E) -> Self {
        Self::Store(e)
    }
}

impl<E: fmt::Display> fmt::Display for SessionError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Random(e) => write!(f, "no session token could be made: {e}"),
            Self::Store(e) => write!(f, "the session store failed: {e}"),
        }
    }
}

impl<E: std::error::Error + 'static> std::error::Error for SessionError<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Random(e) => Some(e),
            Self::Store(e) => Some(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session(reauthenticated_at: DateTime<Utc>) -> Session<()> {
        Session {
            user_id: (),
            created_at: reauthenticated_at,
            expires_at: reauthenticated_at + SESSION_LIFETIME,
            proved_at: reauthenticated_at,
            reauthenticated_at,
        }
    }

    #[test]
    fn the_reauthentication_window_is_recent_and_never_in_the_future() {
        let now = now();
        let within = |ago: TimeDelta| {
            session(now - ago).reauthenticated_within(REAUTHENTICATION_WINDOW, now)
        };
        assert!(within(TimeDelta::zero()));
        assert!(within(REAUTHENTICATION_WINDOW));
        assert!(!within(
            REAUTHENTICATION_WINDOW + TimeDelta::microseconds(1)
        ));
        assert!(!within(TimeDelta::seconds(-1)), "a stamp from the future");
    }

    #[test]
    fn a_session_error_boxes_as_send_and_sync_for_question_mark() {
        let boxed: Box<dyn std::error::Error + Send + Sync> =
            SessionError::Store(std::io::Error::other("down")).into();
        assert_eq!(boxed.to_string(), "the session store failed: down");
    }
}
