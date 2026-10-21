use std::fmt;
use std::future::Future;

use chrono::{DateTime, SubsecRound, TimeDelta, Utc};

use crate::token::{SessionToken, TokenHash};

/// How long a session lasts from its issue unless set otherwise.
pub const SESSION_LIFETIME: TimeDelta = TimeDelta::hours(12);

/// How recently a session must have proved its credentials again for a sensitive action.
pub const REAUTHENTICATION_WINDOW: TimeDelta = TimeDelta::minutes(5);

/// A signed-in browser, as its store row holds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Session<U> {
    pub user_id: U,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub reauthenticated_at: DateTime<Utc>,
}

impl<U> Session<U> {
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

    fn set_reauthenticated_at(
        &self,
        hash: &TokenHash,
        at: DateTime<Utc>,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    fn remove(&self, hash: &TokenHash) -> impl Future<Output = Result<(), Self::Error>> + Send;

    fn remove_user(
        &self,
        user_id: &Self::UserId,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Removes every session that expires at or before `now`.
    fn remove_expired(
        &self,
        now: DateTime<Utc>,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;
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

    /// A new session for `user_id`, who has just proved their credentials. Expired sessions go first.
    pub async fn issue(
        &self,
        user_id: S::UserId,
    ) -> Result<(SessionToken, Session<S::UserId>), IssueError<S::Error>> {
        let token = SessionToken::generate().map_err(IssueError::Random)?;
        let at = now();
        let session = Session {
            user_id,
            created_at: at,
            expires_at: at + self.lifetime,
            reauthenticated_at: at,
        };
        self.store
            .remove_expired(at)
            .await
            .map_err(IssueError::Store)?;
        self.store
            .insert(&token.hash(), &session)
            .await
            .map_err(IssueError::Store)?;
        Ok((token, session))
    }

    /// The unexpired session `token` names.
    pub async fn lookup(
        &self,
        token: &SessionToken,
    ) -> Result<Option<Session<S::UserId>>, S::Error> {
        self.store.find(&token.hash(), now()).await
    }

    /// Records that `token`'s holder has just proved their credentials again.
    pub async fn reauthenticated(&self, token: &SessionToken) -> Result<(), S::Error> {
        self.store
            .set_reauthenticated_at(&token.hash(), now())
            .await
    }

    /// Ends `token`'s session.
    pub async fn end(&self, token: &SessionToken) -> Result<(), S::Error> {
        self.store.remove(&token.hash()).await
    }

    /// Ends every session of `user_id`, as on a password change.
    pub async fn end_all(&self, user_id: &S::UserId) -> Result<(), S::Error> {
        self.store.remove_user(user_id).await
    }

    pub async fn purge_expired(&self) -> Result<(), S::Error> {
        self.store.remove_expired(now()).await
    }
}

/// Why no session was issued.
#[derive(Debug)]
pub enum IssueError<E> {
    Random(getrandom::Error),
    Store(E),
}

impl<E: fmt::Display> fmt::Display for IssueError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Random(e) => write!(f, "no session token could be made: {e}"),
            Self::Store(e) => write!(f, "the session could not be stored: {e}"),
        }
    }
}

impl<E: std::error::Error + 'static> std::error::Error for IssueError<E> {
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
}
