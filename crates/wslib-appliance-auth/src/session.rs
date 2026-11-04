//! Sessions as rows of the store's sessions table, and the three checks that
//! turn one back into an identity.
//!
//! A row is keyed by the hash of a token only the cookie carries, so nothing in
//! the database signs anybody in, and the rows never leave the box: a backup
//! does not carry them, and a restore of the accounts or a factory reset
//! deletes them.

use chrono::{DateTime, Utc};
use wslib_appliance_store::sqlx;
use wslib_appliance_store::{Account, Store, StoreError};
use wslib_appliance_types::User;
use wslib_auth::{Proof, Session, SessionError, SessionToken, SqliteSessionStore, TableName};
use wslib_secret::Secret;

use crate::AuthError;

const TABLE: TableName = TableName::new(wslib_appliance_store::SESSIONS_TABLE);
const SECRETS_TABLE: TableName = TableName::new(wslib_appliance_store::SESSION_SECRETS_TABLE);

/// An appliance's sessions, as rows of the store's sessions table.
#[derive(Clone, Debug)]
pub struct Sessions(wslib_auth::Sessions<SqliteSessionStore<String>>);

impl From<SessionError<sqlx::Error>> for AuthError {
    fn from(e: SessionError<sqlx::Error>) -> Self {
        match e {
            SessionError::Random(_) => Self::Random,
            SessionError::Store(e) => Self::Store(StoreError::Db(e)),
        }
    }
}

impl Sessions {
    pub fn new(store: &Store) -> Self {
        let rows =
            SqliteSessionStore::new(store.pool().clone(), TABLE).with_bound_secrets(SECRETS_TABLE);
        Self(wslib_auth::Sessions::new(rows))
    }

    /// A session for `user`, whose credential check began at `proof` and read
    /// `valid_from` as the account's cutoff; [`AuthError::Refused`], its row
    /// ended, if once the row is in the account is disabled or its cutoff has
    /// moved. Every revocation moves the cutoff and deletes the rows under the
    /// write lock, so the insert is deleted by it or follows its commit.
    pub async fn issue(
        &self,
        store: &Store,
        user: &User,
        valid_from: DateTime<Utc>,
        proof: Proof,
    ) -> Result<SessionToken, AuthError> {
        let (token, _) = self.0.issue(user.id.clone(), proof).await?;
        let unrevoked = store.user_by_id(&user.id).await?.is_some_and(|account| {
            account.user.enabled && account.sessions_valid_from == valid_from
        });
        if !unrevoked {
            self.0.end(&token).await?;
            tracing::warn!(
                name: "audit",
                actor = %user.username,
                user_id = %user.id,
                "sign-in refused: the account was revoked while it was checked"
            );
            return Err(AuthError::Refused);
        }
        Ok(token)
    }

    /// Turn a token back into who is asking, or refuse.
    ///
    /// The row must exist and be unexpired, and then three checks make
    /// revocation immediate: the account still exists, it has not been
    /// disabled, and **its credentials were proved no earlier than the
    /// account's sessions were last ended**, at full precision.
    pub async fn resolve(&self, store: &Store, token: &SessionToken) -> Result<User, AuthError> {
        self.resolve_with_reauthenticated_at(store, token)
            .await
            .map(|(user, _)| user)
    }

    /// [`resolve`](Self::resolve), with when the session last proved its
    /// account, at sign-in or since through [`reauthenticated`](Self::reauthenticated).
    pub async fn resolve_with_reauthenticated_at(
        &self,
        store: &Store,
        token: &SessionToken,
    ) -> Result<(User, DateTime<Utc>), AuthError> {
        let (account, session) = self.current(store, token).await?;
        Ok((account.user, session.reauthenticated_at))
    }

    /// A new secret for `token`'s session, which [`resolve_bound`](Self::resolve_bound)
    /// then asks for beside the cookie; [`AuthError::NoSession`] unless it
    /// [resolves](Self::resolve). Call it only where the cookie is set: it is
    /// not a route of its own. The session keeps its newest 16.
    pub async fn bind(&self, store: &Store, token: &SessionToken) -> Result<Secret, AuthError> {
        self.current(store, token).await?;
        let secret = self.0.bind(token).await?.ok_or(AuthError::NoSession)?;
        Ok(Secret::new(secret.expose()))
    }

    /// [`resolve_with_reauthenticated_at`](Self::resolve_with_reauthenticated_at),
    /// and [`AuthError::NoSession`] when the session has a bound secret and
    /// `secret` is none of them. A session never bound resolves without one,
    /// so a host moving its own bound secrets here copies them first.
    pub async fn resolve_bound(
        &self,
        store: &Store,
        token: &SessionToken,
        secret: Option<&Secret>,
    ) -> Result<(User, DateTime<Utc>), AuthError> {
        let secret = secret.map(|secret| SessionToken::from_presented(secret.expose()));
        let session = self.0.lookup_bound(token, secret.as_ref()).await?;
        let (account, session) = Self::checked(store, session).await?;
        Ok((account.user, session.reauthenticated_at))
    }

    /// Stamp `token`'s session as having proved its account again on `proof`:
    /// [`AuthError::NoSession`] unless it [resolves](Self::resolve), and
    /// [`AuthError::Refused`] if `proof` began before the account's sessions
    /// were last ended. Every revocation deletes the rows under its write
    /// lock, so one that commits after the check leaves nothing to stamp.
    pub async fn reauthenticated(
        &self,
        store: &Store,
        token: &SessionToken,
        proof: Proof,
    ) -> Result<(), AuthError> {
        let (account, _) = self.current(store, token).await?;
        if proof.at() < account.sessions_valid_from {
            return Err(AuthError::Refused);
        }
        if !self.0.reauthenticated(token, proof).await? {
            return Err(AuthError::NoSession);
        }
        Ok(())
    }

    async fn current(
        &self,
        store: &Store,
        token: &SessionToken,
    ) -> Result<(Account, Session<String>), AuthError> {
        Self::checked(store, self.0.lookup(token).await?).await
    }

    async fn checked(
        store: &Store,
        session: Option<Session<String>>,
    ) -> Result<(Account, Session<String>), AuthError> {
        let session = session.ok_or(AuthError::NoSession)?;
        let account = store
            .user_by_id(&session.user_id)
            .await?
            .filter(|account| account.user.enabled)
            .ok_or(AuthError::NoSession)?;
        if !session.proved_since(account.sessions_valid_from) {
            tracing::info!(
                username = %account.user.username,
                user_id = %account.user.id,
                "session refused: it was proved before this account's sessions were ended"
            );
            return Err(AuthError::NoSession);
        }
        Ok((account, session))
    }

    pub async fn end(&self, token: &SessionToken) -> Result<(), AuthError> {
        self.0.end(token).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use super::*;
    use crate::tests::{PASSWORD, WEAK_HASH, store, user, user_with_hash};
    use tempfile::TempDir;
    use wslib_appliance_types::Role;

    async fn set_valid_from(store: &Store, id: &str, at: DateTime<Utc>) {
        sqlx::query("UPDATE users SET sessions_valid_from = ? WHERE id = ?")
            .bind(wslib_auth::stamp(at))
            .bind(id)
            .execute(store.pool())
            .await
            .expect("move the cutoff");
    }

    async fn valid_from(store: &Store, id: &str) -> DateTime<Utc> {
        let account = store.user_by_id(id).await.expect("read");
        account.expect("the account").sessions_valid_from
    }

    async fn rows(store: &Store) -> i64 {
        let count = format!(
            "SELECT count(*) FROM {}",
            wslib_appliance_store::SESSIONS_TABLE
        );
        sqlx::query_scalar(&count)
            .fetch_one(store.pool())
            .await
            .expect("count")
    }

    fn refused(resolved: Result<User, AuthError>) -> bool {
        matches!(resolved, Err(AuthError::NoSession))
    }

    /// A session for `user`, as a sign-in that has just verified it issues one.
    async fn signed_in(sessions: &Sessions, store: &Store, user: &User) -> SessionToken {
        let read = valid_from(store, &user.id).await;
        sessions
            .issue(store, user, read, Proof::begin())
            .await
            .expect("issue")
    }

    /// A sign-in's issue held behind a revocation's write lock until it is
    /// blocked there, then the revocation committed: the issue's answer, on a
    /// file with more than one connection.
    async fn issued_behind(revocation: &'static str) -> (TempDir, Store, Result<(), AuthError>) {
        let dir = TempDir::new().expect("temp dir");
        let store = Store::open(dir.path().join("appliance.db"), None)
            .await
            .expect("store");
        let created = user(&store, "admin", Role::Admin).await;
        let read = valid_from(&store, &created.id).await;
        let sessions = Sessions::new(&store);

        let mut held = store.begin().await.expect("the revocation's write lock");
        sqlx::query(revocation)
            .bind(wslib_auth::stamp(wslib_auth::now()))
            .bind(&created.id)
            .execute(&mut *held)
            .await
            .expect("the revocation");
        let issuing = tokio::spawn({
            let (sessions, store) = (sessions.clone(), store.clone());
            async move {
                let issued = sessions.issue(&store, &created, read, Proof::begin());
                issued.await.map(drop)
            }
        });
        let deadline = Instant::now() + Duration::from_secs(4);
        while store.pool().size() as usize - store.pool().num_idle() < 2 {
            assert!(
                Instant::now() < deadline,
                "the issue never reached the database"
            );
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        assert!(!issuing.is_finished(), "blocked behind the write lock");
        held.commit().await.expect("commit");

        let issued = issuing.await.expect("the task");
        (dir, store, issued)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_sign_in_whose_insert_waits_out_a_password_change_is_refused() {
        let (_dir, store, issued) = issued_behind(
            "UPDATE users SET password_hash = 'rotated', sessions_valid_from = ? WHERE id = ?",
        )
        .await;
        assert!(matches!(issued, Err(AuthError::Refused)), "{issued:?}");
        assert_eq!(rows(&store).await, 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_sign_in_whose_insert_waits_out_a_disable_is_refused_and_stays_so() {
        let (_dir, store, issued) =
            issued_behind("UPDATE users SET enabled = 0, sessions_valid_from = ? WHERE id = ?")
                .await;
        assert!(matches!(issued, Err(AuthError::Refused)), "{issued:?}");
        assert_eq!(rows(&store).await, 0, "nothing for a re-enable to revive");
    }

    #[tokio::test]
    async fn a_token_round_trips_into_the_account_that_earned_it_and_survives_a_restart() {
        let store = store().await;
        let created = user(&store, "admin", Role::Admin).await;
        let token = signed_in(&Sessions::new(&store), &store, &created).await;

        let after_restart = Sessions::new(&store);
        let resolved = after_restart.resolve(&store, &token).await;
        assert_eq!(resolved.expect("resolves"), created);
    }

    #[tokio::test]
    async fn a_token_issued_on_another_box_is_refused() {
        let store = store().await;
        let created = user(&store, "admin", Role::Admin).await;
        let token = signed_in(&Sessions::new(&store), &store, &created).await;

        let other_box = crate::tests::store().await;
        let elsewhere = Sessions::new(&other_box);
        assert!(refused(elsewhere.resolve(&other_box, &token).await));
    }

    #[tokio::test]
    async fn a_sign_in_whose_check_began_before_a_revocation_is_refused_and_leaves_no_row() {
        for revoke in ["reset", "disable", "disable and enable"] {
            let store = store().await;
            let created = user(&store, "admin", Role::Admin).await;
            let sessions = Sessions::new(&store);

            let read = valid_from(&store, &created.id).await;
            let proof = Proof::begin();
            let revoked = match revoke {
                "reset" => store
                    .set_password(&created.id, "$argon2id$v=19$reset")
                    .await
                    .map(drop),
                _ => store.set_enabled(&created.id, false).await,
            };
            revoked.expect("the revocation");
            if revoke == "disable and enable" {
                store.set_enabled(&created.id, true).await.expect("enable");
            }
            let issued = sessions.issue(&store, &created, read, proof).await;

            assert!(
                matches!(issued, Err(AuthError::Refused)),
                "{revoke}: {issued:?}"
            );
            assert_eq!(rows(&store).await, 0, "{revoke}");
        }
    }

    #[tokio::test]
    async fn a_proof_a_microsecond_before_the_cutoff_is_refused_and_one_at_it_is_not() {
        let store = store().await;
        let created = user(&store, "admin", Role::Admin).await;
        let sessions = Sessions::new(&store);
        let read = valid_from(&store, &created.id).await;
        let proof = Proof::begin();
        let token = sessions
            .issue(&store, &created, read, proof)
            .await
            .expect("issue");

        let later = proof.at() + chrono::TimeDelta::microseconds(1);
        set_valid_from(&store, &created.id, later).await;
        assert!(refused(sessions.resolve(&store, &token).await));

        set_valid_from(&store, &created.id, proof.at()).await;
        assert!(sessions.resolve(&store, &token).await.is_ok());
    }

    #[tokio::test]
    async fn a_password_change_ends_the_sessions_before_it_and_not_the_one_it_issues() {
        let store = store().await;
        let created = user(&store, "admin", Role::Admin).await;
        let sessions = Sessions::new(&store);
        let before = signed_in(&sessions, &store, &created).await;

        let hash = crate::tests::hash_of_password();
        let stamped = store.set_password_if_unchanged(&created.id, hash, "$argon2id$v=19$new");
        let stamped = stamped.await.expect("rotate").expect("written");
        assert_eq!(rows(&store).await, 0);
        let fresh = sessions
            .issue(&store, &created, stamped, Proof::begin())
            .await
            .expect("issue");

        assert!(refused(sessions.resolve(&store, &before).await));
        assert!(sessions.resolve(&store, &fresh).await.is_ok());
    }

    #[tokio::test]
    async fn a_re_hash_on_sign_in_ends_no_session_and_refuses_no_sign_in() {
        let store = store().await;
        let created = user_with_hash(&store, WEAK_HASH).await;
        let sessions = Sessions::new(&store);
        let existing = signed_in(&sessions, &store, &created).await;
        let before = valid_from(&store, &created.id).await;

        let proof = Proof::begin();
        let account = crate::authenticate(&store, "admin", PASSWORD).await;
        let account = account.expect("sign in");
        assert_ne!(account.password_hash.expose(), WEAK_HASH, "re-hashed");
        assert_eq!(valid_from(&store, &created.id).await, before);
        assert_eq!(rows(&store).await, 1);

        let read = account.sessions_valid_from;
        let fresh = sessions.issue(&store, &account.user, read, proof).await;
        let fresh = fresh.expect("issue");
        assert!(sessions.resolve(&store, &existing).await.is_ok());
        assert!(sessions.resolve(&store, &fresh).await.is_ok());
    }

    #[tokio::test]
    async fn a_disabled_account_loses_its_sessions_and_re_enabling_it_revives_none() {
        let store = store().await;
        let created = user(&store, "admin", Role::Admin).await;
        let sessions = Sessions::new(&store);
        let token = signed_in(&sessions, &store, &created).await;

        store
            .set_enabled(&created.id, false)
            .await
            .expect("disable");
        assert!(refused(sessions.resolve(&store, &token).await));
        store.set_enabled(&created.id, true).await.expect("enable");
        assert!(refused(sessions.resolve(&store, &token).await));
    }

    #[tokio::test]
    async fn a_deleted_account_loses_its_sessions() {
        let store = store().await;
        let created = user(&store, "admin", Role::Admin).await;
        let sessions = Sessions::new(&store);
        let token = signed_in(&sessions, &store, &created).await;

        store.delete_user(&created.id).await.expect("delete");
        assert!(refused(sessions.resolve(&store, &token).await));
    }

    #[tokio::test]
    async fn a_role_change_is_seen_without_a_new_session() {
        let store = store().await;
        let created = user(&store, "admin", Role::Admin).await;
        let sessions = Sessions::new(&store);
        let token = signed_in(&sessions, &store, &created).await;

        store
            .set_role(&created.id, Role::Viewer)
            .await
            .expect("demote");
        let resolved = sessions.resolve(&store, &token).await.expect("resolves");
        assert_eq!(resolved.role, Role::Viewer);
    }

    #[tokio::test]
    async fn ending_one_session_leaves_the_others() {
        let store = store().await;
        let created = user(&store, "admin", Role::Admin).await;
        let sessions = Sessions::new(&store);
        let one = signed_in(&sessions, &store, &created).await;
        let two = signed_in(&sessions, &store, &created).await;

        sessions.end(&one).await.expect("end");
        assert!(refused(sessions.resolve(&store, &one).await));
        assert!(sessions.resolve(&store, &two).await.is_ok());
    }

    #[tokio::test]
    async fn a_token_from_before_the_rows_and_nonsense_are_refused_rather_than_panicking() {
        let store = store().await;
        let sessions = Sessions::new(&store);
        let signed = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1MSJ9.c2lnbmF0dXJl";
        for token in ["", signed, "a.b.c", &"x".repeat(4096)] {
            let token = SessionToken::from_presented(token);
            assert!(refused(sessions.resolve(&store, &token).await));
        }
    }

    #[tokio::test]
    async fn a_stamp_reads_back_as_the_proof_it_was_given() {
        let store = store().await;
        let created = user(&store, "admin", Role::Admin).await;
        let sessions = Sessions::new(&store);
        let token = signed_in(&sessions, &store, &created).await;
        let proof = Proof::begin();

        sessions
            .reauthenticated(&store, &token, proof)
            .await
            .expect("stamp");
        let resolved = sessions.resolve_with_reauthenticated_at(&store, &token);
        assert_eq!(resolved.await.expect("resolves"), (created, proof.at()));
    }

    #[tokio::test]
    async fn stamping_an_unknown_or_expired_session_is_no_session() {
        let store = store().await;
        let created = user(&store, "admin", Role::Admin).await;
        let sessions = Sessions::new(&store);
        let token = signed_in(&sessions, &store, &created).await;
        let expire = format!(
            "UPDATE {} SET expires_at = ?",
            wslib_appliance_store::SESSIONS_TABLE
        );
        sqlx::query(&expire)
            .bind(wslib_auth::stamp(wslib_auth::now()))
            .execute(store.pool())
            .await
            .expect("expire");

        for token in [token, SessionToken::from_presented("unknown")] {
            let stamped = sessions.reauthenticated(&store, &token, Proof::begin());
            let stamped = stamped.await;
            assert!(matches!(stamped, Err(AuthError::NoSession)), "{stamped:?}");
        }
    }

    #[tokio::test]
    async fn a_proof_begun_before_a_revocation_stamps_no_session() {
        for revoke in ["reset", "disable and enable"] {
            let store = store().await;
            let created = user(&store, "admin", Role::Admin).await;
            let sessions = Sessions::new(&store);
            let before = signed_in(&sessions, &store, &created).await;

            let proof = Proof::begin();
            match revoke {
                "reset" => {
                    let reset = store.set_password(&created.id, "$argon2id$v=19$reset");
                    reset.await.expect("reset");
                }
                _ => {
                    store
                        .set_enabled(&created.id, false)
                        .await
                        .expect("disable");
                    store.set_enabled(&created.id, true).await.expect("enable");
                }
            }
            let after = signed_in(&sessions, &store, &created).await;
            let issued = sessions.resolve_with_reauthenticated_at(&store, &after);
            let (_, issued) = issued.await.expect("resolves");

            let stale = sessions.reauthenticated(&store, &before, proof).await;
            assert!(
                matches!(stale, Err(AuthError::NoSession)),
                "{revoke}: {stale:?}"
            );
            let raced = sessions.reauthenticated(&store, &after, proof).await;
            assert!(
                matches!(raced, Err(AuthError::Refused)),
                "{revoke}: {raced:?}"
            );
            let kept = sessions.resolve_with_reauthenticated_at(&store, &after);
            assert_eq!(kept.await.expect("resolves").1, issued, "{revoke}");
        }
    }

    async fn secrets(store: &Store) -> i64 {
        let count = format!(
            "SELECT count(*) FROM {}",
            wslib_appliance_store::SESSION_SECRETS_TABLE
        );
        sqlx::query_scalar(&count)
            .fetch_one(store.pool())
            .await
            .expect("count")
    }

    #[tokio::test]
    async fn a_bound_session_resolves_only_with_one_of_its_secrets() {
        let store = store().await;
        let created = user(&store, "admin", Role::Admin).await;
        let sessions = Sessions::new(&store);
        let token = signed_in(&sessions, &store, &created).await;
        let bound = |secret: Option<Secret>| {
            let (sessions, store, token) = (&sessions, &store, &token);
            async move { sessions.resolve_bound(store, token, secret.as_ref()).await }
        };
        assert!(bound(None).await.is_ok(), "a session never bound");

        let secret = sessions.bind(&store, &token).await.expect("bind");
        let (resolved, _) = bound(Some(secret.clone())).await.expect("resolves");
        assert_eq!(resolved, created);
        for refused in [
            None,
            Some(Secret::new("")),
            Some(Secret::new(token.expose())),
        ] {
            let refused = bound(refused).await;
            assert!(matches!(refused, Err(AuthError::NoSession)), "{refused:?}");
        }
    }

    #[tokio::test]
    async fn only_a_session_that_resolves_is_bound() {
        let store = store().await;
        let created = user(&store, "admin", Role::Admin).await;
        let sessions = Sessions::new(&store);
        let token = signed_in(&sessions, &store, &created).await;
        store
            .set_enabled(&created.id, false)
            .await
            .expect("disable");

        for token in [token, SessionToken::from_presented("unknown")] {
            let bound = sessions.bind(&store, &token).await;
            assert!(matches!(bound, Err(AuthError::NoSession)), "{bound:?}");
        }
        assert_eq!(secrets(&store).await, 0);
    }

    #[tokio::test]
    async fn the_secrets_go_with_their_session_however_it_ends() {
        for end in ["sign out", "password reset", "delete"] {
            let store = store().await;
            let created = user(&store, "admin", Role::Admin).await;
            let sessions = Sessions::new(&store);
            let token = signed_in(&sessions, &store, &created).await;
            sessions.bind(&store, &token).await.expect("bind");
            sessions.bind(&store, &token).await.expect("bind again");
            assert_eq!(secrets(&store).await, 2, "{end}");

            match end {
                "sign out" => sessions.end(&token).await.expect("end"),
                "password reset" => store
                    .set_password(&created.id, "$argon2id$v=19$reset")
                    .await
                    .map(drop)
                    .expect("reset"),
                _ => store.delete_user(&created.id).await.expect("delete"),
            }
            assert_eq!(secrets(&store).await, 0, "{end}");
        }
    }

    #[test]
    fn the_store_and_the_sessions_spell_an_instant_alike() {
        let at = wslib_auth::now();
        assert_eq!(wslib_appliance_store::stamp(at), wslib_auth::stamp(at));
    }

    #[tokio::test]
    async fn signing_in_and_resolving_is_the_whole_loop() {
        let store = store().await;
        user(&store, "operator", Role::Operator).await;
        let sessions = Sessions::new(&store);

        let proof = Proof::begin();
        let account = crate::authenticate(&store, "operator", PASSWORD)
            .await
            .expect("sign in");
        let read = account.sessions_valid_from;
        let token = sessions
            .issue(&store, &account.user, read, proof)
            .await
            .expect("issue");
        let resolved = sessions.resolve(&store, &token).await.expect("resolve");

        assert_eq!(resolved.username, "operator");
        assert_eq!(resolved.role, Role::Operator);
    }
}
