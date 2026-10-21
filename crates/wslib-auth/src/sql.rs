use std::borrow::Cow;
use std::fmt;
use std::marker::PhantomData;
use std::str::FromStr;

use chrono::{DateTime, Utc};
use sqlx::{Database, Pool, Row};

use crate::session::{Session, SessionStore, parse_stamp, stamp};
use crate::token::TokenHash;

/// A [`SessionStore`] in a table of the caller's, on a sqlx pool; the README carries its DDL.
///
/// Times are stored as [`stamp`]s. The user id is stored as its `Display` and
/// read back with `FromStr`.
pub struct SqlSessionStore<DB: Database, U> {
    pool: Pool<DB>,
    queries: Queries,
    user_id: PhantomData<fn() -> U>,
}

#[cfg(feature = "sqlite")]
pub type SqliteSessionStore<U> = SqlSessionStore<sqlx::Sqlite, U>;

#[cfg(feature = "postgres")]
pub type PgSessionStore<U> = SqlSessionStore<sqlx::Postgres, U>;

impl<DB: Database, U> Clone for SqlSessionStore<DB, U> {
    fn clone(&self) -> Self {
        Self {
            pool: self.pool.clone(),
            queries: self.queries.clone(),
            user_id: PhantomData,
        }
    }
}

impl<DB: Database, U> fmt::Debug for SqlSessionStore<DB, U> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SqlSessionStore")
            .field("table", &self.queries.table)
            .finish_non_exhaustive()
    }
}

impl<DB: Database, U> SqlSessionStore<DB, U> {
    /// Sessions in `table` of `pool`'s database.
    pub fn new(pool: Pool<DB>, table: TableName) -> Self {
        Self {
            pool,
            queries: Queries::for_table(table),
            user_id: PhantomData,
        }
    }

    pub fn pool(&self) -> &Pool<DB> {
        &self.pool
    }
}

/// A plain table name: an ASCII letter or `_`, then letters, digits or `_`, at most 63 bytes.
///
/// [`TableName::new`] in a const refuses an invalid literal at compile time:
///
/// ```
/// # use wslib_auth::TableName;
/// const SESSIONS: TableName = TableName::new("app_sessions");
/// ```
///
/// ```compile_fail
/// # use wslib_auth::TableName;
/// const SESSIONS: TableName = TableName::new("app sessions");
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TableName(Cow<'static, str>);

impl TableName {
    /// # Panics
    ///
    /// If `name` is not a plain table name; at compile time in a const.
    pub const fn new(name: &'static str) -> Self {
        assert!(is_plain_identifier(name), "not a plain table name");
        Self(Cow::Borrowed(name))
    }

    /// A name known only at run time.
    pub fn parse(name: impl Into<String>) -> Result<Self, InvalidTableName> {
        let name = name.into();
        if is_plain_identifier(&name) {
            Ok(Self(Cow::Owned(name)))
        } else {
            Err(InvalidTableName(name))
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

const fn is_plain_identifier(name: &str) -> bool {
    let bytes = name.as_bytes();
    if bytes.is_empty() || bytes.len() > 63 || bytes[0].is_ascii_digit() {
        return false;
    }
    let mut i = 0;
    while i < bytes.len() {
        if !(bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
            return false;
        }
        i += 1;
    }
    true
}

/// A table name that is not a plain identifier, as [`TableName`] defines one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidTableName(pub String);

impl fmt::Display for InvalidTableName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?} is not a plain table name", self.0)
    }
}

impl std::error::Error for InvalidTableName {}

#[derive(Debug, Clone)]
struct Queries {
    table: TableName,
    insert: String,
    find: String,
    set_reauthenticated_at: String,
    remove: String,
    remove_user: String,
    remove_expired: String,
}

impl Queries {
    fn for_table(table: TableName) -> Self {
        let name = table.as_str();
        Self {
            insert: format!(
                "INSERT INTO {name} \
                 (token_hash, user_id, created_at, expires_at, proved_at, reauthenticated_at) \
                 VALUES ($1, $2, $3, $4, $5, $6)"
            ),
            find: format!(
                "SELECT user_id, created_at, expires_at, proved_at, reauthenticated_at \
                 FROM {name} WHERE token_hash = $1 AND expires_at > $2"
            ),
            set_reauthenticated_at: format!(
                "UPDATE {name} SET reauthenticated_at = $1 WHERE token_hash = $2"
            ),
            remove: format!("DELETE FROM {name} WHERE token_hash = $1"),
            remove_user: format!("DELETE FROM {name} WHERE user_id = $1"),
            remove_expired: format!("DELETE FROM {name} WHERE expires_at <= $1"),
            table,
        }
    }
}

fn session_from<R, U>(row: &R, table: &TableName) -> Result<Session<U>, sqlx::Error>
where
    R: Row,
    for<'r> &'r str: sqlx::Decode<'r, R::Database> + sqlx::Type<R::Database>,
    for<'c> &'c str: sqlx::ColumnIndex<R>,
    U: FromStr,
    U::Err: std::error::Error + Send + Sync + 'static,
{
    fn column<'r, R, T, E>(
        row: &'r R,
        table: &TableName,
        column: &str,
        parse: impl FnOnce(&'r str) -> Result<T, E>,
    ) -> Result<T, sqlx::Error>
    where
        R: Row,
        &'r str: sqlx::Decode<'r, R::Database> + sqlx::Type<R::Database>,
        for<'c> &'c str: sqlx::ColumnIndex<R>,
        E: std::error::Error + Send + Sync + 'static,
    {
        parse(row.try_get(column)?).map_err(|e| sqlx::Error::ColumnDecode {
            index: format!("{}.{column}", table.as_str()),
            source: Box::new(e),
        })
    }
    Ok(Session {
        user_id: column(row, table, "user_id", str::parse)?,
        created_at: column(row, table, "created_at", parse_stamp)?,
        expires_at: column(row, table, "expires_at", parse_stamp)?,
        proved_at: column(row, table, "proved_at", parse_stamp)?,
        reauthenticated_at: column(row, table, "reauthenticated_at", parse_stamp)?,
    })
}

macro_rules! session_store_for {
    ($db:ty) => {
        impl<U> SessionStore for SqlSessionStore<$db, U>
        where
            U: fmt::Display + FromStr + Send + Sync,
            U::Err: std::error::Error + Send + Sync + 'static,
        {
            type UserId = U;
            type Error = sqlx::Error;

            async fn insert(
                &self,
                hash: &TokenHash,
                session: &Session<U>,
            ) -> Result<(), sqlx::Error> {
                sqlx::query(&self.queries.insert)
                    .bind(hash.as_str())
                    .bind(session.user_id.to_string())
                    .bind(stamp(session.created_at))
                    .bind(stamp(session.expires_at))
                    .bind(stamp(session.proved_at))
                    .bind(stamp(session.reauthenticated_at))
                    .execute(&self.pool)
                    .await?;
                Ok(())
            }

            async fn find(
                &self,
                hash: &TokenHash,
                now: DateTime<Utc>,
            ) -> Result<Option<Session<U>>, sqlx::Error> {
                sqlx::query(&self.queries.find)
                    .bind(hash.as_str())
                    .bind(stamp(now))
                    .fetch_optional(&self.pool)
                    .await?
                    .map(|row| session_from(&row, &self.queries.table))
                    .transpose()
            }

            async fn set_reauthenticated_at(
                &self,
                hash: &TokenHash,
                at: DateTime<Utc>,
            ) -> Result<bool, sqlx::Error> {
                let done = sqlx::query(&self.queries.set_reauthenticated_at)
                    .bind(stamp(at))
                    .bind(hash.as_str())
                    .execute(&self.pool)
                    .await?;
                Ok(done.rows_affected() > 0)
            }

            async fn remove(&self, hash: &TokenHash) -> Result<bool, sqlx::Error> {
                let done = sqlx::query(&self.queries.remove)
                    .bind(hash.as_str())
                    .execute(&self.pool)
                    .await?;
                Ok(done.rows_affected() > 0)
            }

            async fn remove_user(&self, user_id: &U) -> Result<bool, sqlx::Error> {
                let done = sqlx::query(&self.queries.remove_user)
                    .bind(user_id.to_string())
                    .execute(&self.pool)
                    .await?;
                Ok(done.rows_affected() > 0)
            }

            async fn remove_expired(&self, now: DateTime<Utc>) -> Result<(), sqlx::Error> {
                sqlx::query(&self.queries.remove_expired)
                    .bind(stamp(now))
                    .execute(&self.pool)
                    .await?;
                Ok(())
            }
        }
    };
}

#[cfg(feature = "sqlite")]
session_store_for!(sqlx::Sqlite);

#[cfg(feature = "postgres")]
session_store_for!(sqlx::Postgres);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_plain_identifier_names_the_table() {
        for good in ["app_sessions", "_s", "S1"] {
            assert_eq!(TableName::parse(good).unwrap().as_str(), good);
        }
        for bad in [
            "",
            "1s",
            "s-1",
            "s;drop",
            "main.s",
            "\"s\"",
            &"s".repeat(64),
        ] {
            assert_eq!(
                TableName::parse(bad).unwrap_err(),
                InvalidTableName(bad.to_owned())
            );
        }
    }

    #[test]
    #[should_panic(expected = "not a plain table name")]
    fn an_invalid_name_outside_a_const_panics() {
        let _ = TableName::new(std::hint::black_box("s;drop"));
    }

    #[test]
    fn stamps_are_fixed_width_utc_micros_and_read_back() {
        let at = parse_stamp("2026-10-21T01:02:03Z").unwrap();
        assert_eq!(stamp(at), "2026-10-21T01:02:03.000000Z");
        assert_eq!(parse_stamp(&stamp(at)), Ok(at));
    }
}

#[cfg(all(test, feature = "sqlite"))]
mod sqlite_tests {
    use std::time::Duration;

    use chrono::TimeDelta;
    use sqlx::sqlite::SqlitePoolOptions;

    use super::*;
    use crate::{Proof, SessionError, SessionToken, Sessions};

    const DDL: &str = "CREATE TABLE app_sessions (
        token_hash          TEXT PRIMARY KEY NOT NULL,
        user_id             TEXT NOT NULL,
        created_at          TEXT NOT NULL,
        expires_at          TEXT NOT NULL,
        proved_at           TEXT NOT NULL,
        reauthenticated_at  TEXT NOT NULL
    ) STRICT";

    async fn store<U>(table: &'static str) -> SqliteSessionStore<U> {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .idle_timeout(None)
            .max_lifetime(None)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::query(&DDL.replace("app_sessions", table))
            .execute(&pool)
            .await
            .unwrap();
        SqliteSessionStore::new(pool, TableName::new(table))
    }

    async fn sessions() -> Sessions<SqliteSessionStore<String>> {
        Sessions::new(store("app_sessions").await)
    }

    async fn issue(sessions: &Sessions<SqliteSessionStore<String>>, user_id: &str) -> SessionToken {
        sessions
            .issue(user_id.to_owned(), Proof::begin())
            .await
            .unwrap()
            .0
    }

    async fn rows(sessions: &Sessions<SqliteSessionStore<String>>) -> i64 {
        sqlx::query_scalar("SELECT count(*) FROM app_sessions")
            .fetch_one(sessions.store().pool())
            .await
            .unwrap()
    }

    fn a_moment_passes() {
        std::thread::sleep(Duration::from_millis(2));
    }

    #[tokio::test]
    async fn the_calls_can_be_awaited_in_a_spawned_task() {
        let sessions = sessions().await;
        tokio::spawn(async move {
            let token = issue(&sessions, "u1").await;
            sessions.lookup(&token).await.unwrap()
        })
        .await
        .unwrap()
        .unwrap();
    }

    #[tokio::test]
    async fn an_issued_session_is_found_by_its_token_and_only_its_hash_is_kept() {
        let sessions = sessions().await;
        let proof = Proof::begin();
        a_moment_passes();
        let (token, issued) = sessions.issue("u1".to_owned(), proof).await.unwrap();
        assert_eq!(issued.expires_at - issued.created_at, TimeDelta::hours(12));
        assert_eq!(issued.proved_at, proof.at());
        assert!(issued.created_at > issued.proved_at);
        assert_eq!(sessions.lookup(&token).await.unwrap(), Some(issued));

        let stored: String = sqlx::query_scalar("SELECT token_hash FROM app_sessions")
            .fetch_one(sessions.store().pool())
            .await
            .unwrap();
        assert_eq!(stored, token.hash().as_str());
        assert_ne!(stored, token.expose());

        let stranger = SessionToken::generate().unwrap();
        assert_eq!(sessions.lookup(&stranger).await.unwrap(), None);
    }

    #[tokio::test]
    async fn a_proof_begun_before_the_cutoff_is_refused_though_issued_after_it() {
        let sessions = sessions().await;
        let proof = Proof::begin();
        a_moment_passes();
        let sessions_valid_from = crate::now();
        a_moment_passes();
        let (_, session) = sessions.issue("u1".to_owned(), proof).await.unwrap();
        assert!(session.created_at > sessions_valid_from);
        assert!(!session.proved_since(sessions_valid_from));
        assert!(session.proved_since(proof.at()));
    }

    #[tokio::test]
    async fn an_expired_session_is_not_found_and_goes_at_the_next_issue() {
        let sessions = sessions().await.with_lifetime(TimeDelta::zero());
        let expired = issue(&sessions, "u1").await;
        assert_eq!(sessions.lookup(&expired).await.unwrap(), None);
        assert_eq!(rows(&sessions).await, 1);

        let sessions = sessions.with_lifetime(TimeDelta::hours(1));
        let live = issue(&sessions, "u1").await;
        assert_eq!(rows(&sessions).await, 1, "the expired row went");
        assert!(sessions.lookup(&live).await.unwrap().is_some());

        sessions
            .store()
            .remove_expired(crate::now() + TimeDelta::hours(2))
            .await
            .unwrap();
        assert_eq!(rows(&sessions).await, 0);
    }

    #[tokio::test]
    async fn ending_one_session_leaves_the_others_and_ending_all_leaves_other_users() {
        let sessions = sessions().await;
        let a1 = issue(&sessions, "a").await;
        let a2 = issue(&sessions, "a").await;
        let b = issue(&sessions, "b").await;

        assert!(sessions.end(&a1).await.unwrap());
        assert!(!sessions.end(&a1).await.unwrap(), "already ended");
        assert_eq!(sessions.lookup(&a1).await.unwrap(), None);
        assert!(sessions.lookup(&a2).await.unwrap().is_some());

        assert!(sessions.end_all(&"a".to_owned()).await.unwrap());
        assert!(!sessions.end_all(&"a".to_owned()).await.unwrap());
        assert_eq!(sessions.lookup(&a2).await.unwrap(), None);
        assert!(sessions.lookup(&b).await.unwrap().is_some());
    }

    #[tokio::test]
    async fn reauthenticating_stamps_the_proofs_instant_and_nothing_else() {
        let sessions = sessions().await;
        let (token, issued) = sessions
            .issue("u1".to_owned(), Proof::begin())
            .await
            .unwrap();
        let earlier = issued.created_at - TimeDelta::minutes(10);
        sessions
            .store()
            .set_reauthenticated_at(&token.hash(), earlier)
            .await
            .unwrap();
        let stale = sessions.lookup(&token).await.unwrap().unwrap();
        assert!(!stale.reauthenticated_within(crate::REAUTHENTICATION_WINDOW, crate::now()));

        let proof = Proof::begin();
        a_moment_passes();
        assert!(sessions.reauthenticated(&token, proof).await.unwrap());
        let fresh = sessions.lookup(&token).await.unwrap().unwrap();
        assert_eq!(fresh.reauthenticated_at, proof.at());
        assert_eq!(
            Session {
                reauthenticated_at: issued.reauthenticated_at,
                ..fresh
            },
            issued
        );

        let stranger = SessionToken::generate().unwrap();
        assert!(!sessions.reauthenticated(&stranger, proof).await.unwrap());
    }

    #[tokio::test]
    async fn a_user_id_reads_back_through_from_str_and_a_bad_one_names_its_column() {
        let sessions = Sessions::new(store::<u64>("s").await);
        let (token, _) = sessions.issue(42, Proof::begin()).await.unwrap();
        assert_eq!(sessions.lookup(&token).await.unwrap().unwrap().user_id, 42);

        sqlx::query("UPDATE s SET user_id = 'x'")
            .execute(sessions.store().pool())
            .await
            .unwrap();
        let Err(SessionError::Store(sqlx::Error::ColumnDecode { index, .. })) =
            sessions.lookup(&token).await
        else {
            panic!("a decode error");
        };
        assert_eq!(index, "s.user_id");
    }
}
