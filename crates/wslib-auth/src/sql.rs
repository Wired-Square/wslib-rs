use std::fmt;
use std::marker::PhantomData;
use std::str::FromStr;

use chrono::{DateTime, SecondsFormat, Utc};
use sqlx::{Database, Pool, Row};

use crate::session::{Session, SessionStore};
use crate::token::TokenHash;

/// A [`SessionStore`] in a table of the caller's, on a sqlx pool; the README carries its DDL.
///
/// Times are stored as fixed-width RFC 3339 text, UTC with six subsecond
/// digits, so they compare as text in time order. The user id is stored as
/// its `Display` and read back with `FromStr`.
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
    pub fn new(pool: Pool<DB>, table: &str) -> Result<Self, InvalidTableName> {
        Ok(Self {
            pool,
            queries: Queries::for_table(table)?,
            user_id: PhantomData,
        })
    }

    pub fn pool(&self) -> &Pool<DB> {
        &self.pool
    }
}

#[derive(Debug, Clone)]
struct Queries {
    table: String,
    insert: String,
    find: String,
    set_reauthenticated_at: String,
    remove: String,
    remove_user: String,
    remove_expired: String,
}

impl Queries {
    fn for_table(table: &str) -> Result<Self, InvalidTableName> {
        if !is_plain_identifier(table) {
            return Err(InvalidTableName(table.to_owned()));
        }
        Ok(Self {
            table: table.to_owned(),
            insert: format!(
                "INSERT INTO {table} \
                 (token_hash, user_id, created_at, expires_at, reauthenticated_at) \
                 VALUES ($1, $2, $3, $4, $5)"
            ),
            find: format!(
                "SELECT user_id, created_at, expires_at, reauthenticated_at FROM {table} \
                 WHERE token_hash = $1 AND expires_at > $2"
            ),
            set_reauthenticated_at: format!(
                "UPDATE {table} SET reauthenticated_at = $1 WHERE token_hash = $2"
            ),
            remove: format!("DELETE FROM {table} WHERE token_hash = $1"),
            remove_user: format!("DELETE FROM {table} WHERE user_id = $1"),
            remove_expired: format!("DELETE FROM {table} WHERE expires_at <= $1"),
        })
    }
}

fn is_plain_identifier(name: &str) -> bool {
    let mut bytes = name.bytes();
    bytes
        .next()
        .is_some_and(|b| b.is_ascii_alphabetic() || b == b'_')
        && bytes.all(|b| b.is_ascii_alphanumeric() || b == b'_')
        && name.len() <= 63
}

/// A table name that is not a plain identifier: an ASCII letter or `_`, then
/// letters, digits or `_`, at most 63 bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidTableName(pub String);

impl fmt::Display for InvalidTableName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?} is not a plain table name", self.0)
    }
}

impl std::error::Error for InvalidTableName {}

fn stamp(at: DateTime<Utc>) -> String {
    at.to_rfc3339_opts(SecondsFormat::Micros, true)
}

fn decoded<T, E>(value: Result<T, E>) -> Result<T, sqlx::Error>
where
    E: std::error::Error + Send + Sync + 'static,
{
    value.map_err(|e| sqlx::Error::Decode(Box::new(e)))
}

fn session_from<R, U>(row: &R) -> Result<Session<U>, sqlx::Error>
where
    R: Row,
    for<'r> &'r str: sqlx::Decode<'r, R::Database> + sqlx::Type<R::Database>,
    for<'c> &'c str: sqlx::ColumnIndex<R>,
    U: FromStr,
    U::Err: std::error::Error + Send + Sync + 'static,
{
    let time = |column: &str| -> Result<DateTime<Utc>, sqlx::Error> {
        let raw: &str = row.try_get(column)?;
        decoded(DateTime::parse_from_rfc3339(raw)).map(|at| at.with_timezone(&Utc))
    };
    Ok(Session {
        user_id: decoded(row.try_get::<&str, _>("user_id")?.parse())?,
        created_at: time("created_at")?,
        expires_at: time("expires_at")?,
        reauthenticated_at: time("reauthenticated_at")?,
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
                    .map(|row| session_from(&row))
                    .transpose()
            }

            async fn set_reauthenticated_at(
                &self,
                hash: &TokenHash,
                at: DateTime<Utc>,
            ) -> Result<(), sqlx::Error> {
                sqlx::query(&self.queries.set_reauthenticated_at)
                    .bind(stamp(at))
                    .bind(hash.as_str())
                    .execute(&self.pool)
                    .await?;
                Ok(())
            }

            async fn remove(&self, hash: &TokenHash) -> Result<(), sqlx::Error> {
                sqlx::query(&self.queries.remove)
                    .bind(hash.as_str())
                    .execute(&self.pool)
                    .await?;
                Ok(())
            }

            async fn remove_user(&self, user_id: &U) -> Result<(), sqlx::Error> {
                sqlx::query(&self.queries.remove_user)
                    .bind(user_id.to_string())
                    .execute(&self.pool)
                    .await?;
                Ok(())
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
            assert!(Queries::for_table(good).is_ok(), "{good}");
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
                Queries::for_table(bad).unwrap_err(),
                InvalidTableName(bad.to_owned())
            );
        }
    }

    #[test]
    fn stamps_are_fixed_width_utc_micros() {
        let at = DateTime::parse_from_rfc3339("2026-10-21T01:02:03Z")
            .unwrap()
            .with_timezone(&Utc);
        assert_eq!(stamp(at), "2026-10-21T01:02:03.000000Z");
    }
}

#[cfg(all(test, feature = "sqlite"))]
mod sqlite_tests {
    use chrono::TimeDelta;
    use sqlx::sqlite::SqlitePoolOptions;

    use super::*;
    use crate::{SessionToken, Sessions};

    const DDL: &str = "CREATE TABLE app_sessions (
        token_hash          TEXT PRIMARY KEY NOT NULL,
        user_id             TEXT NOT NULL,
        created_at          TEXT NOT NULL,
        expires_at          TEXT NOT NULL,
        reauthenticated_at  TEXT NOT NULL
    ) STRICT";

    async fn store<U>(table: &str) -> SqliteSessionStore<U> {
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
        SqliteSessionStore::new(pool, table).unwrap()
    }

    async fn sessions() -> Sessions<SqliteSessionStore<String>> {
        Sessions::new(store("app_sessions").await)
    }

    async fn rows(sessions: &Sessions<SqliteSessionStore<String>>) -> i64 {
        sqlx::query_scalar("SELECT count(*) FROM app_sessions")
            .fetch_one(sessions.store().pool())
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn the_calls_can_be_awaited_in_a_spawned_task() {
        let sessions = sessions().await;
        tokio::spawn(async move {
            let (token, _) = sessions.issue("u1".to_owned()).await.unwrap();
            sessions.lookup(&token).await.unwrap()
        })
        .await
        .unwrap()
        .unwrap();
    }

    #[tokio::test]
    async fn an_issued_session_is_found_by_its_token_and_only_its_hash_is_kept() {
        let sessions = sessions().await;
        let (token, issued) = sessions.issue("u1".to_owned()).await.unwrap();
        assert_eq!(issued.expires_at - issued.created_at, TimeDelta::hours(12));
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
    async fn an_expired_session_is_not_found_and_goes_at_the_next_issue() {
        let sessions = sessions().await.with_lifetime(TimeDelta::zero());
        let (expired, _) = sessions.issue("u1".to_owned()).await.unwrap();
        assert_eq!(sessions.lookup(&expired).await.unwrap(), None);
        assert_eq!(rows(&sessions).await, 1);

        let sessions = sessions.with_lifetime(TimeDelta::hours(1));
        let (live, _) = sessions.issue("u1".to_owned()).await.unwrap();
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
        let (a1, _) = sessions.issue("a".to_owned()).await.unwrap();
        let (a2, _) = sessions.issue("a".to_owned()).await.unwrap();
        let (b, _) = sessions.issue("b".to_owned()).await.unwrap();

        sessions.end(&a1).await.unwrap();
        assert_eq!(sessions.lookup(&a1).await.unwrap(), None);
        assert!(sessions.lookup(&a2).await.unwrap().is_some());

        sessions.end_all(&"a".to_owned()).await.unwrap();
        assert_eq!(sessions.lookup(&a2).await.unwrap(), None);
        assert!(sessions.lookup(&b).await.unwrap().is_some());
    }

    #[tokio::test]
    async fn reauthenticating_moves_the_stamp_and_nothing_else() {
        let sessions = sessions().await;
        let (token, issued) = sessions.issue("u1".to_owned()).await.unwrap();
        let earlier = issued.created_at - TimeDelta::minutes(10);
        sessions
            .store()
            .set_reauthenticated_at(&token.hash(), earlier)
            .await
            .unwrap();
        let stale = sessions.lookup(&token).await.unwrap().unwrap();
        assert!(!stale.reauthenticated_within(crate::REAUTHENTICATION_WINDOW, crate::now()));

        sessions.reauthenticated(&token).await.unwrap();
        let fresh = sessions.lookup(&token).await.unwrap().unwrap();
        assert!(fresh.reauthenticated_within(crate::REAUTHENTICATION_WINDOW, crate::now()));
        assert_eq!(
            (fresh.created_at, fresh.expires_at),
            (issued.created_at, issued.expires_at)
        );
    }

    #[tokio::test]
    async fn a_user_id_reads_back_through_from_str() {
        let sessions = Sessions::new(store::<u64>("s").await);
        let (token, _) = sessions.issue(42).await.unwrap();
        assert_eq!(sessions.lookup(&token).await.unwrap().unwrap().user_id, 42);

        sqlx::query("UPDATE s SET user_id = 'x'")
            .execute(sessions.store().pool())
            .await
            .unwrap();
        assert!(matches!(
            sessions.lookup(&token).await,
            Err(sqlx::Error::Decode(_))
        ));
    }
}
