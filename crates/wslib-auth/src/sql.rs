use std::borrow::Cow;
use std::fmt;
use std::marker::PhantomData;
use std::str::FromStr;

use chrono::{DateTime, Utc};
use sqlx::{Database, Pool, Row};

use crate::session::{BoundSecretStore, Session, SessionStore, parse_stamp, stamp};
use crate::token::TokenHash;

/// A [`SessionStore`] in a table of the caller's, on a sqlx pool; the README carries its DDL.
///
/// Times are stored as [`stamp`]s. The user id is stored as its `Display` and
/// read back with `FromStr`. It is a [`BoundSecretStore`] once given a second
/// table with [`with_bound_secrets`](Self::with_bound_secrets); until then its
/// calls fail with `sqlx::Error::Configuration`.
pub struct SqlSessionStore<DB: Database, U> {
    pool: Pool<DB>,
    queries: Queries,
    bound: Option<BoundQueries>,
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
            bound: self.bound.clone(),
            user_id: PhantomData,
        }
    }
}

impl<DB: Database, U> fmt::Debug for SqlSessionStore<DB, U> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SqlSessionStore")
            .field("table", &self.queries.table)
            .field(
                "bound_secrets",
                &self.bound.as_ref().map(|bound| &bound.table),
            )
            .finish_non_exhaustive()
    }
}

impl<DB: Database, U> SqlSessionStore<DB, U> {
    /// Sessions in `table` of `pool`'s database.
    pub fn new(pool: Pool<DB>, table: TableName) -> Self {
        Self {
            pool,
            queries: Queries::for_table(table),
            bound: None,
            user_id: PhantomData,
        }
    }

    /// Secrets bound to the sessions in `table`, whose rows reference the
    /// sessions table with `ON DELETE CASCADE`; the README carries its DDL.
    pub fn with_bound_secrets(self, table: TableName) -> Self {
        Self {
            bound: Some(BoundQueries::for_tables(&self.queries.table, table)),
            ..self
        }
    }

    fn bound_queries(&self) -> Result<&BoundQueries, sqlx::Error> {
        self.bound.as_ref().ok_or_else(|| {
            sqlx::Error::Configuration("no table for bound secrets: call with_bound_secrets".into())
        })
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

#[derive(Debug, Clone)]
struct BoundQueries {
    table: TableName,
    insert: String,
    prune: String,
    select: String,
}

impl BoundQueries {
    fn for_tables(sessions: &TableName, table: TableName) -> Self {
        let (sessions, name) = (sessions.as_str(), table.as_str());
        Self {
            insert: format!(
                "INSERT INTO {name} (session_hash, secret_hash, issued_at) \
                 SELECT token_hash, $2, $3 FROM {sessions} \
                 WHERE token_hash = $1 AND expires_at > $3"
            ),
            prune: format!(
                "DELETE FROM {name} WHERE session_hash = $1 AND secret_hash NOT IN \
                 (SELECT secret_hash FROM {name} WHERE session_hash = $1 \
                 ORDER BY issued_at DESC, secret_hash DESC LIMIT $2)"
            ),
            select: format!("SELECT secret_hash FROM {name} WHERE session_hash = $1"),
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
        impl<U: fmt::Display> SqlSessionStore<$db, U> {
            /// [`SessionStore::remove_user`] inside the caller's transaction.
            pub async fn remove_user_in(
                &self,
                tx: &mut sqlx::Transaction<'_, $db>,
                user_id: &U,
            ) -> Result<bool, sqlx::Error> {
                self.remove_user_on(&mut **tx, user_id).await
            }

            async fn remove_user_on<'e>(
                &self,
                executor: impl sqlx::Executor<'e, Database = $db>,
                user_id: &U,
            ) -> Result<bool, sqlx::Error> {
                let done = sqlx::query(&self.queries.remove_user)
                    .bind(user_id.to_string())
                    .execute(executor)
                    .await?;
                Ok(done.rows_affected() > 0)
            }
        }

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
                self.remove_user_on(&self.pool, user_id).await
            }

            async fn remove_expired(&self, now: DateTime<Utc>) -> Result<(), sqlx::Error> {
                sqlx::query(&self.queries.remove_expired)
                    .bind(stamp(now))
                    .execute(&self.pool)
                    .await?;
                Ok(())
            }
        }

        impl<U> BoundSecretStore for SqlSessionStore<$db, U>
        where
            U: fmt::Display + FromStr + Send + Sync,
            U::Err: std::error::Error + Send + Sync + 'static,
        {
            async fn bind_secret(
                &self,
                session: &TokenHash,
                secret: &TokenHash,
                at: DateTime<Utc>,
                keep: usize,
            ) -> Result<bool, sqlx::Error> {
                let queries = self.bound_queries()?;
                let mut tx = self.pool.begin().await?;
                let inserted = match sqlx::query(&queries.insert)
                    .bind(session.as_str())
                    .bind(secret.as_str())
                    .bind(stamp(at))
                    .execute(&mut *tx)
                    .await
                {
                    // The session went after the insert read it.
                    Err(sqlx::Error::Database(e)) if e.is_foreign_key_violation() => {
                        return Ok(false);
                    }
                    inserted => inserted?,
                };
                sqlx::query(&queries.prune)
                    .bind(session.as_str())
                    .bind(i64::try_from(keep).unwrap_or(i64::MAX))
                    .execute(&mut *tx)
                    .await?;
                tx.commit().await?;
                Ok(inserted.rows_affected() > 0)
            }

            async fn bound_secrets(
                &self,
                session: &TokenHash,
            ) -> Result<Vec<TokenHash>, sqlx::Error> {
                let hashes: Vec<String> = sqlx::query_scalar(&self.bound_queries()?.select)
                    .bind(session.as_str())
                    .fetch_all(&self.pool)
                    .await?;
                Ok(hashes.into_iter().map(TokenHash::from_stored).collect())
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

#[cfg(test)]
mod store_tests;
