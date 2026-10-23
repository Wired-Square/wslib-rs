//! A flat key/value table of strings, for what an app keeps after it has a database.
//!
//! Keys are dotted and namespaced by the part of the app that owns them —
//! `branding.app_name` — and each is a const where it is owned.
//!
//! The crate does not create the table; an app's own migration does:
//!
//! ```sql
//! CREATE TABLE settings (
//!     key        TEXT PRIMARY KEY NOT NULL,
//!     value      TEXT NOT NULL,
//!     updated_at TEXT NOT NULL
//! ) STRICT;
//! ```
//!
//! # Two namespaces are reserved
//!
//! - **Secrets**, stored as `secret.<name>`, go through [`Settings::secret`]
//!   and its siblings, by the bare name, and are never exported.
//! - **Local state** that describes this installation rather than how it is
//!   configured (when a task last ran, a change awaiting confirmation), stored
//!   as `local.<name>` or under [`Settings::local_prefix`], goes through
//!   [`Settings::local`] and its siblings, and is never exported nor touched by
//!   a restore.
//!
//! [`Settings::setting`] and [`Settings::set_setting`] refuse a key in either
//! ([`Error::Reserved`]), so the namespace's own calls are the only way in or
//! out. Raw SQL through [`Database::pool`] still sees the rows, and the stored
//! prefixes are part of the table's contract.
//!
//! # A change is announced
//!
//! [`Settings::changed`] sees each [`Settings::set_setting`] and
//! [`Settings::set_setting_doc`] through this `Settings` or a clone of it, and
//! each [`Settings::replaced`]. A secret or local write is not a change. Raw SQL,
//! another process, and a `Settings` made by another [`Settings::new`] are not
//! seen: make one and clone it.

use std::collections::BTreeMap;
use std::sync::Arc;

use serde::Serialize;
use serde::de::DeserializeOwned;
use sqlx::sqlite::SqlitePool;
use sqlx::{Sqlite, SqliteExecutor, Transaction};
use tokio::sync::watch;
use wslib_secret::Secret;

use crate::{Database, Error, is_plain_name, stamp};

const SECRET_PREFIX: &str = "secret.";

/// The settings table of a [`Database`].
#[derive(Debug, Clone)]
pub struct Settings {
    pool: SqlitePool,
    table: String,
    local_prefix: String,
    changed: Arc<watch::Sender<u64>>,
}

impl Settings {
    /// The table `settings`, with local state under `local.`.
    pub fn new(db: &Database) -> Self {
        Self {
            pool: db.pool().clone(),
            table: "settings".to_string(),
            local_prefix: "local.".to_string(),
            changed: Arc::new(watch::Sender::new(0)),
        }
    }

    /// Use the table `name`, which is `[a-z][a-z0-9_]*`.
    pub fn table(mut self, name: &str) -> Result<Self, Error> {
        if !is_plain_name(name) {
            return Err(Error::InvalidName(name.to_string()));
        }
        self.table = name.to_string();
        Ok(self)
    }

    /// Store local state under `prefix`, which ends in `.` and does not overlap `secret.`.
    pub fn local_prefix(mut self, prefix: &str) -> Result<Self, Error> {
        let overlaps = prefix.starts_with(SECRET_PREFIX) || SECRET_PREFIX.starts_with(prefix);
        if !prefix.ends_with('.') || overlaps {
            return Err(Error::LocalPrefix(prefix.to_string()));
        }
        self.local_prefix = prefix.to_string();
        Ok(self)
    }

    /// The one rule for what is never exported or replaced, in Rust rather
    /// than SQL: SQLite's `LIKE` is case-insensitive, so `SECRET.x` would be
    /// reserved to a query and not to a write, and become a row nothing reads.
    fn is_reserved(&self, key: &str) -> bool {
        key.starts_with(SECRET_PREFIX) || key.starts_with(&self.local_prefix)
    }

    fn reject_reserved(&self, key: &str) -> Result<(), Error> {
        if self.is_reserved(key) {
            return Err(Error::Reserved(key.to_string()));
        }
        Ok(())
    }

    fn local_key(&self, name: &str) -> String {
        format!("{}{name}", self.local_prefix)
    }

    /// Every setting that may be exported: no secret and no local state.
    pub async fn exportable(&self) -> Result<BTreeMap<String, String>, Error> {
        let rows: Vec<(String, String)> = sqlx::query_as(&format!(
            "SELECT key, value FROM {} ORDER BY key",
            self.table
        ))
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .filter(|(key, _)| !self.is_reserved(key))
            .collect())
    }

    /// Replace every exportable setting with `rows`, inside `tx`; call
    /// [`Settings::replaced`] once it commits.
    ///
    /// Secrets and local state are neither deleted nor written: a carried
    /// reserved key is skipped with a warning. Carried settings replace rather
    /// than merge, so a key removed at the source is removed here.
    pub async fn replace_exportable(
        &self,
        tx: &mut Transaction<'_, Sqlite>,
        rows: &BTreeMap<String, String>,
    ) -> Result<(), Error> {
        // Read then delete, so one `is_reserved` decides what goes and what may come back.
        let existing: Vec<String> = sqlx::query_scalar(&format!("SELECT key FROM {}", self.table))
            .fetch_all(&mut **tx)
            .await?;
        for key in existing.iter().filter(|key| !self.is_reserved(key)) {
            sqlx::query(&format!("DELETE FROM {} WHERE key = ?", self.table))
                .bind(key)
                .execute(&mut **tx)
                .await?;
        }
        for (key, value) in rows {
            if self.is_reserved(key) {
                tracing::warn!(
                    key = for_the_log(key),
                    "an import carried a key in a reserved namespace; it was not applied"
                );
                continue;
            }
            self.write(&mut **tx, key, value).await?;
        }
        Ok(())
    }

    pub async fn setting(&self, key: &str) -> Result<Option<String>, Error> {
        self.reject_reserved(key)?;
        self.read(&self.pool, key).await
    }

    /// A setting as a JSON document; absent or unparseable is `T::default()`,
    /// the second with a warning naming the key.
    pub async fn setting_doc<T: DeserializeOwned + Default>(&self, key: &str) -> Result<T, Error> {
        self.reject_reserved(key)?;
        self.read_doc(key).await
    }

    /// Write a setting, replacing whatever was there.
    pub async fn set_setting(&self, key: &str, value: &str) -> Result<(), Error> {
        self.reject_reserved(key)?;
        self.write(&self.pool, key, value).await?;
        self.replaced();
        Ok(())
    }

    pub async fn set_setting_doc<T: Serialize>(&self, key: &str, value: &T) -> Result<(), Error> {
        self.reject_reserved(key)?;
        self.write_doc(key, value).await?;
        self.replaced();
        Ok(())
    }

    /// A receiver that changes after each settings write; it keeps only the
    /// latest, so a reader re-reads every setting it holds.
    pub fn changed(&self) -> watch::Receiver<u64> {
        self.changed.subscribe()
    }

    /// Announce a change [`Settings::changed`] cannot see, once it has committed:
    /// a restore, or configuration an app keeps in its own tables.
    pub fn replaced(&self) {
        self.changed
            .send_modify(|generation| *generation = generation.wrapping_add(1));
    }

    /// Read local state by its bare name — `"backup.last_run"`.
    pub async fn local(&self, name: &str) -> Result<Option<String>, Error> {
        self.read(&self.pool, &self.local_key(name)).await
    }

    /// [`Settings::local`] as a JSON document, with [`Settings::setting_doc`]'s answers.
    pub async fn local_doc<T: DeserializeOwned + Default>(&self, name: &str) -> Result<T, Error> {
        self.read_doc(&self.local_key(name)).await
    }

    pub async fn set_local(&self, name: &str, value: &str) -> Result<(), Error> {
        self.write(&self.pool, &self.local_key(name), value).await
    }

    pub async fn set_local_doc<T: Serialize>(&self, name: &str, value: &T) -> Result<(), Error> {
        self.write_doc(&self.local_key(name), value).await
    }

    pub async fn clear_local(&self, name: &str) -> Result<(), Error> {
        self.delete(&self.pool, &self.local_key(name)).await
    }

    /// Read a secret by its bare name — `"backup.passphrase"`.
    pub async fn secret(&self, name: &str) -> Result<Option<Secret>, Error> {
        Ok(self
            .read(&self.pool, &secret_key(name))
            .await?
            .map(Secret::new))
    }

    pub async fn secret_in(
        &self,
        tx: &mut Transaction<'_, Sqlite>,
        name: &str,
    ) -> Result<Option<Secret>, Error> {
        Ok(self
            .read(&mut **tx, &secret_key(name))
            .await?
            .map(Secret::new))
    }

    /// The bare names of the stored secrets starting with the bare `prefix`, sorted.
    pub async fn secret_names(&self, prefix: &str) -> Result<Vec<String>, Error> {
        let start = secret_key(prefix);
        let keys: Vec<String> = sqlx::query_scalar(&format!(
            "SELECT key FROM {} WHERE key >= ? ORDER BY key",
            self.table
        ))
        .bind(&start)
        .fetch_all(&self.pool)
        .await?;
        Ok(keys
            .iter()
            .map_while(|key| key.strip_prefix(&start))
            .map(|rest| format!("{prefix}{rest}"))
            .collect())
    }

    pub async fn set_secret(&self, name: &str, value: &Secret) -> Result<(), Error> {
        self.write(&self.pool, &secret_key(name), value.expose())
            .await
    }

    pub async fn set_secret_in(
        &self,
        tx: &mut Transaction<'_, Sqlite>,
        name: &str,
        value: &Secret,
    ) -> Result<(), Error> {
        self.write(&mut **tx, &secret_key(name), value.expose())
            .await
    }

    pub async fn clear_secret(&self, name: &str) -> Result<(), Error> {
        self.delete(&self.pool, &secret_key(name)).await
    }

    pub async fn clear_secret_in(
        &self,
        tx: &mut Transaction<'_, Sqlite>,
        name: &str,
    ) -> Result<(), Error> {
        self.delete(&mut **tx, &secret_key(name)).await
    }

    /// Write a secret only if none is stored, and answer the one that is, so
    /// two callers generating one at once are both handed the one that landed.
    pub async fn init_secret(&self, name: &str, value: &Secret) -> Result<Secret, Error> {
        // The no-op `DO UPDATE` is what makes `RETURNING` answer the existing row.
        let landed: String = sqlx::query_scalar(&format!(
            "INSERT INTO {} (key, value, updated_at) VALUES (?, ?, ?) \
             ON CONFLICT (key) DO UPDATE SET value = value RETURNING value",
            self.table
        ))
        .bind(secret_key(name))
        .bind(value.expose())
        .bind(stamp::format(stamp::now()))
        .fetch_one(&self.pool)
        .await?;
        Ok(Secret::new(landed))
    }

    async fn read_doc<T: DeserializeOwned + Default>(&self, key: &str) -> Result<T, Error> {
        let Some(raw) = self.read(&self.pool, key).await? else {
            return Ok(T::default());
        };
        Ok(serde_json::from_str(&raw).unwrap_or_else(|e| {
            tracing::warn!(key, error = %e, "a stored document will not parse; using its default");
            T::default()
        }))
    }

    async fn write_doc<T: Serialize>(&self, key: &str, value: &T) -> Result<(), Error> {
        let raw = serde_json::to_string(value).map_err(|source| Error::Serialise {
            key: key.to_string(),
            source,
        })?;
        self.write(&self.pool, key, &raw).await
    }

    async fn read<'e>(
        &self,
        db: impl SqliteExecutor<'e>,
        key: &str,
    ) -> Result<Option<String>, Error> {
        Ok(
            sqlx::query_scalar(&format!("SELECT value FROM {} WHERE key = ?", self.table))
                .bind(key)
                .fetch_optional(db)
                .await?,
        )
    }

    async fn write<'e>(
        &self,
        db: impl SqliteExecutor<'e>,
        key: &str,
        value: &str,
    ) -> Result<(), Error> {
        sqlx::query(&format!(
            "INSERT INTO {} (key, value, updated_at) VALUES (?, ?, ?) \
             ON CONFLICT (key) DO UPDATE SET value = excluded.value, \
             updated_at = excluded.updated_at",
            self.table
        ))
        .bind(key)
        .bind(value)
        .bind(stamp::format(stamp::now()))
        .execute(db)
        .await?;
        Ok(())
    }

    async fn delete<'e>(&self, db: impl SqliteExecutor<'e>, key: &str) -> Result<(), Error> {
        sqlx::query(&format!("DELETE FROM {} WHERE key = ?", self.table))
            .bind(key)
            .execute(db)
            .await?;
        Ok(())
    }
}

fn secret_key(name: &str) -> String {
    format!("{SECRET_PREFIX}{name}")
}

/// A key out of someone else's file, cut to log by characters: a byte slice
/// panics inside a multi-byte character, and a field expression in `tracing`
/// is only evaluated when a subscriber is installed, which no test does.
fn for_the_log(key: &str) -> String {
    key.chars().take(64).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_carried_key_is_cut_for_the_log_by_characters_not_bytes() {
        let crafted = format!("{SECRET_PREFIX}{}é{}", "x".repeat(56), "y".repeat(10));
        assert!(!crafted.is_char_boundary(64), "the plant must straddle one");

        let logged = for_the_log(&crafted);
        assert_eq!(logged.chars().count(), 64);
        assert!(crafted.starts_with(&logged));
    }

    #[tokio::test]
    async fn the_namespaces_are_matched_case_sensitively_and_end_at_their_dot() {
        let db = Database::open_in_memory(&[]).await.unwrap();
        let settings = Settings::new(&db);
        assert!(settings.is_reserved("secret.sample"));
        assert!(!settings.is_reserved("SECRET.sample"));
        assert!(!settings.is_reserved("Secret.sample"));
        assert!(settings.is_reserved("local.backup.last_run"));
        assert!(!settings.is_reserved("LOCAL.backup.last_run"));
        assert!(!settings.is_reserved("locals.count"));
        assert!(!settings.is_reserved("secrets.enabled"));

        let settings = settings.local_prefix("here.").unwrap();
        assert!(settings.is_reserved("here.backup.last_run"));
        assert!(!settings.is_reserved("local.backup.last_run"));
    }
}
