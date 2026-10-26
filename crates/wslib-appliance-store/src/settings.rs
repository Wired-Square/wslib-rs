//! The key/value table of strings for everything operational, keyed by dotted
//! names owned by one place each: `branding.app_name`.
//!
//! # Two namespaces are reserved
//!
//! - **Secrets**, stored as `secret.<name>`, go through [`Store::secret`] and
//!   its siblings by the bare name, and never leave the box.
//! - **This box's own state** (when a task last ran, a change awaiting
//!   confirmation), stored as `box.<name>`, goes through [`Store::box_state`]
//!   and its siblings by the bare name; it is never exported, a restore
//!   neither deletes nor writes it, and a factory reset takes it.
//!
//! [`Store::setting`] and [`Store::set_setting`] refuse a key in either. Raw
//! SQL through [`Store::pool`] still sees the rows: the table's columns and
//! both stored prefixes are contract, and stay reserved for good.
//!
//! # A change is announced
//!
//! [`Store::settings_changed`] sees each [`Store::set_setting`] and
//! [`Store::set_setting_doc`] through this store or a clone of it, and each
//! [`Store::settings_replaced`]. A secret or box-state write is not a change.
//! Raw SQL and another process's `Store` are not seen.

use std::collections::BTreeMap;

use serde::Serialize;
use serde::de::DeserializeOwned;
use sqlx::{Sqlite, SqliteExecutor, Transaction};

use wslib_secret::Secret;

use crate::{Store, StoreError, now, stamp};

pub(crate) const SECRET_PREFIX: &str = "secret.";

pub(crate) const BOX_PREFIX: &str = "box.";

/// The one rule for what is never exported or replaced, in Rust rather than
/// SQL: SQLite's `LIKE` is case-insensitive, so `SECRET.x` would be reserved to
/// a query and not to a write, and become a row nothing reads.
fn is_reserved(key: &str) -> bool {
    [SECRET_PREFIX, BOX_PREFIX]
        .iter()
        .any(|prefix| key.starts_with(prefix))
}

fn secret_key(name: &str) -> String {
    format!("{SECRET_PREFIX}{name}")
}

fn box_key(name: &str) -> String {
    format!("{BOX_PREFIX}{name}")
}

/// A key out of someone else's file, cut to log by characters, never bytes.
fn for_the_log(key: &str) -> String {
    key.chars().take(64).collect()
}

impl Store {
    /// Every setting that may leave this box: no secret and no box state.
    pub async fn exportable_settings(&self) -> Result<BTreeMap<String, String>, StoreError> {
        let rows: Vec<(String, String)> =
            sqlx::query_as("SELECT key, value FROM settings ORDER BY key")
                .fetch_all(&self.pool)
                .await?;
        Ok(rows
            .into_iter()
            .filter(|(key, _)| !is_reserved(key))
            .collect())
    }

    /// Replace every exportable setting with `rows`, inside `tx`; call
    /// [`Store::settings_replaced`] once it commits.
    ///
    /// Secrets and box state are neither deleted nor written: a carried
    /// reserved key is skipped with a warning. Carried settings replace rather
    /// than merge, so a key removed at the source is removed here.
    pub async fn replace_exportable_settings(
        tx: &mut Transaction<'_, Sqlite>,
        rows: &BTreeMap<String, String>,
    ) -> Result<(), StoreError> {
        // Read then delete, so one `is_reserved` decides what goes and what may come back.
        let existing: Vec<String> = sqlx::query_scalar("SELECT key FROM settings")
            .fetch_all(&mut **tx)
            .await?;
        for key in existing.iter().filter(|key| !is_reserved(key)) {
            sqlx::query("DELETE FROM settings WHERE key = ?")
                .bind(key)
                .execute(&mut **tx)
                .await?;
        }

        let now = stamp(now());
        for (key, value) in rows {
            if is_reserved(key) {
                tracing::warn!(
                    key = for_the_log(key),
                    "a backup carried a key in a reserved namespace; it was not applied"
                );
                continue;
            }
            sqlx::query("INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?)")
                .bind(key)
                .bind(value)
                .bind(&now)
                .execute(&mut **tx)
                .await?;
        }
        Ok(())
    }

    pub async fn setting(&self, key: &str) -> Result<Option<String>, StoreError> {
        reject_reserved(key)?;
        read_key(&self.pool, key).await
    }

    /// A setting as a JSON document; absent or unparseable is `T::default()`,
    /// the second with a warning naming the key.
    pub async fn setting_doc<T: DeserializeOwned + Default>(
        &self,
        key: &str,
    ) -> Result<T, StoreError> {
        reject_reserved(key)?;
        self.read_doc(key).await
    }

    /// Read this box's own state by its bare name — `"backup.last_run"`.
    pub async fn box_state(&self, name: &str) -> Result<Option<String>, StoreError> {
        read_key(&self.pool, &box_key(name)).await
    }

    /// [`Store::box_state`] as a JSON document, with [`Store::setting_doc`]'s
    /// answers.
    pub async fn box_state_doc<T: DeserializeOwned + Default>(
        &self,
        name: &str,
    ) -> Result<T, StoreError> {
        self.read_doc(&box_key(name)).await
    }

    async fn read_doc<T: DeserializeOwned + Default>(&self, key: &str) -> Result<T, StoreError> {
        let Some(raw) = read_key(&self.pool, key).await? else {
            return Ok(T::default());
        };
        Ok(serde_json::from_str(&raw).unwrap_or_else(|e| {
            tracing::warn!(key, error = %e, "a stored document will not parse; using its default");
            T::default()
        }))
    }

    /// Read a secret by its bare name — `"backup.schedule_passphrase"`.
    pub async fn secret(&self, name: &str) -> Result<Option<Secret>, StoreError> {
        Ok(read_key(&self.pool, &secret_key(name))
            .await?
            .map(Secret::new))
    }

    pub async fn secret_in(
        tx: &mut Transaction<'_, Sqlite>,
        name: &str,
    ) -> Result<Option<Secret>, StoreError> {
        Ok(read_key(&mut **tx, &secret_key(name))
            .await?
            .map(Secret::new))
    }

    /// The bare names of the stored secrets starting with the bare `prefix`, sorted.
    pub async fn secret_names(&self, prefix: &str) -> Result<Vec<String>, StoreError> {
        let start = secret_key(prefix);
        let keys: Vec<String> =
            sqlx::query_scalar("SELECT key FROM settings WHERE key >= ? ORDER BY key")
                .bind(&start)
                .fetch_all(&self.pool)
                .await?;
        Ok(keys
            .iter()
            .map_while(|key| key.strip_prefix(&start))
            .map(|rest| format!("{prefix}{rest}"))
            .collect())
    }

    /// Write a setting, replacing whatever was there.
    pub async fn set_setting(&self, key: &str, value: &str) -> Result<(), StoreError> {
        reject_reserved(key)?;
        write_key(&self.pool, key, value).await?;
        self.settings_replaced();
        Ok(())
    }

    pub async fn set_setting_doc<T: Serialize>(
        &self,
        key: &str,
        value: &T,
    ) -> Result<(), StoreError> {
        reject_reserved(key)?;
        self.write_doc(key, value).await?;
        self.settings_replaced();
        Ok(())
    }

    /// A receiver that changes after each settings write; it keeps only the
    /// latest, so a reader re-reads every setting it holds.
    pub fn settings_changed(&self) -> tokio::sync::watch::Receiver<u64> {
        self.settings.subscribe()
    }

    /// Announce a change [`Store::settings_changed`] cannot see, once it has
    /// committed: a restore, a factory reset, or configuration a product keeps
    /// in its own tables.
    pub fn settings_replaced(&self) {
        self.settings
            .send_modify(|generation| *generation = generation.wrapping_add(1));
    }

    pub async fn set_secret(&self, name: &str, value: &Secret) -> Result<(), StoreError> {
        write_key(&self.pool, &secret_key(name), value.expose()).await
    }

    pub async fn set_secret_in(
        tx: &mut Transaction<'_, Sqlite>,
        name: &str,
        value: &Secret,
    ) -> Result<(), StoreError> {
        write_key(&mut **tx, &secret_key(name), value.expose()).await
    }

    pub async fn clear_secret(&self, name: &str) -> Result<(), StoreError> {
        delete_key(&self.pool, &secret_key(name)).await
    }

    pub async fn clear_secret_in(
        tx: &mut Transaction<'_, Sqlite>,
        name: &str,
    ) -> Result<(), StoreError> {
        delete_key(&mut **tx, &secret_key(name)).await
    }

    pub async fn set_box_state(&self, name: &str, value: &str) -> Result<(), StoreError> {
        write_key(&self.pool, &box_key(name), value).await
    }

    pub async fn set_box_state_doc<T: Serialize>(
        &self,
        name: &str,
        value: &T,
    ) -> Result<(), StoreError> {
        self.write_doc(&box_key(name), value).await
    }

    async fn write_doc<T: Serialize>(&self, key: &str, value: &T) -> Result<(), StoreError> {
        let raw = serde_json::to_string(value)
            .map_err(|e| StoreError::unreadable("settings", "document", format!("{key}: {e}")))?;
        write_key(&self.pool, key, &raw).await
    }

    pub async fn clear_box_state(&self, name: &str) -> Result<(), StoreError> {
        delete_key(&self.pool, &box_key(name)).await
    }

    /// Write a secret only if none is stored, and answer the one that is, so
    /// two callers generating one at once are both handed the one that landed.
    pub async fn init_secret(&self, name: &str, value: &Secret) -> Result<Secret, StoreError> {
        // The no-op `DO UPDATE` is what makes `RETURNING` answer the existing row.
        let landed: String = sqlx::query_scalar(
            "INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?) \
             ON CONFLICT (key) DO UPDATE SET value = value RETURNING value",
        )
        .bind(secret_key(name))
        .bind(value.expose())
        .bind(stamp(now()))
        .fetch_one(&self.pool)
        .await?;
        Ok(Secret::new(landed))
    }
}

async fn read_key<'e>(
    db: impl SqliteExecutor<'e>,
    key: &str,
) -> Result<Option<String>, StoreError> {
    Ok(
        sqlx::query_scalar("SELECT value FROM settings WHERE key = ?")
            .bind(key)
            .fetch_optional(db)
            .await?,
    )
}

async fn write_key<'e>(
    db: impl SqliteExecutor<'e>,
    key: &str,
    value: &str,
) -> Result<(), StoreError> {
    sqlx::query(
        "INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?) \
         ON CONFLICT (key) DO UPDATE SET value = excluded.value, \
         updated_at = excluded.updated_at",
    )
    .bind(key)
    .bind(value)
    .bind(stamp(now()))
    .execute(db)
    .await?;
    Ok(())
}

async fn delete_key<'e>(db: impl SqliteExecutor<'e>, key: &str) -> Result<(), StoreError> {
    sqlx::query("DELETE FROM settings WHERE key = ?")
        .bind(key)
        .execute(db)
        .await?;
    Ok(())
}

fn reject_reserved(key: &str) -> Result<(), StoreError> {
    if is_reserved(key) {
        return Err(StoreError::Reserved(key.to_string()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::store;

    #[test]
    fn a_key_out_of_a_bundle_is_cut_by_characters_and_not_by_bytes() {
        let crafted = format!("{SECRET_PREFIX}{}é{}", "x".repeat(56), "y".repeat(10));
        assert!(!crafted.is_char_boundary(64), "the plant must straddle one");

        let logged = for_the_log(&crafted);
        assert_eq!(logged.chars().count(), 64);
        assert!(crafted.starts_with(&logged));
    }

    #[tokio::test]
    async fn a_secret_is_reachable_only_through_the_calls_that_own_it() {
        let store = store().await;
        store
            .set_secret("sample_secret", &Secret::new("d0not1eak"))
            .await
            .expect("write");

        assert_eq!(
            store
                .secret("sample_secret")
                .await
                .expect("read")
                .as_ref()
                .map(Secret::expose),
            Some("d0not1eak")
        );

        let key = "secret.sample_secret";
        assert!(
            matches!(store.setting(key).await, Err(StoreError::Reserved(_))),
            "reading a secret through `setting` must be refused"
        );
        assert!(
            matches!(
                store.set_setting(key, "x").await,
                Err(StoreError::Reserved(_))
            ),
            "writing one through `set_setting` must be refused"
        );

        store.clear_secret("sample_secret").await.expect("clear");
        assert!(
            store.secret("sample_secret").await.expect("read").is_none(),
            "cleared is absent"
        );
    }

    #[tokio::test]
    async fn this_boxs_own_state_is_reachable_only_through_the_calls_that_own_it() {
        let store = store().await;
        store
            .set_box_state("backup.last_run", "2026-09-19T00:00:00Z")
            .await
            .expect("write");
        assert_eq!(
            store.box_state("backup.last_run").await.expect("read"),
            Some("2026-09-19T00:00:00Z".to_string())
        );

        let key = "box.backup.last_run";
        assert!(matches!(
            store.setting(key).await,
            Err(StoreError::Reserved(_))
        ));
        assert!(matches!(
            store.set_setting(key, "x").await,
            Err(StoreError::Reserved(_))
        ));

        store
            .clear_box_state("backup.last_run")
            .await
            .expect("clear");
        assert_eq!(
            store.box_state("backup.last_run").await.expect("read"),
            None,
            "cleared is absent, which is the state a caller reads as never run"
        );
    }

    #[tokio::test]
    async fn this_boxs_own_state_never_leaves_the_box_and_a_restore_leaves_it_alone() {
        let store = store().await;
        store
            .set_box_state("host.pending_rollback", "checkpoint-7")
            .await
            .expect("write");
        store
            .set_setting("branding.app_name", "Widget Monitor")
            .await
            .expect("write");

        let exported = store.exportable_settings().await.expect("export");
        assert_eq!(exported.keys().collect::<Vec<_>>(), ["branding.app_name"]);

        let mut tx = store.begin().await.expect("begin");
        Store::replace_exportable_settings(
            &mut tx,
            &BTreeMap::from([
                (
                    "box.host.pending_rollback".to_string(),
                    "theirs".to_string(),
                ),
                ("branding.app_name".to_string(), "New".to_string()),
            ]),
        )
        .await
        .expect("restore");
        tx.commit().await.expect("commit");

        assert_eq!(
            store.box_state("host.pending_rollback").await.unwrap(),
            Some("checkpoint-7".to_string()),
            "neither deleted by the replace nor overwritten by the carried row"
        );
        assert_eq!(
            store.setting("branding.app_name").await.unwrap(),
            Some("New".to_string())
        );
    }

    #[tokio::test]
    async fn a_document_round_trips_in_both_namespaces_and_an_unreadable_one_is_its_default() {
        #[derive(Debug, Default, PartialEq, serde::Serialize, serde::Deserialize)]
        struct Doc {
            enabled: bool,
            every_hours: u32,
        }
        let doc = Doc {
            enabled: true,
            every_hours: 24,
        };
        let store = store().await;

        assert_eq!(
            store.setting_doc::<Doc>("backup.schedule").await.unwrap(),
            Doc::default(),
            "absent is the default, so a screen renders before anything was saved"
        );
        store
            .set_setting_doc("backup.schedule", &doc)
            .await
            .expect("write");
        assert_eq!(
            store.setting_doc::<Doc>("backup.schedule").await.unwrap(),
            doc
        );
        assert!(
            store
                .exportable_settings()
                .await
                .unwrap()
                .contains_key("backup.schedule"),
            "a settings document is configuration and travels"
        );

        store
            .set_box_state_doc(
                "backup.state",
                &Doc {
                    enabled: false,
                    every_hours: 1,
                },
            )
            .await
            .expect("write");
        assert_eq!(
            store
                .box_state_doc::<Doc>("backup.state")
                .await
                .unwrap()
                .every_hours,
            1
        );
        assert!(matches!(
            store.setting_doc::<Doc>("box.backup.state").await,
            Err(StoreError::Reserved(_))
        ));

        store
            .set_box_state("backup.state", "not json")
            .await
            .unwrap();
        assert_eq!(
            store.box_state_doc::<Doc>("backup.state").await.unwrap(),
            Doc::default(),
            "a row this build cannot parse reads as the default, not as a fault"
        );
    }

    #[tokio::test]
    async fn a_second_loader_offering_a_secret_is_handed_the_one_that_landed() {
        let store = store().await;
        let first = store
            .init_secret("sample_secret", &Secret::new("first"))
            .await
            .expect("init");
        let second = store
            .init_secret("sample_secret", &Secret::new("second"))
            .await
            .expect("init again");

        assert_eq!(first.expose(), "first");
        assert_eq!(second.expose(), "first", "the loser takes what landed");
    }

    #[tokio::test]
    async fn a_setting_that_was_never_written_is_absent_rather_than_empty() {
        let store = store().await;
        assert_eq!(
            store.setting("branding.app_name").await.expect("read"),
            None
        );

        store
            .set_setting("branding.app_name", "")
            .await
            .expect("write");
        assert_eq!(
            store.setting("branding.app_name").await.expect("read"),
            Some(String::new())
        );
    }

    #[test]
    fn the_namespaces_are_matched_case_sensitively() {
        assert!(is_reserved("secret.sample_secret"));
        assert!(!is_reserved("SECRET.sample_secret"));
        assert!(!is_reserved("Secret.sample_secret"));
        assert!(is_reserved("box.backup.last_run"));
        assert!(!is_reserved("BOX.backup.last_run"));
        assert!(!is_reserved("boxes.count"), "the prefix ends at its dot");
    }

    #[tokio::test]
    async fn a_secret_never_leaves_the_box_through_the_export() {
        let store = store().await;
        store
            .set_secret("sample_secret", &Secret::new("d0not1eak"))
            .await
            .expect("write");
        store
            .set_setting("branding.app_name", "Widget Monitor")
            .await
            .expect("write");

        let exported = store.exportable_settings().await.expect("export");
        assert_eq!(
            exported,
            BTreeMap::from([(
                "branding.app_name".to_string(),
                "Widget Monitor".to_string()
            )])
        );
        assert!(
            !format!("{exported:?}").contains("d0not1eak"),
            "not the key, and not the value either"
        );
    }

    #[tokio::test]
    async fn a_key_that_merely_mentions_the_word_secret_is_not_in_the_namespace() {
        let store = store().await;
        for key in ["poller.secret_rotation_days", "secrets.enabled", "secret"] {
            store.set_setting(key, "yes").await.expect("write");
        }
        let exported = store.exportable_settings().await.expect("export");
        assert_eq!(exported.len(), 3, "{exported:?}");
    }

    #[tokio::test]
    async fn a_restore_replaces_the_carried_settings_and_leaves_the_secrets_alone() {
        let store = store().await;
        store
            .set_secret("sample_secret", &Secret::new("d0not1eak"))
            .await
            .expect("write");
        store
            .set_setting("branding.app_name", "Old")
            .await
            .expect("write");
        store
            .set_setting("gone.after.restore", "x")
            .await
            .expect("write");

        let mut tx = store.begin().await.expect("begin");
        Store::replace_exportable_settings(
            &mut tx,
            &BTreeMap::from([("branding.app_name".to_string(), "New".to_string())]),
        )
        .await
        .expect("restore");
        tx.commit().await.expect("commit");

        assert_eq!(
            store.setting("branding.app_name").await.unwrap(),
            Some("New".to_string())
        );
        assert_eq!(
            store.setting("gone.after.restore").await.unwrap(),
            None,
            "a carried section replaces rather than merges"
        );
        assert_eq!(
            store
                .secret("sample_secret")
                .await
                .unwrap()
                .as_ref()
                .map(Secret::expose),
            Some("d0not1eak"),
            "the running daemon is holding this in memory; deleting it would sign \
             the world out at the next restart"
        );
    }

    #[tokio::test]
    async fn a_differently_cased_key_is_not_in_the_namespace_on_either_side() {
        let store = store().await;
        store
            .set_setting("SECRET.pretend", "v")
            .await
            .expect("write");

        assert!(
            store
                .exportable_settings()
                .await
                .unwrap()
                .contains_key("SECRET.pretend")
        );

        let mut tx = store.begin().await.expect("begin");
        Store::replace_exportable_settings(&mut tx, &BTreeMap::new())
            .await
            .expect("restore");
        tx.commit().await.expect("commit");

        assert_eq!(
            store.setting("SECRET.pretend").await.unwrap(),
            None,
            "it is an ordinary key, so an empty bundle removes it"
        );
    }

    #[tokio::test]
    async fn a_crafted_bundle_cannot_install_a_signing_key() {
        let store = store().await;
        store
            .set_secret("sample_secret", &Secret::new("theirs"))
            .await
            .expect("write");

        let mut tx = store.begin().await.expect("begin");
        Store::replace_exportable_settings(
            &mut tx,
            &BTreeMap::from([
                ("secret.sample_secret".to_string(), "attacker".to_string()),
                ("branding.app_name".to_string(), "New".to_string()),
            ]),
        )
        .await
        .expect("restore");
        tx.commit().await.expect("commit");

        assert_eq!(
            store
                .secret("sample_secret")
                .await
                .unwrap()
                .as_ref()
                .map(Secret::expose),
            Some("theirs"),
            "the crafted key was dropped, not applied"
        );
        assert_eq!(
            store.setting("branding.app_name").await.unwrap(),
            Some("New".to_string()),
            "and the rest of the bundle still landed"
        );
    }

    #[tokio::test]
    async fn a_settings_write_is_announced_and_a_secret_or_box_state_write_is_not() {
        let store = store().await;
        let mut changed = store.settings_changed();
        let clone = store.sparing_host_admins();

        store
            .set_secret("sample_secret", &Secret::new("x"))
            .await
            .unwrap();
        store.init_secret("other", &Secret::new("y")).await.unwrap();
        store.clear_secret("other").await.unwrap();
        store.set_box_state("backup.last_run", "now").await.unwrap();
        store.set_box_state_doc("backup.state", &1).await.unwrap();
        store.clear_box_state("backup.last_run").await.unwrap();
        let mut tx = store.begin().await.unwrap();
        Store::set_secret_in(&mut tx, "in_tx", &Secret::new("z"))
            .await
            .unwrap();
        Store::clear_secret_in(&mut tx, "in_tx").await.unwrap();
        tx.commit().await.unwrap();
        assert!(
            !changed.has_changed().unwrap(),
            "the sweeper writes box state every round"
        );

        clone.set_setting("branding.app_name", "New").await.unwrap();
        assert!(
            changed.has_changed().unwrap(),
            "a clone's write is this store's"
        );
        changed.mark_unchanged();

        store.set_setting_doc("backup.schedule", &1).await.unwrap();
        assert!(changed.has_changed().unwrap());
        changed.mark_unchanged();

        assert!(store.set_setting("secret.x", "y").await.is_err());
        assert!(
            !changed.has_changed().unwrap(),
            "a refused write is no change"
        );

        store.settings_replaced();
        assert!(changed.has_changed().unwrap());
    }

    #[tokio::test]
    async fn secret_names_lists_bare_names_under_an_exact_prefix() {
        let store = store().await;
        for name in ["cred.b", "cred.a", "cred_x", "credXa", "cre", "other"] {
            store.set_secret(name, &Secret::new("v")).await.unwrap();
        }
        store.set_setting("cred.setting", "v").await.unwrap();
        store.set_box_state("cred.box", "v").await.unwrap();

        assert_eq!(
            store.secret_names("cred.").await.unwrap(),
            ["cred.a", "cred.b"]
        );
        assert_eq!(
            store.secret_names("cred_").await.unwrap(),
            ["cred_x"],
            "an `_` is matched as itself, not as any character"
        );
        assert_eq!(
            store.secret_names("").await.unwrap(),
            ["cre", "cred.a", "cred.b", "credXa", "cred_x", "other"]
        );
        assert!(store.secret_names("none").await.unwrap().is_empty());
    }

    async fn rename_in_one_transaction(store: &Store, commit: bool) {
        let mut tx = store.begin().await.unwrap();
        let value = Store::secret_in(&mut tx, "cred.old")
            .await
            .unwrap()
            .expect("stored");
        Store::set_secret_in(&mut tx, "cred.new", &value)
            .await
            .unwrap();
        Store::clear_secret_in(&mut tx, "cred.old").await.unwrap();
        if commit {
            tx.commit().await.unwrap();
        } else {
            tx.rollback().await.unwrap();
        }
    }

    #[tokio::test]
    async fn a_secret_renamed_in_a_transaction_moves_only_when_it_commits() {
        let store = store().await;
        store
            .set_secret("cred.old", &Secret::new("v"))
            .await
            .unwrap();

        rename_in_one_transaction(&store, false).await;
        assert_eq!(store.secret_names("cred.").await.unwrap(), ["cred.old"]);

        rename_in_one_transaction(&store, true).await;
        assert_eq!(store.secret_names("cred.").await.unwrap(), ["cred.new"]);
        assert_eq!(
            store
                .secret("cred.new")
                .await
                .unwrap()
                .as_ref()
                .map(Secret::expose),
            Some("v")
        );
    }

    #[tokio::test]
    async fn writing_a_setting_twice_replaces_it() {
        let store = store().await;
        store.set_setting("a.key", "first").await.expect("write");
        store.set_setting("a.key", "second").await.expect("rewrite");
        assert_eq!(
            store.setting("a.key").await.expect("read"),
            Some("second".to_string())
        );
    }
}
