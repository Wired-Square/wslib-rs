//! The key/value table of strings for everything operational, keyed by dotted
//! names owned by one place each: `branding.app_name`. It is
//! `wslib_db_sqlite`'s `Settings`, with local state under `box.`.
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
//! Raw SQL and another `Store`, in this process or another, are not seen.

use std::collections::BTreeMap;

use serde::Serialize;
use serde::de::DeserializeOwned;
use sqlx::{Sqlite, Transaction};

use wslib_secret::Secret;

use crate::{Store, StoreError};

pub(crate) const BOX_PREFIX: &str = "box.";

impl Store {
    /// Every setting that may leave this box: no secret and no box state.
    pub async fn exportable_settings(&self) -> Result<BTreeMap<String, String>, StoreError> {
        Ok(self.settings.exportable().await?)
    }

    /// Replace every exportable setting with `rows`, inside `tx`; call
    /// [`Store::settings_replaced`] once it commits.
    ///
    /// Secrets and box state are neither deleted nor written: a carried
    /// reserved key is skipped with a warning. Carried settings replace rather
    /// than merge, so a key removed at the source is removed here.
    pub async fn replace_exportable_settings(
        &self,
        tx: &mut Transaction<'_, Sqlite>,
        rows: &BTreeMap<String, String>,
    ) -> Result<(), StoreError> {
        Ok(self.settings.replace_exportable(tx, rows).await?)
    }

    pub async fn setting(&self, key: &str) -> Result<Option<String>, StoreError> {
        Ok(self.settings.setting(key).await?)
    }

    /// A setting as a JSON document; absent or unparseable is `T::default()`,
    /// the second with a warning naming the key.
    pub async fn setting_doc<T: DeserializeOwned + Default>(
        &self,
        key: &str,
    ) -> Result<T, StoreError> {
        Ok(self.settings.setting_doc(key).await?)
    }

    /// Read this box's own state by its bare name — `"backup.last_run"`.
    pub async fn box_state(&self, name: &str) -> Result<Option<String>, StoreError> {
        Ok(self.settings.local(name).await?)
    }

    /// [`Store::box_state`] as a JSON document, with [`Store::setting_doc`]'s
    /// answers.
    pub async fn box_state_doc<T: DeserializeOwned + Default>(
        &self,
        name: &str,
    ) -> Result<T, StoreError> {
        Ok(self.settings.local_doc(name).await?)
    }

    /// Read a secret by its bare name — `"backup.schedule_passphrase"`.
    pub async fn secret(&self, name: &str) -> Result<Option<Secret>, StoreError> {
        Ok(self.settings.secret(name).await?)
    }

    pub async fn secret_in(
        &self,
        tx: &mut Transaction<'_, Sqlite>,
        name: &str,
    ) -> Result<Option<Secret>, StoreError> {
        Ok(self.settings.secret_in(tx, name).await?)
    }

    /// The bare names of the stored secrets starting with the bare `prefix`, sorted.
    pub async fn secret_names(&self, prefix: &str) -> Result<Vec<String>, StoreError> {
        Ok(self.settings.secret_names(prefix).await?)
    }

    /// Write a setting, replacing whatever was there.
    pub async fn set_setting(&self, key: &str, value: &str) -> Result<(), StoreError> {
        Ok(self.settings.set_setting(key, value).await?)
    }

    pub async fn set_setting_doc<T: Serialize>(
        &self,
        key: &str,
        value: &T,
    ) -> Result<(), StoreError> {
        Ok(self.settings.set_setting_doc(key, value).await?)
    }

    /// A receiver that changes after each settings write; it keeps only the
    /// latest, so a reader re-reads every setting it holds.
    pub fn settings_changed(&self) -> tokio::sync::watch::Receiver<u64> {
        self.settings.changed()
    }

    /// Announce a change [`Store::settings_changed`] cannot see, once it has
    /// committed: a restore, a factory reset, or configuration a product keeps
    /// in its own tables.
    pub fn settings_replaced(&self) {
        self.settings.replaced();
    }

    pub async fn set_secret(&self, name: &str, value: &Secret) -> Result<(), StoreError> {
        Ok(self.settings.set_secret(name, value).await?)
    }

    pub async fn set_secret_in(
        &self,
        tx: &mut Transaction<'_, Sqlite>,
        name: &str,
        value: &Secret,
    ) -> Result<(), StoreError> {
        Ok(self.settings.set_secret_in(tx, name, value).await?)
    }

    pub async fn clear_secret(&self, name: &str) -> Result<(), StoreError> {
        Ok(self.settings.clear_secret(name).await?)
    }

    pub async fn clear_secret_in(
        &self,
        tx: &mut Transaction<'_, Sqlite>,
        name: &str,
    ) -> Result<(), StoreError> {
        Ok(self.settings.clear_secret_in(tx, name).await?)
    }

    pub async fn set_box_state(&self, name: &str, value: &str) -> Result<(), StoreError> {
        Ok(self.settings.set_local(name, value).await?)
    }

    pub async fn set_box_state_doc<T: Serialize>(
        &self,
        name: &str,
        value: &T,
    ) -> Result<(), StoreError> {
        Ok(self.settings.set_local_doc(name, value).await?)
    }

    pub async fn clear_box_state(&self, name: &str) -> Result<(), StoreError> {
        Ok(self.settings.clear_local(name).await?)
    }

    /// Write a secret only if none is stored, and answer the one that is, so
    /// two callers generating one at once are both handed the one that landed.
    pub async fn init_secret(&self, name: &str, value: &Secret) -> Result<Secret, StoreError> {
        Ok(self.settings.init_secret(name, value).await?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::store;

    #[tokio::test]
    async fn the_reserved_message_names_the_stores_own_calls() {
        let e = store().await.setting("box.x").await.expect_err("reserved");
        assert!(e.to_string().contains("Store::box_state"), "{e}");
    }

    #[tokio::test]
    async fn a_box_state_document_round_trips_and_is_refused_as_a_setting() {
        let store = store().await;
        store.set_box_state_doc("x", &[1, 2]).await.expect("write");
        assert_eq!(
            store.box_state_doc::<Vec<u32>>("x").await.expect("read"),
            [1, 2]
        );
        assert!(matches!(
            store.setting_doc::<Vec<u32>>("box.x").await,
            Err(StoreError::Reserved(_))
        ));
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
        store
            .replace_exportable_settings(
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
    async fn a_document_that_will_not_serialise_is_unreadable_and_names_its_key() {
        let not_a_map = BTreeMap::from([((1, 2), 3)]);
        let e = store()
            .await
            .set_setting_doc("backup.schedule", &not_a_map)
            .await
            .expect_err("a map keyed by tuples is not JSON");
        assert!(
            matches!(&e, StoreError::Unreadable { table: "settings", what: "document", because }
                if because.starts_with("backup.schedule: ")),
            "{e:?}"
        );
    }

    #[tokio::test]
    async fn the_namespaces_are_matched_case_sensitively_and_end_at_their_dot() {
        let store = store().await;
        for key in ["SECRET.sample_secret", "BOX.backup.last_run", "boxes.count"] {
            store.set_setting(key, "v").await.expect(key);
        }
        for key in ["secret.sample_secret", "box.backup.last_run"] {
            assert!(
                matches!(store.setting(key).await, Err(StoreError::Reserved(_))),
                "{key}"
            );
        }
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
        store
            .set_secret_in(&mut tx, "in_tx", &Secret::new("z"))
            .await
            .unwrap();
        store.clear_secret_in(&mut tx, "in_tx").await.unwrap();
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
}
