//! Emptying the platform's tables for a factory reset, in the reset's own
//! transaction, beside the product's erase of its own.

use sqlx::{Sqlite, Transaction};

use crate::{Store, StoreError};

/// Every table the platform's migrations create, in name order; a test holds
/// it to `sqlite_master`.
pub(crate) const PLATFORM_TABLES: [&str; 13] = [
    "app_roles",
    "asserted_roles",
    "audit",
    "passkeys",
    "platform_session_secrets",
    "platform_sessions",
    "recovery_codes",
    "settings",
    "totp",
    "totp_required",
    "trusted_cas",
    "trusted_certs",
    "users",
];

impl Store {
    /// Empty every platform table, inside a transaction from [`Store::begin`],
    /// where the product's own deletes go too, in any order.
    ///
    /// The commit catches a product table left full only if it references
    /// `users` with no `ON DELETE` action, or with `RESTRICT`; the product's
    /// list of its own tables is its own to keep.
    ///
    /// **Every secret goes with `settings`**: after the commit, reload any
    /// secret held in memory and call [`Store::settings_replaced`].
    pub async fn erase_platform(tx: &mut Transaction<'_, Sqlite>) -> Result<(), StoreError> {
        for table in PLATFORM_TABLES {
            sqlx::query(&format!("DELETE FROM {table}"))
                .execute(&mut **tx)
                .await?;
        }
        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::audit::tests::record;
    use crate::certs::tests::{ca, cert};
    use crate::tests::{store, tables};
    use chrono::DateTime;
    use wslib_appliance_types::Role;
    use wslib_secret::Secret;

    pub(crate) async fn rows(store: &Store, table: &str) -> i64 {
        sqlx::query_scalar(&format!("SELECT count(*) FROM {table}"))
            .fetch_one(store.pool())
            .await
            .expect("count")
    }

    /// A row in every platform table, so an erase has something to miss.
    async fn populate(store: &Store) -> String {
        let at = DateTime::from_timestamp(1_757_000_000, 0).unwrap();
        let user = store
            .create_user("admin", "not-a-real-hash", Role::Admin)
            .await
            .expect("create");
        store
            .set_setting("branding.app_name", "Widget Monitor")
            .await
            .expect("setting");
        store
            .set_secret("sample_secret", &Secret::new("abc"))
            .await
            .expect("secret");
        store
            .set_box_state("host.pending_rollback", "checkpoint-7")
            .await
            .expect("box state");
        store
            .record_audit(&record(at, "did a thing"))
            .await
            .expect("audit");
        store
            .pin_cert(&cert("widget-01", &"00".repeat(32)))
            .await
            .expect("pin");
        store.trust_ca(&ca("aa11", "admin")).await.expect("trust");
        store
            .set_app_role(&user.id, "widgets", Some(Role::Viewer))
            .await
            .expect("app role");
        crate::factors::tests::furnish(store, &user.id, 1).await;
        let required = store
            .create_user("member", "not-a-real-hash", Role::Viewer)
            .await
            .expect("create");
        store.require_totp(&required.id).await.expect("required");
        crate::asserted::tests::seen(store, "a1", Some(Role::Admin)).await;
        crate::tests::session(store, &user.id).await;
        for table in PLATFORM_TABLES {
            assert!(rows(store, table).await > 0, "{table} is populated");
        }
        user.id
    }

    /// A product row referencing the platform's, to be forgotten or not.
    async fn widget_owned_by(store: &Store, owner: &str) {
        sqlx::query("INSERT INTO app_widgets (name, owner) VALUES ('a widget', ?)")
            .bind(owner)
            .execute(store.pool())
            .await
            .expect("an app row");
    }

    #[tokio::test]
    async fn the_platform_list_is_every_table_but_the_migration_records() {
        let platform_only = Store::open_in_memory(None).await.expect("store");
        let mut expected = vec![
            "_migration_chains",
            "_platform_migrations",
            "_sqlx_migrations",
        ];
        expected.extend(PLATFORM_TABLES);
        expected.sort_unstable();
        assert_eq!(tables(&platform_only).await, expected);
    }

    #[tokio::test]
    async fn erasing_the_platform_leaves_every_platform_table_empty_and_the_schema_intact() {
        let store = store().await;
        populate(&store).await;
        let before = tables(&store).await;

        let mut tx = store.begin().await.expect("begin");
        Store::erase_platform(&mut tx).await.expect("erase");
        tx.commit().await.expect("commit");

        for table in PLATFORM_TABLES {
            assert_eq!(rows(&store, table).await, 0, "{table} is empty");
        }
        assert_eq!(tables(&store).await, before, "the schema is untouched");
        assert_eq!(rows(&store, "_migration_chains").await, 2, "nor the chains");
        assert!(
            store
                .secret("sample_secret")
                .await
                .expect("secret")
                .is_none(),
            "the secrets went with the settings"
        );
        assert!(
            store
                .box_state("host.pending_rollback")
                .await
                .expect("box state")
                .is_none(),
            "and so did this box's own state"
        );
    }

    #[tokio::test]
    async fn a_consumers_referencing_rows_go_in_the_same_transaction_in_any_order() {
        let store = store().await;
        let owner = populate(&store).await;
        widget_owned_by(&store, &owner).await;

        let mut tx = store.begin().await.expect("begin");
        Store::erase_platform(&mut tx).await.expect("erase");
        sqlx::query("DELETE FROM app_widgets")
            .execute(&mut *tx)
            .await
            .expect("the consumer's half");
        tx.commit().await.expect("both halves commit together");

        assert_eq!(rows(&store, "app_widgets").await, 0);
        assert_eq!(store.user_count().await.expect("count"), 0);
    }

    #[tokio::test]
    async fn a_referencing_table_the_consumer_forgot_fails_the_commit_rather_than_surviving() {
        let store = store().await;
        let owner = populate(&store).await;
        widget_owned_by(&store, &owner).await;

        let mut tx = store.begin().await.expect("begin");
        Store::erase_platform(&mut tx)
            .await
            .expect("the delete itself is not where the check is");
        assert!(
            tx.commit().await.is_err(),
            "the forgotten reference fails the commit"
        );

        for table in PLATFORM_TABLES {
            assert!(rows(&store, table).await > 0, "{table} is as it was");
        }
    }
}
