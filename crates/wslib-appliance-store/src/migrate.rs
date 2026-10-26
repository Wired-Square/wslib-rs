//! The platform's migrations and a product's, as two `wslib_db_sqlite` chains,
//! `platform` and then `app`: the platform's below [`APP_FLOOR`], the
//! product's from it.
//!
//! Both are mirrored into `_sqlx_migrations`, so a build on sqlx's own runner
//! over the two concatenated still opens the database, and refuses a newer one.
//! That is why the two share one numbering. A platform migration added after a
//! product's applies at the next start.
//!
//! **The `.sql` files under `migrations/` are frozen byte for byte**: their
//! checksums are recorded on every box, and a database refuses a changed one.

use sqlx::migrate::Migrator;
use wslib_db_sqlite::Chain;

use crate::StoreError;

const PLATFORM_CEILING: i64 = 999;

/// The lowest version a product's own migration may take.
pub const APP_FLOOR: i64 = PLATFORM_CEILING + 1;

pub(crate) const APP: &str = "app";

/// The platform's chain, then `app`'s, `None` for a product with no schema
/// yet; an app migration below [`APP_FLOOR`] is refused.
pub(crate) fn chains(app: Option<&Migrator>) -> Result<Vec<Chain>, StoreError> {
    if let Some(m) = app
        .iter()
        .flat_map(|app| app.iter())
        .find(|m| m.version < APP_FLOOR)
    {
        return Err(StoreError::MigrationVersion {
            version: m.version,
            description: m.description.to_string(),
        });
    }
    let mut chains = vec![Chain::new("platform", &platform()).mirrored()];
    chains.extend(app.map(|app| Chain::new(APP, app).mirrored()));
    Ok(chains)
}

fn platform() -> Migrator {
    sqlx::migrate!("./migrations")
}

#[cfg(test)]
mod tests {
    use std::future::Future;
    use std::pin::Pin;

    use sqlx::error::BoxDynError;
    use sqlx::migrate::{Migration, MigrationSource};
    use sqlx::sqlite::SqlitePool;

    use super::*;
    use crate::tests::app_migrations;
    use crate::{now, stamp};

    #[derive(Debug)]
    struct Resolved(Vec<Migration>);

    impl MigrationSource<'static> for Resolved {
        fn resolve(
            self,
        ) -> Pin<Box<dyn Future<Output = Result<Vec<Migration>, BoxDynError>> + Send + 'static>>
        {
            Box::pin(async move { Ok(self.0) })
        }
    }

    async fn on_sqlx_runner_at_0004(path: &std::path::Path) -> SqlitePool {
        let pool = SqlitePool::connect_with(
            sqlx::sqlite::SqliteConnectOptions::new()
                .filename(path)
                .create_if_missing(true),
        )
        .await
        .expect("connect");
        let migrations = platform()
            .iter()
            .filter(|m| m.version <= 4)
            .cloned()
            .collect();
        Migrator::new(Resolved(migrations))
            .await
            .expect("chain")
            .run(&pool)
            .await
            .expect("the schema at 0004");
        pool
    }

    #[test]
    fn the_platform_runs_first_and_the_app_after() {
        let app = app_migrations();
        let chains = chains(Some(&app)).expect("composes");
        let names: Vec<&str> = chains.iter().map(Chain::name).collect();
        assert_eq!(names, ["platform", APP]);
        assert_eq!(chains[0].version(), Some(7));
        assert_eq!(chains[1].version(), Some(1000));
    }

    #[test]
    fn an_app_numbering_from_one_is_refused_by_version() {
        let e = chains(Some(&sqlx::migrate!("./test-migrations/collides")))
            .expect_err("2 is inside the platform's range");
        assert!(
            matches!(e, StoreError::MigrationVersion { version: 2, .. }),
            "{e:?}"
        );
        assert!(e.to_string().contains("1000"), "{e}");
    }

    #[tokio::test]
    async fn a_database_at_0004_gains_the_factor_tables_and_keeps_its_accounts() {
        let dir = tempfile::TempDir::new().expect("temp dir");
        let path = dir.path().join("appliance.db");
        let pool = on_sqlx_runner_at_0004(&path).await;
        sqlx::query(
            "INSERT INTO users (id, username, password_hash, role, created_at, updated_at, \
             sessions_valid_from) VALUES ('u1', 'admin', 'h', 'admin', ?1, ?1, ?1)",
        )
        .bind(stamp(now()))
        .execute(&pool)
        .await
        .expect("an account");
        pool.close().await;

        let store = crate::Store::open(&path, Some(app_migrations()))
            .await
            .expect("migrates forward");
        assert!(store.user_by_id("u1").await.expect("read").is_some());
        crate::factors::tests::furnish(&store, "u1", 1).await;
        assert_eq!(store.second_factors().await.expect("read").len(), 1);
        assert!(!store.totp_required("u1").await.expect("read"));
        store.require_totp("u1").await.expect("required");
        assert!(store.totp_required("u1").await.expect("read"));
        store.close().await;
    }

    #[test]
    fn the_platforms_own_migrations_stay_inside_its_range() {
        for migration in platform().iter() {
            assert!(
                (1..=PLATFORM_CEILING).contains(&migration.version),
                "platform migration {} ({}) is outside 1..={PLATFORM_CEILING}",
                migration.version,
                migration.description,
            );
        }
    }
}
