//! The platform's migrations and a product's, concatenated into one sqlx
//! `Migrator` recorded in `_sqlx_migrations`: the platform's below
//! [`APP_FLOOR`], the product's from it.
//!
//! sqlx's runner applies the slice in order without sorting, so a platform
//! migration added after a product's applies at the next start.
//!
//! **The `.sql` files under `migrations/` are frozen byte for byte**: sqlx
//! checksums them, and a database refuses a changed one.

use std::future::Future;
use std::pin::Pin;

use sqlx::error::BoxDynError;
use sqlx::migrate::{MigrateError, Migration, MigrationSource, Migrator};
use sqlx::sqlite::SqlitePool;

use crate::StoreError;

const PLATFORM_CEILING: i64 = 999;

/// The lowest version a product's own migration may take.
pub const APP_FLOOR: i64 = PLATFORM_CEILING + 1;

/// One `Migrator` running the platform's migrations and then the app's, `None`
/// for a product with no schema yet; an app migration below [`APP_FLOOR`] is
/// refused.
pub(crate) async fn compose(app: Option<Migrator>) -> Result<Migrator, StoreError> {
    let mut migrations: Vec<Migration> = platform().iter().cloned().collect();
    for migration in app.iter().flat_map(|app| app.iter()) {
        if migration.version < APP_FLOOR {
            return Err(StoreError::MigrationVersion {
                version: migration.version,
                description: migration.description.to_string(),
            });
        }
        migrations.push(migration.clone());
    }
    Ok(Migrator::new(Chain(migrations)).await?)
}

fn platform() -> Migrator {
    sqlx::migrate!("./migrations")
}

/// Refuse a database that is not exactly at `chain`, without applying
/// anything: behind it (no version table is behind at the first version), or
/// ahead of it as `VersionMissing`.
pub(crate) async fn verify_applied(chain: &Migrator, pool: &SqlitePool) -> Result<(), StoreError> {
    use sqlx::migrate::Migrate;
    let mut conn = pool.acquire().await?;
    let applied: Vec<i64> = match conn.list_applied_migrations().await {
        Ok(applied) => applied.into_iter().map(|m| m.version).collect(),
        Err(MigrateError::Execute(sqlx::Error::Database(e)))
            if e.message().contains("no such table") =>
        {
            Vec::new()
        }
        Err(e) => return Err(e.into()),
    };
    if let Some(behind) = chain.iter().find(|m| !applied.contains(&m.version)) {
        return Err(StoreError::SchemaBehind {
            version: behind.version,
        });
    }
    if let Some(ahead) = applied
        .iter()
        .find(|v| !chain.iter().any(|m| m.version == **v))
    {
        return Err(MigrateError::VersionMissing(*ahead).into());
    }
    Ok(())
}

/// A list of migrations that is already resolved.
#[derive(Debug)]
struct Chain(Vec<Migration>);

impl MigrationSource<'static> for Chain {
    fn resolve(
        self,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<Migration>, BoxDynError>> + Send + 'static>> {
        Box::pin(async move { Ok(self.0) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::app_migrations;
    use crate::{now, stamp};

    #[tokio::test]
    async fn the_platform_runs_first_and_the_app_after() {
        let composed = compose(Some(app_migrations())).await.expect("composes");
        let versions: Vec<i64> = composed.iter().map(|m| m.version).collect();

        assert_eq!(versions, [1, 2, 3, 4, 5, 6, 7, 1000]);
        assert!(
            versions.windows(2).all(|w| w[0] < w[1]),
            "slice order is application order — sqlx iterates and does not sort"
        );
    }

    #[tokio::test]
    async fn an_app_numbering_from_one_is_refused_by_version() {
        let e = compose(Some(sqlx::migrate!("./test-migrations/collides")))
            .await
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
        let to_0004: Vec<Migration> = platform()
            .iter()
            .filter(|m| m.version <= 4)
            .cloned()
            .collect();
        let pool = SqlitePool::connect_with(
            sqlx::sqlite::SqliteConnectOptions::new()
                .filename(&path)
                .create_if_missing(true),
        )
        .await
        .expect("connect");
        Migrator::new(Chain(to_0004))
            .await
            .expect("chain")
            .run(&pool)
            .await
            .expect("the schema at 0004");
        sqlx::query(
            "INSERT INTO users (id, username, password_hash, role, created_at, updated_at, \
             sessions_valid_from) VALUES ('u1', 'admin', 'h', 'admin', ?1, ?1, ?1)",
        )
        .bind(stamp(now()))
        .execute(&pool)
        .await
        .expect("an account");
        pool.close().await;

        let store = crate::Store::open(&path, Some(crate::tests::app_migrations()))
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

    #[tokio::test]
    async fn a_database_at_0006_loses_the_token_signing_secret_and_keeps_its_others() {
        let dir = tempfile::TempDir::new().expect("temp dir");
        let path = dir.path().join("appliance.db");
        let to_0006: Vec<Migration> = platform()
            .iter()
            .filter(|m| m.version <= 6)
            .cloned()
            .collect();
        let pool = SqlitePool::connect_with(
            sqlx::sqlite::SqliteConnectOptions::new()
                .filename(&path)
                .create_if_missing(true),
        )
        .await
        .expect("connect");
        Migrator::new(Chain(to_0006))
            .await
            .expect("chain")
            .run(&pool)
            .await
            .expect("the schema at 0006");
        for key in ["secret.session_signing", "secret.kept"] {
            sqlx::query("INSERT INTO settings (key, value, updated_at) VALUES (?, 'x', 'x')")
                .bind(key)
                .execute(&pool)
                .await
                .expect("a secret");
        }
        pool.close().await;

        let store = crate::Store::open(&path, None)
            .await
            .expect("migrates forward");
        assert!(
            store
                .secret("session_signing")
                .await
                .expect("read")
                .is_none()
        );
        assert!(store.secret("kept").await.expect("read").is_some());
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
