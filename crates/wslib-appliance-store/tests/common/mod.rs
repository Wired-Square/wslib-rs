use std::borrow::Cow;
use std::path::Path;

use sqlx::error::BoxDynError;
use sqlx::migrate::{Migrate, MigrateError, Migration, MigrationSource, MigrationType, Migrator};
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePool};
use wslib_appliance_store::sqlx;

#[derive(Debug)]
struct Resolved(Vec<Migration>);

impl MigrationSource<'static> for Resolved {
    fn resolve(
        self,
    ) -> std::pin::Pin<Box<dyn Future<Output = Result<Vec<Migration>, BoxDynError>> + Send + 'static>>
    {
        Box::pin(async move { Ok(self.0) })
    }
}

pub async fn migrator(migrations: impl IntoIterator<Item = Migration>) -> Migrator {
    Migrator::new(Resolved(migrations.into_iter().collect()))
        .await
        .expect("migrator")
}

pub fn migration(version: i64, sql: &str) -> Migration {
    Migration::new(
        version,
        Cow::Owned(format!("trial {version}")),
        MigrationType::Simple,
        Cow::Owned(sql.to_string()),
        false,
    )
}

pub fn platform() -> Migrator {
    sqlx::migrate!("./migrations")
}

pub async fn pool(path: &Path) -> SqlitePool {
    SqlitePool::connect_with(
        SqliteConnectOptions::new()
            .filename(path)
            .create_if_missing(true)
            .journal_mode(SqliteJournalMode::Wal)
            .foreign_keys(true),
    )
    .await
    .expect("connect")
}

pub async fn registry(path: &Path) -> Vec<(String, bool)> {
    let pool = pool(path).await;
    let rows = sqlx::query_as("SELECT name, mirrored FROM _migration_chains ORDER BY name")
        .fetch_all(&pool)
        .await
        .expect("registry");
    pool.close().await;
    rows
}

pub fn both_mirrored() -> [(String, bool); 2] {
    [("app".to_string(), true), ("platform".to_string(), true)]
}

async fn previous_chain(app: &Migrator) -> Migrator {
    migrator(platform().iter().chain(app.iter()).cloned()).await
}

/// The previous build's `Store::open`: sqlx's runner over both chains as one.
pub async fn previous_build(path: &Path, app: &Migrator) -> Result<(), MigrateError> {
    let chain = previous_chain(app).await;
    let pool = pool(path).await;
    let ran = chain.run(&pool).await;
    pool.close().await;
    ran
}

/// The previous build's `Store::open_existing`: every version of its chain
/// applied, and none it lacks.
pub async fn previous_build_offline(path: &Path, app: &Migrator) -> Result<(), String> {
    let chain = previous_chain(app).await;
    let pool = pool(path).await;
    let mut conn = pool.acquire().await.expect("acquire");
    let applied: Vec<i64> = conn
        .list_applied_migrations()
        .await
        .map_err(|e| e.to_string())?
        .into_iter()
        .map(|m| m.version)
        .collect();
    drop(conn);
    pool.close().await;
    if let Some(behind) = chain.iter().find(|m| !applied.contains(&m.version)) {
        return Err(format!("behind at {}", behind.version));
    }
    match applied
        .iter()
        .find(|v| !chain.iter().any(|m| m.version == **v))
    {
        Some(ahead) => Err(format!("ahead at {ahead}")),
        None => Ok(()),
    }
}
