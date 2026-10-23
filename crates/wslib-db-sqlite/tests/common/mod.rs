use std::borrow::Cow;

use wslib_db_sqlite::Chain;
use wslib_db_sqlite::sqlx::error::BoxDynError;
use wslib_db_sqlite::sqlx::migrate::{Migration, MigrationSource, MigrationType, Migrator};

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

pub fn migration(version: i64, sql: &str) -> Migration {
    Migration::new(
        version,
        Cow::Owned(format!("migration {version}")),
        MigrationType::Simple,
        Cow::Owned(sql.to_string()),
        false,
    )
}

/// A `Migrator` as sqlx's own `migrate!` would build it.
pub async fn migrator(migrations: impl IntoIterator<Item = Migration>) -> Migrator {
    Migrator::new(Resolved(migrations.into_iter().collect()))
        .await
        .expect("migrator")
}

pub async fn chain(name: &str, migrations: &[(i64, &str)]) -> Chain {
    let migrations = migrations.iter().map(|&(v, sql)| migration(v, sql));
    Chain::new(name, &migrator(migrations).await)
}
