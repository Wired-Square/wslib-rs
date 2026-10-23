mod common;

use std::path::Path;

use common::{chain, migration, migrator};
use wslib_db_sqlite::sqlx::migrate::MigrateError;
use wslib_db_sqlite::sqlx::sqlite::{SqliteConnectOptions, SqlitePool};
use wslib_db_sqlite::sqlx::{self, Row};
use wslib_db_sqlite::{Chain, Database, Error};

const LIB: &[(i64, &str)] = &[
    (1, "CREATE TABLE lib_a (x TEXT)"),
    (2, "CREATE TABLE lib_b (x TEXT)"),
];
const APP: &[(i64, &str)] = &[(1000, "CREATE TABLE widgets (name TEXT)")];
const BROKEN: &str = "CREATE TABLE nonsense (";

fn with(base: &[(i64, &'static str)], more: &[(i64, &'static str)]) -> Vec<(i64, &'static str)> {
    base.iter().chain(more).copied().collect()
}

async fn chains(lib: &[(i64, &str)], app: &[(i64, &str)]) -> [Chain; 2] {
    [chain("lib", lib).await, chain("app", app).await]
}

async fn versions(pool: &SqlitePool, table: &str) -> Vec<i64> {
    sqlx::query_scalar(&format!("SELECT version FROM {table} ORDER BY version"))
        .fetch_all(pool)
        .await
        .unwrap_or_default()
}

async fn tables(pool: &SqlitePool) -> Vec<String> {
    sqlx::query_scalar(
        "SELECT name FROM sqlite_master WHERE type = 'table' \
         AND name NOT LIKE 'sqlite_%' ORDER BY name",
    )
    .fetch_all(pool)
    .await
    .unwrap()
}

/// Run sqlx's own runner over `lib` then `app`, concatenated into one chain,
/// as a build before this crate did.
async fn sqlx_runner(
    path: &Path,
    lib: &[(i64, &str)],
    app: &[(i64, &str)],
) -> Result<(), MigrateError> {
    let pool = SqlitePool::connect_with(
        SqliteConnectOptions::new()
            .filename(path)
            .create_if_missing(true),
    )
    .await
    .expect("connect");
    let concatenated = lib.iter().chain(app).map(|&(v, sql)| migration(v, sql));
    let ran = migrator(concatenated).await.run(&pool).await;
    pool.close().await;
    ran
}

async fn open(path: &Path, lib: &[(i64, &str)], app: &[(i64, &str)]) -> Result<Database, Error> {
    Database::open(path, &chains(lib, app).await).await
}

#[tokio::test]
async fn a_fresh_database_takes_every_chain_and_keeps_each_in_its_own_table() {
    let db = Database::open_in_memory(&chains(LIB, APP).await)
        .await
        .expect("open");
    assert_eq!(versions(db.pool(), "lib_migrations").await, [1, 2]);
    assert_eq!(versions(db.pool(), "app_migrations").await, [1000]);
    assert_eq!(
        tables(db.pool()).await,
        [
            "app_migrations",
            "lib_a",
            "lib_b",
            "lib_migrations",
            "widgets"
        ],
        "a chain never imported never makes _sqlx_migrations"
    );

    let row = sqlx::query(
        "SELECT description, checksum, installed_on FROM lib_migrations WHERE version = 1",
    )
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(row.get::<String, _>("description"), "migration 1");
    assert_eq!(row.get::<String, _>("checksum").len(), 96, "SHA-384 in hex");
    wslib_db_sqlite::stamp::from_row(&row, "lib_migrations", "installed_on").expect("a stamp");
}

#[tokio::test]
async fn two_chains_may_number_alike() {
    let db = Database::open_in_memory(&chains(LIB, &[(1, "CREATE TABLE app_a (x TEXT)")]).await)
        .await
        .expect("open");
    assert_eq!(versions(db.pool(), "app_migrations").await, [1]);
}

#[tokio::test]
async fn a_migration_added_to_an_earlier_chain_after_a_later_one_applied_runs_at_the_next_open() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("app.db");
    open(&path, &LIB[..1], APP)
        .await
        .expect("open")
        .close()
        .await;

    let db = open(&path, LIB, APP).await.expect("reopen");
    assert_eq!(versions(db.pool(), "lib_migrations").await, [1, 2]);
    assert!(tables(db.pool()).await.contains(&"lib_b".to_string()));
    db.close().await;
}

#[tokio::test]
async fn a_failing_migration_in_a_later_chain_rolls_back_an_earlier_chains_too() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("app.db");
    open(&path, &LIB[..1], APP)
        .await
        .expect("open")
        .close()
        .await;

    let failed = open(&path, LIB, &with(APP, &[(1001, BROKEN)])).await;
    assert!(
        matches!(&failed, Err(Error::Migrate { chain, source: MigrateError::ExecuteMigration(_, 1001) }) if chain == "app"),
        "{failed:?}"
    );

    let db = Database::open_existing(&path, &chains(&LIB[..1], APP).await)
        .await
        .expect("exactly as it was");
    assert_eq!(versions(db.pool(), "lib_migrations").await, [1]);
    assert!(!tables(db.pool()).await.contains(&"lib_b".to_string()));
    db.close().await;
}

#[tokio::test]
async fn a_failure_on_a_fresh_database_leaves_no_bookkeeping() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("app.db");
    assert!(open(&path, LIB, &[(1000, BROKEN)]).await.is_err());
    let db = Database::open(&path, &[])
        .await
        .expect("open with no chains");
    assert!(
        tables(db.pool()).await.is_empty(),
        "{:?}",
        tables(db.pool()).await
    );
    db.close().await;
}

#[tokio::test]
async fn open_existing_refuses_a_database_behind_or_ahead_of_a_chain() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("app.db");
    open(&path, &LIB[..1], APP)
        .await
        .expect("open")
        .close()
        .await;

    let behind = Database::open_existing(&path, &chains(LIB, APP).await).await;
    assert!(
        matches!(&behind, Err(Error::SchemaBehind { chain, version: 2 }) if chain == "lib"),
        "{behind:?}"
    );

    let unknown = chain("extra", &[(5, "SELECT 1")]).await;
    let no_table = Database::open_existing(&path, &[unknown]).await;
    assert!(
        matches!(&no_table, Err(Error::SchemaBehind { chain, version: 5 }) if chain == "extra"),
        "a chain with no table is behind at its first version: {no_table:?}"
    );

    for refused in [
        Database::open_existing(&path, &chains(&[], APP).await).await,
        open(&path, &[], APP).await,
    ] {
        assert!(
            matches!(&refused, Err(Error::Migrate { chain, source: MigrateError::VersionMissing(1) }) if chain == "lib"),
            "ahead of the chain: {refused:?}"
        );
    }

    Database::open_existing(&path, &chains(&LIB[..1], APP).await)
        .await
        .expect("exactly at both")
        .close()
        .await;
}

#[tokio::test]
async fn a_modified_applied_migration_is_refused_naming_its_chain_and_version() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("app.db");
    open(&path, LIB, APP).await.expect("open").close().await;

    let edited = [(1, "CREATE TABLE lib_a (x TEXT) -- edited"), LIB[1]];
    for refused in [
        open(&path, &edited, APP).await,
        Database::open_existing(&path, &chains(&edited, APP).await).await,
    ] {
        assert!(
            matches!(&refused, Err(Error::Migrate { chain, source: MigrateError::VersionMismatch(1) }) if chain == "lib"),
            "{refused:?}"
        );
    }
}

#[tokio::test]
async fn a_pending_no_transaction_migration_is_refused() {
    let mut no_tx = migration(3, "VACUUM");
    no_tx.no_tx = true;
    let lib = LIB.iter().map(|&(v, sql)| migration(v, sql)).chain([no_tx]);
    let lib = Chain::new("lib", &migrator(lib).await);
    let refused = Database::open_in_memory(&[lib]).await;
    assert!(
        matches!(&refused, Err(Error::NoTransaction { chain, version: 3 }) if chain == "lib"),
        "{refused:?}"
    );
}

#[tokio::test]
async fn a_database_from_sqlx_runner_is_imported_and_the_old_build_still_refuses_a_newer_schema() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("app.db");
    sqlx_runner(&path, LIB, APP).await.expect("the old build");

    let db = open(&path, LIB, APP).await.expect("imports");
    assert_eq!(versions(db.pool(), "lib_migrations").await, [1, 2]);
    assert_eq!(versions(db.pool(), "app_migrations").await, [1000]);
    assert_eq!(versions(db.pool(), "_sqlx_migrations").await, [1, 2, 1000]);
    let imported: Vec<String> =
        sqlx::query_scalar("SELECT name FROM _imported_chains ORDER BY name")
            .fetch_all(db.pool())
            .await
            .unwrap();
    assert_eq!(imported, ["app", "lib"]);
    db.close().await;

    sqlx_runner(&path, LIB, APP)
        .await
        .expect("the old build opens an unchanged schema");

    let newer = with(APP, &[(1001, "CREATE TABLE gadgets (name TEXT)")]);
    let db = open(&path, LIB, &newer).await.expect("applies 1001");
    assert_eq!(
        versions(db.pool(), "_sqlx_migrations").await,
        [1, 2, 1000, 1001]
    );
    let row = sqlx::query(
        "SELECT description, success, checksum FROM _sqlx_migrations WHERE version = 1001",
    )
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(row.get::<String, _>("description"), "migration 1001");
    assert!(row.get::<bool, _>("success"));
    assert_eq!(
        row.get::<Vec<u8>, _>("checksum"),
        migration(1001, newer[1].1).checksum.to_vec()
    );
    db.close().await;

    let old = sqlx_runner(&path, LIB, APP).await;
    assert!(
        matches!(old, Err(MigrateError::VersionMissing(1001))),
        "{old:?}"
    );
    sqlx_runner(&path, LIB, &newer)
        .await
        .expect("a build that knows 1001 sees exactly what its runner would have written");
}

#[tokio::test]
async fn an_import_interrupted_leaves_sqlx_bookkeeping_untouched_and_runs_again() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("app.db");
    sqlx_runner(&path, LIB, APP).await.expect("the old build");

    let lib = with(LIB, &[(3, "CREATE TABLE lib_c (x TEXT)")]);
    assert!(
        open(&path, &lib, &with(APP, &[(1001, BROKEN)]))
            .await
            .is_err()
    );

    let pool = SqlitePool::connect_with(SqliteConnectOptions::new().filename(&path))
        .await
        .unwrap();
    assert_eq!(
        tables(&pool).await,
        ["_sqlx_migrations", "lib_a", "lib_b", "widgets"]
    );
    assert_eq!(versions(&pool, "_sqlx_migrations").await, [1, 2, 1000]);
    pool.close().await;

    let app = with(APP, &[(1001, "CREATE TABLE gadgets (name TEXT)")]);
    let db = open(&path, &lib, &app)
        .await
        .expect("imports again, then applies");
    assert_eq!(versions(db.pool(), "lib_migrations").await, [1, 2, 3]);
    assert_eq!(versions(db.pool(), "app_migrations").await, [1000, 1001]);
    assert_eq!(
        versions(db.pool(), "_sqlx_migrations").await,
        [1, 2, 3, 1000, 1001]
    );
    db.close().await;
}

#[tokio::test]
async fn an_import_refuses_a_row_no_chain_or_two_chains_have_or_whose_checksum_differs() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("app.db");
    sqlx_runner(&path, LIB, APP).await.expect("the old build");

    let unclaimed = open(&path, LIB, &[]).await;
    assert!(
        matches!(unclaimed, Err(Error::Unclaimed { version: 1000 })),
        "{unclaimed:?}"
    );

    let ambiguous = open(&path, LIB, &with(&LIB[1..], APP)).await;
    assert!(
        matches!(&ambiguous, Err(Error::Ambiguous { version: 2, chain, other }) if chain == "lib" && other == "app"),
        "{ambiguous:?}"
    );

    let edited = [(1000, "CREATE TABLE widgets (name TEXT) -- edited")];
    let mismatch = open(&path, LIB, &edited).await;
    assert!(
        matches!(&mismatch, Err(Error::Migrate { chain, source: MigrateError::VersionMismatch(1000) }) if chain == "app"),
        "{mismatch:?}"
    );

    open(&path, LIB, APP)
        .await
        .expect("none of that was kept")
        .close()
        .await;
}

#[tokio::test]
async fn imported_chains_whose_versions_collide_refuse_the_open_before_anything_applies() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("app.db");
    sqlx_runner(&path, LIB, APP).await.expect("the old build");
    open(&path, LIB, APP).await.expect("imports").close().await;

    let app = with(APP, &[(2, "CREATE TABLE gadgets (name TEXT)")]);
    let held = open(&path, LIB, &app).await;
    assert!(
        matches!(&held, Err(Error::Collision { version: 2, chain, other }) if chain == "app" && other == "lib"),
        "a version _sqlx_migrations holds for lib: {held:?}"
    );

    let lib = with(LIB, &[(3, "CREATE TABLE lib_c (x TEXT)")]);
    let app = with(APP, &[(3, "CREATE TABLE gadgets (name TEXT)")]);
    let both = open(&path, &lib, &app).await;
    assert!(
        matches!(&both, Err(Error::Collision { version: 3, chain, other }) if chain == "app" && other == "lib"),
        "a version both would write: {both:?}"
    );

    let db = open(&path, LIB, APP).await.expect("nothing applied");
    assert_eq!(versions(db.pool(), "_sqlx_migrations").await, [1, 2, 1000]);
    assert_eq!(versions(db.pool(), "lib_migrations").await, [1, 2]);
    db.close().await;
}

#[tokio::test]
async fn a_chain_added_after_the_import_never_touches_sqlx_bookkeeping() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("app.db");
    sqlx_runner(&path, LIB, APP).await.expect("the old build");
    open(&path, LIB, APP).await.expect("imports").close().await;

    let mut all = chains(LIB, APP).await.to_vec();
    all.push(chain("extra", &[(1, "CREATE TABLE extra_a (x TEXT)")]).await);
    let db = Database::open(&path, &all).await.expect("open");
    assert_eq!(versions(db.pool(), "extra_migrations").await, [1]);
    assert_eq!(versions(db.pool(), "_sqlx_migrations").await, [1, 2, 1000]);
    db.close().await;
}

#[tokio::test]
async fn a_chain_empty_at_the_first_import_still_dual_writes_its_first_migration() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("app.db");
    sqlx_runner(&path, LIB, &[])
        .await
        .expect("the old build, with no app migrations");
    open(&path, LIB, &[]).await.expect("imports").close().await;

    let db = open(&path, LIB, APP).await.expect("applies 1000");
    assert_eq!(versions(db.pool(), "_sqlx_migrations").await, [1, 2, 1000]);
    db.close().await;

    let old = sqlx_runner(&path, LIB, &[]).await;
    assert!(
        matches!(old, Err(MigrateError::VersionMissing(1000))),
        "{old:?}"
    );
}
