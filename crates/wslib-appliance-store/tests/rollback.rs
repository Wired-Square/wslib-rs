//! A database the previous build made, on sqlx's own runner over one
//! concatenated chain, opened by this one, and by the previous build again.

mod common;

use std::path::{Path, PathBuf};

use common::{
    both_mirrored, migration, migrator, platform, pool, previous_build, previous_build_offline,
    registry,
};
use sqlx::migrate::{MigrateError, Migration, Migrator};
use tempfile::TempDir;
use wslib_appliance_store::{Store, StoreError, sqlx};
use wslib_db_sqlite::{Chain, Database, Error as DatabaseError};

fn app() -> Migrator {
    sqlx::migrate!("./test-migrations/app")
}

async fn app_and(extra: &[Migration]) -> Migrator {
    migrator(app().iter().cloned().chain(extra.iter().cloned())).await
}

const PREVIOUS_VERSIONS: [i64; 9] = [1, 2, 3, 4, 5, 6, 7, 8, 1000];

/// A database as the previous build leaves it, with an account and a setting.
async fn previous_database(dir: &TempDir, app: &Migrator) -> PathBuf {
    let path = dir.path().join("appliance.db");
    previous_build(&path, app)
        .await
        .expect("the previous chain");
    let pool = pool(&path).await;
    let now = wslib_appliance_store::stamp(wslib_appliance_store::now());
    sqlx::query(
        "INSERT INTO users (id, username, password_hash, role, created_at, updated_at, \
         sessions_valid_from) VALUES ('u1', 'admin', 'h', 'admin', ?1, ?1, ?1)",
    )
    .bind(&now)
    .execute(&pool)
    .await
    .expect("an account");
    sqlx::query("INSERT INTO settings VALUES ('branding.app_name', 'Widgets', ?1)")
        .bind(&now)
        .execute(&pool)
        .await
        .expect("a setting");
    pool.close().await;
    path
}

/// Every schema object and every row of every table, for "exactly as before".
async fn everything(path: &Path) -> Vec<String> {
    let pool = pool(path).await;
    let mut out: Vec<String> = sqlx::query_as::<_, (String, String, Option<String>)>(
        "SELECT type, name, sql FROM sqlite_master ORDER BY name",
    )
    .fetch_all(&pool)
    .await
    .expect("schema")
    .into_iter()
    .map(|row| format!("{row:?}"))
    .collect();
    let tables: Vec<String> = sqlx::query_scalar(
        "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' \
         ORDER BY name",
    )
    .fetch_all(&pool)
    .await
    .expect("tables");
    for table in tables {
        let columns: Vec<String> =
            sqlx::query_scalar(&format!("SELECT name FROM pragma_table_info('{table}')"))
                .fetch_all(&pool)
                .await
                .expect("columns");
        let row = columns
            .iter()
            .map(|c| format!("quote({c})"))
            .collect::<Vec<_>>()
            .join(" || ',' || ");
        let rows: Vec<String> =
            sqlx::query_scalar(&format!("SELECT {row} FROM {table} ORDER BY 1"))
                .fetch_all(&pool)
                .await
                .expect("rows");
        out.extend(rows.into_iter().map(|row| format!("{table}: {row}")));
    }
    pool.close().await;
    out
}

async fn rows(path: &Path, sql: &str) -> Vec<(i64, String)> {
    let pool = pool(path).await;
    let rows = sqlx::query_as(sql).fetch_all(&pool).await.expect(sql);
    pool.close().await;
    rows
}

fn versions(rows: &[(i64, String)]) -> Vec<i64> {
    rows.iter().map(|(v, _)| *v).collect()
}

async fn legacy(path: &Path) -> Vec<(i64, String)> {
    rows(
        path,
        "SELECT version, lower(hex(checksum)) FROM _sqlx_migrations ORDER BY version",
    )
    .await
}

#[tokio::test]
async fn a_previous_database_is_imported_with_its_rows_checksums_and_app_schema_version() {
    let dir = TempDir::new().expect("temp dir");
    let path = previous_database(&dir, &app()).await;
    let before = legacy(&path).await;
    let untouched = everything(&path).await;
    assert_eq!(versions(&before), PREVIOUS_VERSIONS);

    let store = Store::open(&path, Some(app())).await.expect("imports");
    assert_eq!(store.app_schema_version(), 1000);
    assert!(store.user_by_id("u1").await.expect("read").is_some());
    assert_eq!(
        store.setting("branding.app_name").await.expect("read"),
        Some("Widgets".to_string())
    );
    store.close().await;

    let platform = rows(
        &path,
        "SELECT version, checksum FROM _platform_migrations ORDER BY version",
    )
    .await;
    let app_rows = rows(
        &path,
        "SELECT version, checksum FROM _app_migrations ORDER BY version",
    )
    .await;
    assert_eq!(
        [platform, app_rows].concat(),
        before,
        "every row, checksum intact"
    );
    assert_eq!(legacy(&path).await, before, "sqlx's own table untouched");
    assert_ne!(
        everything(&path).await,
        untouched,
        "the comparison sees the import"
    );
    assert_eq!(registry(&path).await, both_mirrored());

    Store::open(&path, Some(app()))
        .await
        .expect("a second open finds nothing to do")
        .close()
        .await;
    Store::open_existing(&path, Some(app()))
        .await
        .expect("an offline open sees it current")
        .close()
        .await;
}

#[tokio::test]
async fn a_database_before_0007_gains_it_in_both_records_in_the_importing_open() {
    let dir = TempDir::new().expect("temp dir");
    let path = dir.path().join("appliance.db");
    let pool = pool(&path).await;
    let (platform, app_migrations) = (platform(), app());
    let before_0007 = platform.iter().filter(|m| m.version < 7);
    migrator(before_0007.chain(app_migrations.iter()).cloned())
        .await
        .run(&pool)
        .await
        .expect("a build before 0007");
    pool.close().await;

    Store::open(&path, Some(app()))
        .await
        .expect("imports, then applies 0007")
        .close()
        .await;
    let platform = rows(
        &path,
        "SELECT version, checksum FROM _platform_migrations ORDER BY version",
    )
    .await;
    assert_eq!(versions(&platform), [1, 2, 3, 4, 5, 6, 7, 8]);
    assert_eq!(versions(&legacy(&path).await), PREVIOUS_VERSIONS);
    previous_build(&path, &app())
        .await
        .expect("a build with 0007 opens it");
}

#[tokio::test]
async fn a_database_at_0006_loses_the_token_signing_secret_and_keeps_its_others() {
    let dir = TempDir::new().expect("temp dir");
    let path = dir.path().join("appliance.db");
    let to_0006 = migrator(platform().iter().filter(|m| m.version <= 6).cloned()).await;
    let pool = pool(&path).await;
    to_0006.run(&pool).await.expect("the schema at 0006");
    for key in ["secret.session_signing", "secret.kept"] {
        sqlx::query("INSERT INTO settings (key, value, updated_at) VALUES (?, 'x', 'x')")
            .bind(key)
            .execute(&pool)
            .await
            .expect("a secret");
    }
    pool.close().await;

    let store = Store::open(&path, None).await.expect("migrates forward");
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

#[tokio::test]
async fn the_previous_build_still_opens_an_imported_database_with_nothing_to_do() {
    let dir = TempDir::new().expect("temp dir");
    let path = previous_database(&dir, &app()).await;
    Store::open(&path, Some(app()))
        .await
        .expect("imports")
        .close()
        .await;
    let before = everything(&path).await;

    previous_build(&path, &app()).await.expect("nothing to do");
    previous_build_offline(&path, &app())
        .await
        .expect("and its offline open sees it current");
    assert_eq!(everything(&path).await, before);
}

#[tokio::test]
async fn the_previous_build_refuses_a_newer_app_schema_with_version_missing() {
    let dir = TempDir::new().expect("temp dir");
    let path = previous_database(&dir, &app()).await;
    let newer = app_and(&[migration(1001, "CREATE TABLE gadgets (id TEXT)")]).await;
    let store = Store::open(&path, Some(newer)).await.expect("1001 applies");
    assert_eq!(store.app_schema_version(), 1001);
    store.close().await;
    assert_eq!(legacy(&path).await.last().map(|(v, _)| *v), Some(1001));

    let refused = previous_build(&path, &app()).await;
    assert!(
        matches!(refused, Err(MigrateError::VersionMissing(1001))),
        "{refused:?}"
    );
    assert_eq!(
        previous_build_offline(&path, &app()).await,
        Err("ahead at 1001".to_string())
    );
}

#[tokio::test]
async fn a_build_with_fewer_app_migrations_is_refused_alike_before_and_after_the_import() {
    let dir = TempDir::new().expect("temp dir");
    let newer = app_and(&[migration(1001, "CREATE TABLE gadgets (id TEXT)")]).await;
    let path = previous_database(&dir, &newer).await;
    let is_1001_missing = |refused: &Result<Store, StoreError>| {
        matches!(
            refused,
            Err(StoreError::Migrate(MigrateError::VersionMissing(1001)))
        )
    };

    let refused = Store::open_existing(&path, Some(app())).await;
    assert!(is_1001_missing(&refused), "before, offline: {refused:?}");
    let refused = Store::open(&path, Some(app())).await;
    assert!(is_1001_missing(&refused), "before: {refused:?}");

    Store::open(&path, Some(newer))
        .await
        .expect("imports")
        .close()
        .await;
    let refused = Store::open(&path, Some(app())).await;
    assert!(is_1001_missing(&refused), "after: {refused:?}");
}

async fn with_gadgets() -> Migrator {
    app_and(&[migration(
        1001,
        "CREATE TABLE gadgets (id TEXT); INSERT INTO gadgets VALUES ('ran')",
    )])
    .await
}

/// Imported by this build, then rolled back to the previous one, which applies 1001.
async fn rolled_back_and_1001_applied(dir: &TempDir) -> PathBuf {
    let path = previous_database(dir, &app()).await;
    Store::open(&path, Some(app()))
        .await
        .expect("imports")
        .close()
        .await;
    previous_build(&path, &with_gadgets().await)
        .await
        .expect("the previous build applies 1001");
    path
}

#[tokio::test]
async fn a_migration_the_previous_build_applied_after_the_import_is_adopted_not_rerun() {
    let dir = TempDir::new().expect("temp dir");
    let path = rolled_back_and_1001_applied(&dir).await;
    let legacy_before = legacy(&path).await;

    let store = Store::open(&path, Some(with_gadgets().await))
        .await
        .expect("adopts 1001");
    assert_eq!(store.app_schema_version(), 1001);
    let runs: Vec<String> = sqlx::query_scalar("SELECT id FROM gadgets")
        .fetch_all(store.pool())
        .await
        .expect("gadgets");
    assert_eq!(runs, ["ran"], "1001's SQL ran once");
    store.close().await;

    let app_rows = rows(
        &path,
        "SELECT version, checksum FROM _app_migrations ORDER BY version",
    )
    .await;
    assert_eq!(
        app_rows,
        legacy_before[legacy_before.len() - 2..],
        "recorded with the previous build's checksum"
    );
    assert_eq!(legacy(&path).await, legacy_before);
    Store::open_existing(&path, Some(with_gadgets().await))
        .await
        .expect("an offline open sees it current")
        .close()
        .await;
}

#[tokio::test]
async fn a_migration_the_previous_build_applied_after_the_import_refuses_a_build_without_it() {
    let dir = TempDir::new().expect("temp dir");
    let path = rolled_back_and_1001_applied(&dir).await;
    let before = everything(&path).await;

    for refused in [
        Store::open(&path, Some(app())).await,
        Store::open_existing(&path, Some(app())).await,
    ] {
        assert!(
            matches!(
                refused,
                Err(StoreError::Migrate(MigrateError::VersionMissing(1001)))
            ),
            "{refused:?}"
        );
    }
    assert_eq!(everything(&path).await, before);
}

#[tokio::test]
async fn a_failed_row_after_the_import_is_dirty_and_changes_nothing() {
    let dir = TempDir::new().expect("temp dir");
    let path = previous_database(&dir, &app()).await;
    Store::open(&path, Some(app()))
        .await
        .expect("imports")
        .close()
        .await;
    let pool = pool(&path).await;
    sqlx::query("UPDATE _sqlx_migrations SET success = FALSE WHERE version = 1000")
        .execute(&pool)
        .await
        .expect("a failed row");
    pool.close().await;
    let before = everything(&path).await;

    for refused in [
        Store::open(&path, Some(app())).await,
        Store::open_existing(&path, Some(app())).await,
    ] {
        assert!(
            matches!(refused, Err(StoreError::Migrate(MigrateError::Dirty(1000)))),
            "{refused:?}"
        );
    }
    assert_eq!(everything(&path).await, before);
}

#[tokio::test]
async fn an_interrupted_import_leaves_the_database_exactly_as_it_was_and_retries_cleanly() {
    let dir = TempDir::new().expect("temp dir");
    let path = previous_database(&dir, &app()).await;
    let before = everything(&path).await;

    let failing = app_and(&[migration(1001, "INSERT INTO nowhere VALUES (1)")]).await;
    let refused = Store::open(&path, Some(failing)).await;
    assert!(
        matches!(
            &refused,
            Err(StoreError::Migrate(MigrateError::ExecuteMigration(_, 1001)))
        ),
        "{refused:?}"
    );
    assert_eq!(everything(&path).await, before, "not a row or table moved");

    let store = Store::open(&path, Some(app())).await.expect("retries");
    assert_eq!(store.app_schema_version(), 1000);
    store.close().await;
    previous_build(&path, &app())
        .await
        .expect("and the previous build still opens it");
}

fn parents_and_kids() -> Migration {
    migration(
        1001,
        "CREATE TABLE parents (id TEXT PRIMARY KEY); \
         CREATE TABLE kids (parent TEXT NOT NULL REFERENCES parents (id)); \
         INSERT INTO parents VALUES ('a'); INSERT INTO kids VALUES ('a');",
    )
}

/// SQLite's table rebuild of `parents`, copying the rows `copied` selects.
fn rebuild_parents(copied: &str) -> Migration {
    migration(
        1002,
        &format!(
            "CREATE TABLE parents_new (id TEXT PRIMARY KEY, extra TEXT); \
             INSERT INTO parents_new SELECT id, NULL FROM parents WHERE {copied}; \
             DROP TABLE parents; ALTER TABLE parents_new RENAME TO parents;"
        ),
    )
}

#[tokio::test]
async fn a_migration_may_rebuild_a_referenced_table() {
    let dir = TempDir::new().expect("temp dir");
    let path = dir.path().join("appliance.db");
    let rebuilt = app_and(&[parents_and_kids(), rebuild_parents("TRUE")]).await;
    let store = Store::open(&path, Some(rebuilt)).await.expect("rebuilds");
    assert_eq!(store.app_schema_version(), 1002);
    let joined: Vec<(String, Option<String>)> =
        sqlx::query_as("SELECT parent, extra FROM kids JOIN parents ON parents.id = kids.parent")
            .fetch_all(store.pool())
            .await
            .expect("kids and their parents");
    assert_eq!(joined, [("a".to_string(), None)]);
    store.close().await;
}

#[tokio::test]
async fn a_migration_that_leaves_a_reference_dangling_is_refused_and_changes_nothing() {
    let dir = TempDir::new().expect("temp dir");
    let path = dir.path().join("appliance.db");
    Store::open(&path, Some(app_and(&[parents_and_kids()]).await))
        .await
        .expect("1001")
        .close()
        .await;
    let before = everything(&path).await;

    let losing = app_and(&[parents_and_kids(), rebuild_parents("FALSE")]).await;
    let refused = Store::open(&path, Some(losing)).await;
    assert!(
        matches!(
            &refused,
            Err(StoreError::Migrate(MigrateError::ExecuteMigration(_, 1002)))
        ),
        "{refused:?}"
    );
    assert_eq!(everything(&path).await, before);
}

#[tokio::test]
async fn a_version_the_other_chain_holds_refuses_with_a_collision_before_anything_applies() {
    let dir = TempDir::new().expect("temp dir");
    let path = previous_database(&dir, &app()).await;
    Store::open(&path, Some(app()))
        .await
        .expect("imports")
        .close()
        .await;
    let before = everything(&path).await;

    // Below the app's floor, so only an open without the store's check can try it.
    let platform = platform();
    let colliding = app_and(&[
        migration(1001, "CREATE TABLE gadgets (id TEXT)"),
        migration(7, "CREATE TABLE sevens (id TEXT)"),
    ])
    .await;
    let refused = Database::open(
        &path,
        &[
            Chain::new("platform", &platform),
            Chain::new("app", &colliding),
        ],
    )
    .await;
    assert!(
        matches!(
            &refused,
            Err(DatabaseError::Collision { version: 7, chain, other })
                if chain == "app" && other == "platform"
        ),
        "{refused:?}"
    );
    assert_eq!(everything(&path).await, before, "1001 did not apply either");

    let platform_8 = migrator(
        platform
            .iter()
            .cloned()
            .chain([migration(8, "CREATE TABLE platform_eight (id TEXT)")]),
    )
    .await;
    let app_8 = app_and(&[migration(8, "CREATE TABLE app_eight (id TEXT)")]).await;
    let refused = Database::open(
        &path,
        &[
            Chain::new("platform", &platform_8),
            Chain::new("app", &app_8),
        ],
    )
    .await;
    assert!(
        matches!(&refused, Err(DatabaseError::Collision { version: 8, .. })),
        "both chains pending one new version: {refused:?}"
    );
    assert_eq!(everything(&path).await, before);
}

#[tokio::test]
async fn a_factory_reset_and_a_settings_restore_leave_the_migration_records_alone() {
    let dir = TempDir::new().expect("temp dir");
    let path = previous_database(&dir, &app()).await;
    let store = Store::open(&path, Some(app())).await.expect("imports");
    let records = |path| async move {
        let mut all = Vec::new();
        for table in ["_platform_migrations", "_app_migrations"] {
            all.extend(rows(path, &format!("SELECT version, checksum FROM {table}")).await);
        }
        all.extend(legacy(path).await);
        all
    };
    let before = records(&path).await;

    let mut tx = store.begin().await.expect("begin");
    store
        .replace_exportable_settings(&mut tx, &Default::default())
        .await
        .expect("restore");
    Store::erase_platform(&mut tx).await.expect("erase");
    sqlx::query("DELETE FROM app_widgets")
        .execute(&mut *tx)
        .await
        .expect("the product's half");
    tx.commit().await.expect("commit");
    store.close().await;

    assert_eq!(records(&path).await, before);
    previous_build(&path, &app())
        .await
        .expect("the previous build still opens it");
}

#[tokio::test]
async fn an_offline_open_before_the_import_reads_a_current_database_as_current_and_writes_nothing()
{
    let dir = TempDir::new().expect("temp dir");
    let path = previous_database(&dir, &app()).await;
    let before = everything(&path).await;

    let store = Store::open_existing(&path, Some(app()))
        .await
        .expect("current by sqlx's rules is current");
    assert_eq!(store.app_schema_version(), 1000);
    store.close().await;
    assert_eq!(everything(&path).await, before);

    let newer = app_and(&[migration(1001, "CREATE TABLE gadgets (id TEXT)")]).await;
    let behind = Store::open_existing(&path, Some(newer)).await;
    assert!(
        matches!(&behind, Err(StoreError::SchemaBehind { version: 1001 })),
        "{behind:?}"
    );
    assert_eq!(everything(&path).await, before);
}

#[tokio::test]
async fn a_fresh_database_with_mirrored_chains_opens_in_the_previous_build_and_refuses_newer() {
    let dir = TempDir::new().expect("temp dir");
    let path = dir.path().join("appliance.db");
    Store::open(&path, Some(app()))
        .await
        .expect("fresh")
        .close()
        .await;
    assert_eq!(versions(&legacy(&path).await), PREVIOUS_VERSIONS);
    let before = everything(&path).await;

    previous_build(&path, &app()).await.expect("nothing to do");
    previous_build_offline(&path, &app())
        .await
        .expect("current");
    assert_eq!(everything(&path).await, before, "and no schema change");

    let newer = app_and(&[migration(1001, "CREATE TABLE gadgets (id TEXT)")]).await;
    Store::open(&path, Some(newer))
        .await
        .expect("1001 applies")
        .close()
        .await;
    let refused = previous_build(&path, &app()).await;
    assert!(
        matches!(refused, Err(MigrateError::VersionMissing(1001))),
        "{refused:?}"
    );
}

#[tokio::test]
async fn a_build_without_a_registered_chain_is_refused_and_changes_nothing() {
    let dir = TempDir::new().expect("temp dir");
    let path = dir.path().join("appliance.db");
    Store::open(&path, Some(app()))
        .await
        .expect("both chains")
        .close()
        .await;
    let before = everything(&path).await;

    for refused in [
        Store::open(&path, None).await,
        Store::open_existing(&path, None).await,
    ] {
        assert!(
            matches!(
                &refused,
                Err(StoreError::Database(DatabaseError::UnknownChain(name))) if name == "app"
            ),
            "{refused:?}"
        );
    }
    assert_eq!(everything(&path).await, before);
}

#[tokio::test]
async fn a_stray_empty_sqlx_table_on_a_fresh_database_imports_nothing() {
    let dir = TempDir::new().expect("temp dir");
    let path = dir.path().join("appliance.db");
    let pool = pool(&path).await;
    sqlx::query(
        "CREATE TABLE _sqlx_migrations (version BIGINT PRIMARY KEY, description TEXT NOT NULL, \
         installed_on TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP, success BOOLEAN NOT NULL, \
         checksum BLOB NOT NULL, execution_time BIGINT NOT NULL)",
    )
    .execute(&pool)
    .await
    .expect("an empty table, as an older build's failed run leaves one");
    pool.close().await;

    Store::open(&path, Some(app()))
        .await
        .expect("fresh")
        .close()
        .await;
    assert_eq!(
        registry(&path).await,
        both_mirrored(),
        "mirrored because asked"
    );
    assert_eq!(
        versions(&legacy(&path).await),
        PREVIOUS_VERSIONS,
        "each written once, by the mirroring"
    );
    previous_build(&path, &app())
        .await
        .expect("the previous build opens it");
}
