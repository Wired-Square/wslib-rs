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
const GADGETS: &str = "CREATE TABLE gadgets (name TEXT)";

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
    assert_eq!(versions(db.pool(), "_lib_migrations").await, [1, 2]);
    assert_eq!(versions(db.pool(), "_app_migrations").await, [1000]);
    assert_eq!(
        tables(db.pool()).await,
        [
            "_app_migrations",
            "_lib_migrations",
            "_migration_chains",
            "lib_a",
            "lib_b",
            "widgets"
        ],
        "a chain not mirrored never makes _sqlx_migrations"
    );

    let row = sqlx::query(
        "SELECT description, checksum, installed_on FROM _lib_migrations WHERE version = 1",
    )
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(row.get::<String, _>("description"), "migration 1");
    assert_eq!(row.get::<String, _>("checksum").len(), 96, "SHA-384 in hex");
    wslib_db_sqlite::stamp::from_row(&row, "_lib_migrations", "installed_on").expect("a stamp");
}

#[tokio::test]
async fn two_chains_may_number_alike() {
    let db = Database::open_in_memory(&chains(LIB, &[(1, "CREATE TABLE app_a (x TEXT)")]).await)
        .await
        .expect("open");
    assert_eq!(versions(db.pool(), "_app_migrations").await, [1]);
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
    assert_eq!(versions(db.pool(), "_lib_migrations").await, [1, 2]);
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
    assert_eq!(versions(db.pool(), "_lib_migrations").await, [1]);
    assert!(!tables(db.pool()).await.contains(&"lib_b".to_string()));
    db.close().await;
}

#[tokio::test]
async fn a_failure_on_a_fresh_database_leaves_no_bookkeeping() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("app.db");
    assert!(open(&path, LIB, &[(1000, BROKEN)]).await.is_err());
    let db = Database::open_existing(&path, &[])
        .await
        .expect("open, writing nothing");
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

    let mut with_extra = chains(&LIB[..1], APP).await.to_vec();
    with_extra.push(chain("extra", &[(5, "SELECT 1")]).await);
    let no_table = Database::open_existing(&path, &with_extra).await;
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
    assert_eq!(versions(db.pool(), "_lib_migrations").await, [1, 2]);
    assert_eq!(versions(db.pool(), "_app_migrations").await, [1000]);
    assert_eq!(versions(db.pool(), "_sqlx_migrations").await, [1, 2, 1000]);
    let imported: Vec<String> =
        sqlx::query_scalar("SELECT name FROM _migration_chains WHERE mirrored ORDER BY name")
            .fetch_all(db.pool())
            .await
            .unwrap();
    assert_eq!(imported, ["app", "lib"]);
    db.close().await;

    sqlx_runner(&path, LIB, APP)
        .await
        .expect("the old build opens an unchanged schema");

    let newer = with(APP, &[(1001, GADGETS)]);
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

    let app = with(APP, &[(1001, GADGETS)]);
    let db = open(&path, &lib, &app)
        .await
        .expect("imports again, then applies");
    assert_eq!(versions(db.pool(), "_lib_migrations").await, [1, 2, 3]);
    assert_eq!(versions(db.pool(), "_app_migrations").await, [1000, 1001]);
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
    assert_eq!(versions(db.pool(), "_lib_migrations").await, [1, 2]);
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
    assert_eq!(versions(db.pool(), "_extra_migrations").await, [1]);
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

async fn open_existing(
    path: &Path,
    lib: &[(i64, &str)],
    app: &[(i64, &str)],
) -> Result<Database, Error> {
    Database::open_existing(path, &chains(lib, app).await).await
}

#[tokio::test]
async fn a_registered_chain_the_open_does_not_name_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("app.db");
    open(&path, LIB, APP).await.expect("open").close().await;

    let lib_only = [chain("lib", LIB).await];
    for refused in [
        Database::open(&path, &lib_only).await,
        Database::open_existing(&path, &lib_only).await,
    ] {
        assert!(
            matches!(&refused, Err(Error::UnknownChain(name)) if name == "app"),
            "{refused:?}"
        );
    }
}

#[tokio::test]
async fn a_stray_empty_sqlx_table_is_never_imported_nor_written() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("app.db");
    let db = open(&path, LIB, APP)
        .await
        .expect("a fresh database, not mirrored");
    sqlx::query(
        "CREATE TABLE _sqlx_migrations (version BIGINT PRIMARY KEY, description TEXT NOT NULL, \
         installed_on TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP, success BOOLEAN NOT NULL, \
         checksum BLOB NOT NULL, execution_time BIGINT NOT NULL)",
    )
    .execute(db.pool())
    .await
    .unwrap();
    db.close().await;

    let app = with(APP, &[(1001, GADGETS)]);
    let db = open(&path, LIB, &app).await.expect("reopen");
    assert_eq!(versions(db.pool(), "_app_migrations").await, [1000, 1001]);
    assert!(versions(db.pool(), "_sqlx_migrations").await.is_empty());
    let mirrored: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM _migration_chains WHERE mirrored")
        .fetch_one(db.pool())
        .await
        .unwrap();
    assert_eq!(mirrored, 0);
    db.close().await;
}

#[tokio::test]
async fn mirrored_chains_on_a_fresh_database_satisfy_sqlx_runner_until_a_newer_migration() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("app.db");
    let mirrored = |lib: Chain, app: Chain| [lib.mirrored(), app.mirrored()];
    let [lib, app] = chains(LIB, APP).await;
    Database::open(&path, &mirrored(lib, app))
        .await
        .expect("open")
        .close()
        .await;

    sqlx_runner(&path, LIB, APP)
        .await
        .expect("an older build finds every version it knows");

    let newer = with(APP, &[(1001, GADGETS)]);
    let [lib, app] = chains(LIB, &newer).await;
    Database::open(&path, &mirrored(lib, app))
        .await
        .expect("applies 1001")
        .close()
        .await;
    let old = sqlx_runner(&path, LIB, APP).await;
    assert!(
        matches!(old, Err(MigrateError::VersionMissing(1001))),
        "{old:?}"
    );
}

#[tokio::test]
async fn a_row_in_sqlx_table_whose_checksum_differs_from_its_mirrored_chain_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("app.db");
    let lib = chain("lib", &LIB[..1]).await.mirrored();
    let db = Database::open(&path, &[lib]).await.expect("open");
    sqlx::query(
        "INSERT INTO _sqlx_migrations (version, description, success, checksum, execution_time) \
         VALUES (2, 'stray', TRUE, x'00', 0)",
    )
    .execute(db.pool())
    .await
    .unwrap();
    db.close().await;

    let lib = [chain("lib", LIB).await.mirrored()];
    for refused in [
        Database::open(&path, &lib).await,
        Database::open_existing(&path, &lib).await,
    ] {
        assert!(
            matches!(&refused, Err(Error::Migrate { chain, source: MigrateError::VersionMismatch(2) }) if chain == "lib"),
            "{refused:?}"
        );
    }
}

/// Imported at `APP`, then rolled back to a build on sqlx's runner that
/// applied 1001.
async fn rolled_back_past_1001(path: &Path) {
    sqlx_runner(path, LIB, APP).await.expect("the old build");
    open(path, LIB, APP).await.expect("imports").close().await;
    sqlx_runner(path, LIB, &with(APP, &[(1001, GADGETS)]))
        .await
        .expect("the old build applies 1001");
}

#[tokio::test]
async fn a_migration_sqlx_runner_applied_after_the_import_is_adopted_not_run_again() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("app.db");
    rolled_back_past_1001(&path).await;

    let app = with(APP, &[(1001, GADGETS)]);
    open_existing(&path, LIB, &app)
        .await
        .expect("current, counting 1001")
        .close()
        .await;

    let app = with(&app, &[(1002, "CREATE TABLE gizmos (name TEXT)")]);
    let db = open(&path, LIB, &app)
        .await
        .expect("adopts 1001, which would fail if run again, and applies 1002");
    assert_eq!(
        versions(db.pool(), "_app_migrations").await,
        [1000, 1001, 1002]
    );
    assert_eq!(
        versions(db.pool(), "_sqlx_migrations").await,
        [1, 2, 1000, 1001, 1002]
    );
    db.close().await;
    open_existing(&path, LIB, &app)
        .await
        .expect("current")
        .close()
        .await;
}

#[tokio::test]
async fn a_build_without_a_migration_sqlx_runner_applied_after_the_import_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("app.db");
    rolled_back_past_1001(&path).await;

    for refused in [
        open_existing(&path, LIB, APP).await,
        open(&path, LIB, APP).await,
    ] {
        assert!(
            matches!(refused, Err(Error::Unclaimed { version: 1001 })),
            "{refused:?}"
        );
    }
}

const PARENTS_AND_CHILDREN: &str = "CREATE TABLE parents (id INTEGER PRIMARY KEY);
     CREATE TABLE children (id INTEGER PRIMARY KEY, parent INTEGER REFERENCES parents (id));";

#[tokio::test]
async fn a_migration_that_leaves_a_dangling_reference_fails_as_that_migration() {
    let app = [
        (1, PARENTS_AND_CHILDREN),
        (2, "INSERT INTO children (parent) VALUES (9)"),
    ];
    let failed = Database::open_in_memory(&[chain("app", &app).await]).await;
    let Err(Error::Migrate {
        chain,
        source: MigrateError::ExecuteMigration(e, 2),
    }) = &failed
    else {
        panic!("{failed:?}");
    };
    assert_eq!(chain, "app");
    assert!(
        e.as_database_error()
            .is_some_and(|e| e.is_foreign_key_violation()),
        "{e:?}"
    );
}

#[tokio::test]
async fn a_reference_dangling_before_the_open_is_not_blamed_on_a_migration() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("app.db");
    let app = [(1, PARENTS_AND_CHILDREN)];
    open(&path, &[], &app).await.expect("open").close().await;
    let pool = SqlitePool::connect_with(
        SqliteConnectOptions::new()
            .filename(&path)
            .foreign_keys(false),
    )
    .await
    .unwrap();
    sqlx::query("INSERT INTO children (parent) VALUES (9)")
        .execute(&pool)
        .await
        .unwrap();
    pool.close().await;

    open(&path, &[], &with(&app, &[(2, GADGETS)]))
        .await
        .expect("applies 2")
        .close()
        .await;
}

const PARENTS_AND_KIDS: &str = "CREATE TABLE parents (id INTEGER PRIMARY KEY, name TEXT);
     CREATE TABLE kids (id INTEGER PRIMARY KEY, parent INTEGER REFERENCES parents (id));
     INSERT INTO parents (id, name) VALUES (1, 'Pat');
     INSERT INTO kids (id, parent) VALUES (1, 1);";

fn rebuild_parents(kept: &str) -> String {
    format!(
        "CREATE TABLE parents_new (id INTEGER PRIMARY KEY, name TEXT NOT NULL);
         INSERT INTO parents_new SELECT id, name FROM parents WHERE {kept};
         DROP TABLE parents;
         ALTER TABLE parents_new RENAME TO parents;"
    )
}

#[tokio::test]
async fn a_migration_may_rebuild_a_referenced_table_the_way_sqlite_documents() {
    let rebuild = rebuild_parents("TRUE");
    let app = [(1001, PARENTS_AND_KIDS), (1002, rebuild.as_str())];
    let db = Database::open_in_memory(&[chain("app", &app).await])
        .await
        .expect("open");

    let joined: Vec<(i64, String)> = sqlx::query_as(
        "SELECT kids.id, parents.name FROM kids JOIN parents ON parents.id = kids.parent",
    )
    .fetch_all(db.pool())
    .await
    .unwrap();
    assert_eq!(joined, [(1, "Pat".to_string())]);
    let orphan = sqlx::query("INSERT INTO kids (parent) VALUES (9)")
        .execute(db.pool())
        .await;
    assert!(orphan.is_err(), "the rebuilt parents is still referenced");
}

#[tokio::test]
async fn a_rebuild_that_drops_a_referenced_row_fails_as_that_migration_and_rolls_back() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("app.db");
    let app = [(1001, PARENTS_AND_KIDS)];
    let before = chains(&[], &app).await;
    open(&path, &[], &app).await.expect("open").close().await;

    let rebuild = rebuild_parents("id <> 1");
    let failed = open(&path, &[], &[app[0], (1002, &rebuild)]).await;
    let Err(Error::Migrate {
        chain,
        source: MigrateError::ExecuteMigration(e, 1002),
    }) = &failed
    else {
        panic!("{failed:?}");
    };
    assert_eq!(chain, "app");
    assert!(
        e.as_database_error()
            .is_some_and(|e| e.is_foreign_key_violation()),
        "{e:?}"
    );

    let db = Database::open_existing(&path, &before)
        .await
        .expect("exactly as it was");
    assert_eq!(versions(db.pool(), "_app_migrations").await, [1001]);
    assert!(!tables(db.pool()).await.contains(&"parents_new".to_string()));
    let parents: Vec<i64> = sqlx::query_scalar("SELECT id FROM parents")
        .fetch_all(db.pool())
        .await
        .unwrap();
    assert_eq!(parents, [1]);
    db.close().await;
}

#[tokio::test]
async fn open_existing_before_the_import_verifies_against_sqlx_table_and_writes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("app.db");
    sqlx_runner(&path, LIB, APP).await.expect("the old build");

    let db = open_existing(&path, LIB, APP)
        .await
        .expect("current by sqlx's rules");
    assert_eq!(
        tables(db.pool()).await,
        ["_sqlx_migrations", "lib_a", "lib_b", "widgets"],
        "nothing written"
    );
    db.close().await;

    let newer = with(APP, &[(1001, GADGETS)]);
    let behind = open_existing(&path, LIB, &newer).await;
    assert!(
        matches!(&behind, Err(Error::SchemaBehind { chain, version: 1001 }) if chain == "app"),
        "{behind:?}"
    );

    let unclaimed = open_existing(&path, LIB, &[]).await;
    assert!(
        matches!(unclaimed, Err(Error::Unclaimed { version: 1000 })),
        "{unclaimed:?}"
    );

    let edited = [(1000, "CREATE TABLE widgets (name TEXT) -- edited")];
    let mismatch = open_existing(&path, LIB, &edited).await;
    assert!(
        matches!(&mismatch, Err(Error::Migrate { chain, source: MigrateError::VersionMismatch(1000) }) if chain == "app"),
        "{mismatch:?}"
    );
}

#[tokio::test]
async fn mirroring_asked_for_after_a_chain_was_registered_without_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("app.db");
    open(&path, LIB, APP).await.expect("open").close().await;

    let [lib, app] = chains(LIB, APP).await;
    let late = [lib, app.mirrored()];
    for refused in [
        Database::open(&path, &late).await,
        Database::open_existing(&path, &late).await,
    ] {
        assert!(
            matches!(&refused, Err(Error::MirroredTooLate(name)) if name == "app"),
            "{refused:?}"
        );
    }
}

#[tokio::test]
async fn a_failed_row_in_sqlx_table_is_refused_as_dirty() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("app.db");
    sqlx_runner(&path, LIB, APP).await.expect("the old build");
    let pool = SqlitePool::connect_with(SqliteConnectOptions::new().filename(&path))
        .await
        .unwrap();
    sqlx::query("UPDATE _sqlx_migrations SET success = FALSE WHERE version = 1000")
        .execute(&pool)
        .await
        .unwrap();
    pool.close().await;

    for refused in [
        open_existing(&path, LIB, APP).await,
        open(&path, LIB, APP).await,
    ] {
        assert!(
            matches!(&refused, Err(Error::Migrate { chain, source: MigrateError::Dirty(1000) }) if chain == "app"),
            "{refused:?}"
        );
    }
}
