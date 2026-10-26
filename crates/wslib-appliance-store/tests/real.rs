//! A copy of a deployed database, opened by this build and by the build that
//! made it. Ignored: the paths come from the environment, and it prints counts,
//! versions and verdicts, never a row's contents.
//!
//! - `TRIAL_REAL_DB`: the database, beside its `-wal` and `-shm`; only copied.
//! - `TRIAL_REAL_WORK`: an empty directory for the working copies.
//! - `TRIAL_REAL_APP`, optional: the product's migration files. Without it the
//!   product's chain is its applied rows, checksums and all, which never run.

mod common;

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::hash::{DefaultHasher, Hash, Hasher};
use std::path::{Path, PathBuf};

use common::{
    both_mirrored, migration, migrator, platform, pool, previous_build, previous_build_offline,
    registry,
};
use sqlx::migrate::{MigrateError, Migration, MigrationType, Migrator};
use sqlx::sqlite::SqlitePool;
use wslib_appliance_store::{APP_FLOOR, Store, sqlx};

const RECORDS: [&str; 4] = [
    "_sqlx_migrations",
    "_migration_chains",
    "_platform_migrations",
    "_app_migrations",
];

/// What a sign-in reads: the accounts and every factor.
const SIGN_IN: [&str; 5] = [
    "users",
    "totp",
    "recovery_codes",
    "passkeys",
    "totp_required",
];

fn env(name: &str) -> PathBuf {
    PathBuf::from(std::env::var(name).unwrap_or_else(|_| panic!("{name}")))
}

/// A fresh copy of the database, its `-wal` and `-shm` with it.
fn copy(step: &str) -> PathBuf {
    let source = env("TRIAL_REAL_DB");
    let dir = env("TRIAL_REAL_WORK").join(step);
    std::fs::create_dir_all(&dir).expect("work dir");
    let path = dir.join("copy.db");
    for suffix in ["", "-wal", "-shm"] {
        let mut from = source.clone().into_os_string();
        from.push(suffix);
        let mut to = path.clone().into_os_string();
        to.push(suffix);
        if Path::new(&from).exists() {
            std::fs::copy(&from, &to).expect("copy");
        }
    }
    path
}

async fn app(path: &Path) -> Migrator {
    if let Ok(dir) = std::env::var("TRIAL_REAL_APP") {
        return Migrator::new(Path::new(&dir)).await.expect("app files");
    }
    let pool = pool(path).await;
    let rows: Vec<(i64, String, Vec<u8>)> = sqlx::query_as(
        "SELECT version, description, checksum FROM _sqlx_migrations WHERE version >= ? \
         ORDER BY version",
    )
    .bind(APP_FLOOR)
    .fetch_all(&pool)
    .await
    .expect("applied app rows");
    pool.close().await;
    migrator(
        rows.into_iter()
            .map(|(version, description, checksum)| Migration {
                version,
                description: Cow::Owned(description),
                migration_type: MigrationType::Simple,
                sql: Cow::Borrowed("SELECT 'applied, never run'"),
                checksum: Cow::Owned(checksum),
                no_tx: false,
            }),
    )
    .await
}

async fn app_and(path: &Path, extra: Migration) -> Migrator {
    migrator(app(path).await.iter().cloned().chain([extra])).await
}

async fn tables(pool: &SqlitePool) -> Vec<String> {
    sqlx::query_scalar(
        "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' \
         ORDER BY name",
    )
    .fetch_all(pool)
    .await
    .expect("tables")
}

/// Row counts of every table but the migration records.
async fn counts(path: &Path) -> BTreeMap<String, i64> {
    let pool = pool(path).await;
    let mut counts = BTreeMap::new();
    for table in tables(&pool).await {
        if RECORDS.contains(&table.as_str()) {
            continue;
        }
        let n: i64 = sqlx::query_scalar(&format!("SELECT count(*) FROM \"{table}\""))
            .fetch_one(&pool)
            .await
            .expect("count");
        counts.insert(table, n);
    }
    pool.close().await;
    counts
}

/// A hash of every row of `only`, or of every schema object and every table.
async fn digest(path: &Path, only: Option<&[&str]>) -> u64 {
    let pool = pool(path).await;
    let mut hasher = DefaultHasher::new();
    let tables = match only {
        Some(only) => only.iter().map(|t| t.to_string()).collect(),
        None => {
            let schema: Vec<(String, String, Option<String>)> =
                sqlx::query_as("SELECT type, name, sql FROM sqlite_master ORDER BY type, name")
                    .fetch_all(&pool)
                    .await
                    .expect("schema");
            schema.hash(&mut hasher);
            tables(&pool).await
        }
    };
    for table in tables {
        let columns: Vec<String> =
            sqlx::query_scalar(&format!("SELECT name FROM pragma_table_info('{table}')"))
                .fetch_all(&pool)
                .await
                .expect("columns");
        let row = columns
            .iter()
            .map(|c| format!("quote(\"{c}\")"))
            .collect::<Vec<_>>()
            .join(" || ',' || ");
        let rows: Vec<String> =
            sqlx::query_scalar(&format!("SELECT {row} FROM \"{table}\" ORDER BY 1"))
                .fetch_all(&pool)
                .await
                .expect("rows");
        (table, rows).hash(&mut hasher);
    }
    pool.close().await;
    hasher.finish()
}

/// Every `_sqlx_migrations` column, the checksum as hex.
type LegacyRow = (i64, String, String, bool, String, i64);

async fn legacy(path: &Path) -> Vec<LegacyRow> {
    let pool = pool(path).await;
    let rows = sqlx::query_as(
        "SELECT version, description, CAST(installed_on AS TEXT), success, \
         lower(hex(checksum)), execution_time FROM _sqlx_migrations ORDER BY version",
    )
    .fetch_all(&pool)
    .await
    .expect("_sqlx_migrations");
    pool.close().await;
    rows
}

async fn chain_rows(path: &Path) -> Vec<(i64, String)> {
    let pool = pool(path).await;
    let mut rows: Vec<(i64, String)> = Vec::new();
    for table in ["_platform_migrations", "_app_migrations"] {
        rows.extend(
            sqlx::query_as::<_, (i64, String)>(&format!("SELECT version, checksum FROM {table}"))
                .fetch_all(&pool)
                .await
                .expect(table),
        );
    }
    pool.close().await;
    rows.sort();
    rows
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn verdict<T, E: std::fmt::Debug>(result: &Result<T, E>) -> String {
    match result {
        Ok(_) => "Ok".to_string(),
        Err(e) => {
            let e = format!("{e:?}");
            e.split(['(', '{', ' ']).next().unwrap_or(&e).to_string()
        }
    }
}

#[tokio::test]
#[ignore]
async fn a_deployed_database() {
    let before = copy("0-before");
    let before_counts = counts(&before).await;
    let before_legacy = legacy(&before).await;
    let before_sign_in = digest(&before, Some(&SIGN_IN)).await;
    let app_chain = app(&before).await;
    let newest_app = app_chain.iter().map(|m| m.version).max().expect("an app");
    let had_7 = before_legacy.iter().any(|row| row.0 == 7);
    println!(
        "_sqlx_migrations: {:?}",
        before_legacy.iter().map(|r| r.0).collect::<Vec<_>>()
    );
    println!("row counts: {before_counts:?}");

    let platform_sums: BTreeMap<i64, String> = platform()
        .iter()
        .map(|m| (m.version, hex(&m.checksum)))
        .collect();
    let sums_match = before_legacy
        .iter()
        .filter(|row| row.0 < APP_FLOOR)
        .all(|row| platform_sums.get(&row.0) == Some(&row.4));
    println!("this crate's .sql checksums match the deployed rows: {sums_match}");
    assert!(sums_match);

    let path = copy("1-open");
    let opened = Store::open(&path, Some(app(&path).await)).await;
    println!("Store::open: {}", verdict(&opened));
    let store = opened.expect("opens");
    assert_eq!(i64::from(store.app_schema_version()), newest_app);
    let users: Vec<String> = sqlx::query_scalar("SELECT id FROM users")
        .fetch_all(store.pool())
        .await
        .expect("ids");
    for id in &users {
        assert!(store.user_by_id(id).await.expect("read").is_some());
    }
    let factors = store.second_factors().await.expect("factors").len();
    println!(
        "through Store: {} accounts read, {factors} with factors",
        users.len()
    );
    store.close().await;

    let registered = registry(&path).await;
    println!("registry: {registered:?}");
    assert_eq!(registered, both_mirrored());
    let after_legacy = legacy(&path).await;
    let mirrored: Vec<(i64, String)> = after_legacy.iter().map(|r| (r.0, r.4.clone())).collect();
    let chains = chain_rows(&path).await;
    println!(
        "_platform_migrations + _app_migrations: {:?}",
        chains.iter().map(|r| r.0).collect::<Vec<_>>()
    );
    assert_eq!(
        chains, mirrored,
        "each chain row is its _sqlx_migrations row"
    );

    let kept = before_legacy.iter().all(|row| after_legacy.contains(row));
    let added: Vec<i64> = after_legacy
        .iter()
        .filter(|row| !before_legacy.contains(row))
        .map(|row| row.0)
        .collect();
    println!("every applied row unchanged, none re-ran: {kept}; added: {added:?}");
    assert!(kept);
    assert_eq!(added, if had_7 { vec![] } else { vec![7] });

    let after_counts = counts(&path).await;
    let changed: Vec<String> = after_counts
        .iter()
        .filter(|(t, n)| before_counts.get(*t) != Some(n))
        .map(|(t, n)| format!("{t}: {:?} -> {n}", before_counts.get(t)))
        .chain(
            before_counts
                .keys()
                .filter(|t| !after_counts.contains_key(*t))
                .map(|t| format!("{t}: gone")),
        )
        .collect();
    println!("row counts changed: {changed:?}");
    assert!(
        changed.iter().all(|c| c == "platform_sessions: None -> 0"),
        "{changed:?}"
    );
    let sign_in_kept = digest(&path, Some(&SIGN_IN)).await == before_sign_in;
    println!("accounts and factors, row for row, unchanged: {sign_in_kept}");
    assert!(sign_in_kept);

    let digest_before = digest(&path, None).await;
    let offline = previous_build_offline(&path, &app_chain).await;
    let ran = previous_build(&path, &app_chain).await;
    let untouched = digest(&path, None).await == digest_before;
    println!(
        "the previous build: offline open {}, open {}, nothing written {untouched}",
        verdict(&offline),
        verdict(&ran)
    );
    assert!(offline.is_ok() && ran.is_ok() && untouched);

    let path = copy("2-newer");
    let extra = newest_app + 1;
    let newer = app_and(
        &path,
        migration(extra, "CREATE TABLE trial_throwaway (id TEXT)"),
    )
    .await;
    let opened = Store::open(&path, Some(newer)).await;
    println!("Store::open with {extra}: {}", verdict(&opened));
    opened.expect("applies").close().await;
    let refused = previous_build(&path, &app_chain).await;
    println!("the previous build on it: {refused:?}");
    assert!(matches!(refused, Err(MigrateError::VersionMissing(v)) if v == extra));

    let path = copy("3-interrupted");
    let digest_before = digest(&path, None).await;
    let failing = app_and(
        &path,
        migration(extra, "INSERT INTO trial_nowhere VALUES (1)"),
    )
    .await;
    let refused = Store::open(&path, Some(failing)).await;
    let untouched = digest(&path, None).await == digest_before;
    println!(
        "a failing {extra}: {}, nothing written {untouched}",
        verdict(&refused)
    );
    assert!(refused.is_err() && untouched);
    let retried = Store::open(&path, Some(app(&path).await)).await;
    println!("retried: {}", verdict(&retried));
    retried.expect("retries").close().await;

    let path = copy("4-offline");
    let digest_before = digest(&path, None).await;
    let offline = Store::open_existing(&path, Some(app(&path).await)).await;
    let untouched = digest(&path, None).await == digest_before;
    println!(
        "open_existing before the import: {}, nothing written {untouched}",
        verdict(&offline)
    );
    assert!(untouched && offline.is_ok() == had_7);
    if let Ok(store) = offline {
        store.close().await;
    }
}
