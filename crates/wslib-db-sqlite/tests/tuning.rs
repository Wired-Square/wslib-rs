use wslib_db_sqlite::sqlx;
use wslib_db_sqlite::{Database, Tuning};

const SQLITE_DEFAULT_CACHE_SIZE: i64 = -2000;
const TEMP_STORE_DEFAULT: i64 = 0;
const TEMP_STORE_MEMORY: i64 = 2;

/// `(cache_size, temp_store)` of every connection the pool can hold at once.
async fn each_connection(db: &Database) -> Vec<(i64, i64)> {
    let pool = db.pool();
    let mut held = Vec::new();
    for _ in 0..pool.options().get_max_connections() {
        held.push(pool.acquire().await.expect("acquire"));
    }
    let mut seen = Vec::new();
    for conn in &mut held {
        let cache: i64 = sqlx::query_scalar("PRAGMA cache_size")
            .fetch_one(&mut **conn)
            .await
            .unwrap();
        let temp: i64 = sqlx::query_scalar("PRAGMA temp_store")
            .fetch_one(&mut **conn)
            .await
            .unwrap();
        seen.push((cache, temp));
    }
    seen
}

fn assert_every(seen: &[(i64, i64)], expected: (i64, i64)) {
    assert_eq!(seen.len(), 5, "the whole pool");
    assert!(seen.iter().all(|&s| s == expected), "{seen:?}");
}

async fn wal_and_foreign_keys_hold(db: &Database) {
    let mode: String = sqlx::query_scalar("PRAGMA journal_mode")
        .fetch_one(db.pool())
        .await
        .unwrap();
    assert_eq!(mode.to_lowercase(), "wal");
    let foreign_keys: i64 = sqlx::query_scalar("PRAGMA foreign_keys")
        .fetch_one(db.pool())
        .await
        .unwrap();
    assert_eq!(foreign_keys, 1);
}

#[tokio::test]
async fn tuning_holds_on_every_connection_of_both_opens() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("app.db");
    let tuning = Tuning::default().cache_kib(8192).temp_store_in_memory();

    let db = Database::open_with(&path, &[], tuning).await.expect("open");
    assert_every(&each_connection(&db).await, (-8192, TEMP_STORE_MEMORY));
    wal_and_foreign_keys_hold(&db).await;
    db.close().await;

    let db = Database::open_existing_with(&path, &[], tuning)
        .await
        .expect("reopen");
    assert_every(&each_connection(&db).await, (-8192, TEMP_STORE_MEMORY));
    wal_and_foreign_keys_hold(&db).await;
    db.close().await;
}

#[tokio::test]
async fn each_setting_applies_alone() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("app.db");

    let db = Database::open_with(&path, &[], Tuning::default().cache_kib(4096))
        .await
        .expect("open");
    assert_every(&each_connection(&db).await, (-4096, TEMP_STORE_DEFAULT));
    db.close().await;

    let db = Database::open_existing_with(&path, &[], Tuning::default().temp_store_in_memory())
        .await
        .expect("reopen");
    assert_every(
        &each_connection(&db).await,
        (SQLITE_DEFAULT_CACHE_SIZE, TEMP_STORE_MEMORY),
    );
    db.close().await;
}

#[tokio::test]
async fn a_plain_open_leaves_sqlites_defaults() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("app.db");
    let defaults = (SQLITE_DEFAULT_CACHE_SIZE, TEMP_STORE_DEFAULT);

    let db = Database::open(&path, &[]).await.expect("open");
    assert_every(&each_connection(&db).await, defaults);
    db.close().await;

    let db = Database::open_existing(&path, &[]).await.expect("reopen");
    assert_every(&each_connection(&db).await, defaults);
    db.close().await;
}
