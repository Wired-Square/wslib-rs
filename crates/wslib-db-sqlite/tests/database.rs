mod common;

use std::path::{Path, PathBuf};
use std::time::Duration;

use common::chain;
use wslib_db_sqlite::sqlx::{self, Sqlite};
use wslib_db_sqlite::{Chain, Database, Error};
use wslib_file_atomic::testing::assert_owner_only;

async fn parents_and_children() -> Chain {
    chain(
        "app",
        &[(
            1,
            "CREATE TABLE parents (id INTEGER PRIMARY KEY) STRICT;
             CREATE TABLE children (
                 id     INTEGER PRIMARY KEY,
                 parent INTEGER NOT NULL REFERENCES parents (id)
             ) STRICT;",
        )],
    )
    .await
}

async fn note(db: &Database) {
    sqlx::query("CREATE TABLE IF NOT EXISTS notes (body TEXT)")
        .execute(db.pool())
        .await
        .expect("table");
    sqlx::query("INSERT INTO notes VALUES ('written')")
        .execute(db.pool())
        .await
        .expect("row");
}

fn wal(path: &Path) -> PathBuf {
    path.with_file_name("app.db-wal")
}

#[tokio::test]
async fn in_memory_a_pool_query_waits_until_the_transaction_ends() {
    let db = Database::open_in_memory(&[]).await.expect("open");
    let tx = db.begin().await.expect("begin");
    let query = || sqlx::query("SELECT 1").execute(db.pool());
    let waited = tokio::time::timeout(Duration::from_millis(200), query()).await;
    assert!(
        waited.is_err(),
        "still waiting while the transaction is held"
    );
    drop(tx);
    query().await.expect("answered once the transaction ends");
}

#[tokio::test]
async fn foreign_keys_are_enforced() {
    let db = Database::open_in_memory(&[parents_and_children().await])
        .await
        .expect("open");
    let orphan = sqlx::query("INSERT INTO children (parent) VALUES (7)")
        .execute(db.pool())
        .await;
    assert!(orphan.is_err(), "foreign keys must be on");
}

#[tokio::test]
async fn a_transaction_from_begin_checks_foreign_keys_at_the_commit_not_per_statement() {
    let db = Database::open_in_memory(&[parents_and_children().await])
        .await
        .expect("open");
    sqlx::query("INSERT INTO parents (id) VALUES (1)")
        .execute(db.pool())
        .await
        .unwrap();
    sqlx::query("INSERT INTO children (parent) VALUES (1)")
        .execute(db.pool())
        .await
        .unwrap();

    let mut tx = db.begin().await.expect("begin");
    sqlx::query("DELETE FROM parents")
        .execute(&mut *tx)
        .await
        .expect("the parent rows go first");
    sqlx::query("DELETE FROM children")
        .execute(&mut *tx)
        .await
        .expect("the child rows after");
    tx.commit().await.expect("nothing dangles at the commit");

    let mut tx = db.begin().await.expect("begin");
    sqlx::query("INSERT INTO children (parent) VALUES (9)")
        .execute(&mut *tx)
        .await
        .expect("not checked at the statement");
    assert!(tx.commit().await.is_err(), "checked at the commit");
}

#[tokio::test]
async fn a_second_open_of_one_file_finds_what_the_first_wrote() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("app.db");
    let app = [parents_and_children().await];

    let refused = Database::open_existing(&path, &app).await;
    assert!(matches!(refused, Err(Error::NoDatabase(_))), "{refused:?}");
    assert!(!path.exists(), "open_existing creates nothing");

    std::fs::write(&path, b"").unwrap();
    let behind = Database::open_existing(&path, &app).await;
    assert!(
        matches!(&behind, Err(Error::SchemaBehind { chain, version: 1 }) if chain == "app"),
        "{behind:?}"
    );

    let first = Database::open(&path, &app).await.expect("open");
    note(&first).await;
    first.close().await;

    let second = Database::open_existing(&path, &app)
        .await
        .expect("re-open, checking the chain rather than running it");
    let body: String = sqlx::query_scalar("SELECT body FROM notes")
        .fetch_one(second.pool())
        .await
        .unwrap();
    assert_eq!(body, "written");

    let mode: String = sqlx::query_scalar("PRAGMA journal_mode")
        .fetch_one(second.pool())
        .await
        .unwrap();
    assert_eq!(mode.to_lowercase(), "wal");
    second.close().await;
}

#[tokio::test]
async fn every_open_restricts_the_file_and_its_wal_and_shm_to_their_owner() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("app.db");
    let app = [parents_and_children().await];
    let owner_only = || {
        for name in ["app.db", "app.db-wal", "app.db-shm"] {
            assert_owner_only(&dir.path().join(name));
        }
    };

    let db = Database::open(&path, &app).await.expect("open");
    owner_only();
    db.close().await;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    }
    let db = Database::open_existing(&path, &app).await.expect("reopen");
    owner_only();
    db.close().await;
}

#[tokio::test]
async fn the_newest_version_of_each_chain_is_known() {
    let db = Database::open_in_memory(&[
        chain("lib", &[(1, "SELECT 1"), (3, "SELECT 1")]).await,
        chain("app", &[(1000, "SELECT 1")]).await,
        chain("empty", &[]).await,
    ])
    .await
    .expect("open");
    assert_eq!(db.chain_version("lib"), Some(3));
    assert_eq!(db.chain_version("app"), Some(1000));
    assert_eq!(db.chain_version("empty"), None);
    assert_eq!(db.chain_version("other"), None);
}

#[tokio::test]
async fn a_chain_name_that_is_not_plain_or_is_repeated_is_refused_before_the_file_is_made() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("app.db");
    for name in ["App", "1app", "app-x", "", "_sqlx"] {
        let refused = Database::open(&path, &[chain(name, &[]).await]).await;
        assert!(
            matches!(refused, Err(Error::InvalidName(_))),
            "{name:?}: {refused:?}"
        );
    }
    let twice = [chain("app", &[]).await, chain("app", &[]).await];
    let refused = Database::open(&path, &twice).await;
    assert!(
        matches!(refused, Err(Error::DuplicateChain(_))),
        "{refused:?}"
    );
    assert!(!path.exists());
}

#[tokio::test]
async fn a_chain_whose_table_would_be_the_crates_own_is_refused() {
    let refused = Database::open_in_memory(&[chain("sqlx", &[]).await]).await;
    assert!(
        matches!(&refused, Err(Error::ReservedChain(name)) if name == "sqlx"),
        "{refused:?}"
    );
}

#[tokio::test]
async fn a_closed_database_leaves_nothing_beside_it() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("app.db");
    let db = Database::open(&path, &[]).await.expect("open");
    note(&db).await;
    db.close().await;
    for name in ["app.db-wal", "app.db-shm"] {
        assert!(!dir.path().join(name).exists(), "{name}");
    }
}

/// A file database whose pool has every connection checked out, at least two.
async fn every_connection_held(path: &Path) -> (Database, Vec<sqlx::pool::PoolConnection<Sqlite>>) {
    let db = Database::open(path, &[]).await.expect("open");
    let pool = db.pool();
    while pool.num_idle() < pool.size() as usize {
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    let mut held = Vec::new();
    for _ in 0..pool.size().max(2) {
        held.push(pool.acquire().await.expect("acquire"));
    }
    (db, held)
}

#[tokio::test]
async fn closing_removes_the_wal_though_a_connection_was_mid_return() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("app.db");
    let (db, mut held) = every_connection_held(&path).await;
    let returning = held.pop().expect("two held");
    for conn in held {
        conn.close().await.expect("close");
    }
    drop(returning);
    tokio::task::yield_now().await;
    db.close().await;
    assert!(!wal(&path).exists());
}

#[tokio::test]
async fn closing_waits_for_a_connection_still_checked_out() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("app.db");
    let (db, mut held) = every_connection_held(&path).await;
    let out = held.pop().expect("two held");
    drop(held);
    while db.pool().num_idle() == 0 {
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    tokio::join!(db.close(), async {
        tokio::time::sleep(Duration::from_millis(50)).await;
        drop(out);
    });
    assert!(!wal(&path).exists());
}

#[tokio::test]
async fn closing_gives_up_on_a_connection_never_returned() {
    let dir = tempfile::tempdir().unwrap();
    let (db, held) = every_connection_held(&dir.path().join("app.db")).await;
    tokio::time::timeout(Duration::from_secs(10), db.close())
        .await
        .expect("close waits five seconds, not for ever");
    drop(held);
}
