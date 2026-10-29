use std::time::Duration;

use wslib_db_sqlite::sqlx::{self, Connection};
use wslib_db_sqlite::{Database, Tuning};

async fn table(dir: &tempfile::TempDir) -> Database {
    let db = Database::open_with(
        dir.path().join("app.db"),
        &[],
        Tuning::default().own_writer(),
    )
    .await
    .expect("open");
    sqlx::query("CREATE TABLE notes (body TEXT)")
        .execute(db.pool())
        .await
        .unwrap();
    db
}

async fn returned() {
    tokio::time::sleep(Duration::from_millis(20)).await;
}

async fn a_write_lands_within_a_second(db: &Database) {
    let write = async {
        let mut tx = db.begin().await?;
        sqlx::query("INSERT INTO notes VALUES ('after')")
            .execute(&mut *tx)
            .await?;
        tx.commit().await.map_err(wslib_db_sqlite::Error::from)
    };
    match tokio::time::timeout(Duration::from_secs(1), write).await {
        Ok(result) => result.expect("the write"),
        Err(_) => panic!("still waiting on the write lock after 1 s"),
    }
}

/// The state a write future dropped between `BEGIN` and its `Transaction`
/// leaves: the lock taken, and nothing left to roll it back.
#[tokio::test]
async fn a_connection_returned_mid_transaction_is_closed_not_reused() {
    let dir = tempfile::tempdir().unwrap();
    let db = table(&dir).await;
    for pool in [db.pool(), db.writer()] {
        let mut conn = pool.acquire().await.unwrap();
        std::mem::forget(conn.begin_with("BEGIN IMMEDIATE").await.unwrap());
        drop(conn);
        returned().await;

        a_write_lands_within_a_second(&db).await;
    }
}

#[tokio::test]
async fn a_connection_returned_read_only_is_closed_not_reused() {
    let dir = tempfile::tempdir().unwrap();
    let db = table(&dir).await;
    for pool in [db.pool(), db.writer()] {
        let mut conn = pool.acquire().await.unwrap();
        sqlx::query("PRAGMA query_only = ON")
            .execute(&mut *conn)
            .await
            .unwrap();
        drop(conn);
        returned().await;

        let mut held = Vec::new();
        for _ in 0..pool.options().get_max_connections() {
            held.push(pool.acquire().await.unwrap());
        }
        for conn in &mut held {
            let query_only: i64 = sqlx::query_scalar("PRAGMA query_only")
                .fetch_one(&mut **conn)
                .await
                .unwrap();
            assert_eq!(query_only, 0);
        }
    }
}
