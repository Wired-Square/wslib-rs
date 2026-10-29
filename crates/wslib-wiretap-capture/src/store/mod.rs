use std::path::{Path, PathBuf};

use sqlx::migrate::Migrator;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePool};
use sqlx::{ConnectOptions, Connection};
use wslib_db_sqlite::{Chain, Database, Tuning};

mod bytes;
mod captures;
mod error;
mod events;
mod frames;
mod inventory;
mod legacy;
mod meta;
mod query;
mod read;
mod sample;
mod search;

pub use error::{CaptureError, Result};
pub use inventory::inventory_row;
pub use legacy::{Applied, upgrade_legacy};
pub use query::Cancel;
/// The whole of sqlx, for queries; `migrate!` for an application's own
/// migrations still needs `sqlx` in its manifest, at this crate's version.
pub use sqlx;

const CHAIN: &str = "capture";

/// Chain migration N stamps `user_version` N + 5, so a build on the legacy
/// ladder, versions 1 to 6, sees a newer file rather than an unstamped one.
const USER_VERSION_OFFSET: i64 = 5;

static MIGRATOR: Migrator = sqlx::migrate!("./migrations");

/// The capture schema's migration chain, `capture`.
pub fn chain() -> Chain {
    Chain::new(CHAIN, &MIGRATOR)
}

/// The page cache and in-memory temporaries each capture connection gets.
pub fn tuning() -> Tuning {
    Tuning::default()
        .cache_kib(64 * 1024)
        .temp_store_in_memory()
}

/// A capture database, its methods grouped as frames, bytes, metadata, events,
/// inventory, search, statements and whole captures.
///
/// A connection a method drops goes back to the pool on the caller's runtime,
/// so a sync caller that blocks that runtime while it waits can starve the pool.
#[derive(Debug, Clone)]
pub struct Store {
    db: Database,
}

impl Store {
    /// Open (creating if absent), bring a file an older build wrote up to the
    /// chain with [`upgrade_legacy`], apply [`chain`], and stamp
    /// `user_version` as the chain's version plus 5; with the legacy steps
    /// that ran, for the log.
    pub async fn open(path: impl AsRef<Path>) -> Result<(Self, Vec<Applied>)> {
        let path = path.as_ref();
        let mut conn = SqliteConnectOptions::new()
            .filename(path)
            .create_if_missing(true)
            .connect()
            .await?;
        let applied = upgrade_legacy(&mut conn).await?;
        conn.close().await?;
        let db = Database::open_with(path, &[chain()], tuning()).await?;
        let version = db.chain_version(CHAIN).unwrap_or_default() + USER_VERSION_OFFSET;
        sqlx::query(&format!("PRAGMA user_version = {version}"))
            .execute(db.pool())
            .await?;
        Ok((Self::from_database(db), applied))
    }

    /// Copy `original`, with its `-wal` if it has one, to `working`, then
    /// [`open`](Self::open) the copy: a file the application did not create is
    /// never migrated in place. `working` must not exist.
    pub async fn open_copy(
        original: impl AsRef<Path>,
        working: impl AsRef<Path>,
    ) -> Result<(Self, Vec<Applied>)> {
        let (original, working) = (original.as_ref(), working.as_ref());
        if tokio::fs::try_exists(working).await? {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                format!("{} already exists", working.display()),
            )
            .into());
        }
        tokio::fs::copy(original, working).await?;
        let wal = sidecar(original, "-wal");
        if tokio::fs::try_exists(&wal).await? {
            tokio::fs::copy(&wal, sidecar(working, "-wal")).await?;
        }
        Self::open(working).await
    }

    /// A store over a database the application opened itself, with [`chain`]
    /// among its chains.
    pub fn from_database(db: Database) -> Self {
        Self { db }
    }

    pub fn database(&self) -> &Database {
        &self.db
    }

    /// See [`Database::close`].
    pub async fn close(&self) {
        self.db.close().await;
    }

    fn pool(&self) -> &SqlitePool {
        self.db.pool()
    }
}

fn sidecar(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(suffix);
    name.into()
}

#[cfg(test)]
pub(crate) mod testing {
    use wslib_wiretap_protocol::{FrameSelection, ProtocolFrames};

    use super::*;

    /// A file store, as an application opens one, removed with its directory.
    pub(crate) struct TestStore {
        store: Store,
        _dir: tempfile::TempDir,
    }

    impl std::ops::Deref for TestStore {
        type Target = Store;

        fn deref(&self) -> &Store {
            &self.store
        }
    }

    pub(crate) async fn store() -> TestStore {
        let dir = tempfile::tempdir().unwrap();
        let (store, _) = Store::open(dir.path().join("captures.db")).await.unwrap();
        TestStore { store, _dir: dir }
    }

    /// One connection, for a test that needs the next query on the same one.
    pub(crate) async fn memory_store() -> Store {
        Store::from_database(Database::open_in_memory(&[chain()]).await.unwrap())
    }

    pub(crate) async fn execute(store: &Store, sql: &str) {
        sqlx::Executor::execute(store.pool(), sqlx::raw_sql(sql))
            .await
            .unwrap();
    }

    pub(crate) async fn rows<T>(store: &Store, sql: &str) -> Vec<T>
    where
        T: Send + Unpin + for<'r> sqlx::Decode<'r, sqlx::Sqlite> + sqlx::Type<sqlx::Sqlite>,
    {
        sqlx::query_scalar(sql)
            .fetch_all(store.pool())
            .await
            .unwrap()
    }

    pub(crate) async fn count(store: &Store, sql: &str) -> i64 {
        sqlx::query_scalar(sql)
            .fetch_one(store.pool())
            .await
            .unwrap()
    }

    /// The `detail` of a statement's first `EXPLAIN QUERY PLAN` row.
    pub(crate) async fn plan(store: &Store, sql: &str, param: Option<String>) -> String {
        let explain = format!("EXPLAIN QUERY PLAN {sql}");
        let mut query = sqlx::query(&explain);
        if let Some(param) = param {
            query = query.bind(param);
        }
        let row = query.fetch_one(store.pool()).await.unwrap();
        sqlx::Row::get(&row, "detail")
    }

    pub(crate) async fn multi_protocol_capture() -> TestStore {
        let store = store().await;
        execute(
            &store,
            "INSERT INTO frames (capture_id, protocol, timestamp_us, frame_id, bus, dlc, payload)
             VALUES ('c1', 'can',    10, 256, 0, 8, x'AA'),
                    ('c1', 'modbus', 20, 256, 0, 2, x'BB'),
                    ('c1', 'serial', 30, 256, 0, 1, x'CC'),
                    ('c1', 'can',    40, 257, 0, 8, x'DD');",
        )
        .await;
        store
    }

    pub(crate) fn selection(groups: &[(&str, &[u32])]) -> FrameSelection {
        FrameSelection::from_groups(
            groups
                .iter()
                .map(|(protocol, ids)| ProtocolFrames::ids(*protocol, ids.to_vec()))
                .collect(),
        )
    }

    pub(crate) fn whole(protocol: &str) -> FrameSelection {
        FrameSelection::from_groups(vec![ProtocolFrames::whole(protocol)])
    }
}
