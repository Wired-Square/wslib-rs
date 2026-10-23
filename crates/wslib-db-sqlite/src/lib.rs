//! One SQLite database for an app, opened the way it should be.
//!
//! Every query is written with sqlx's runtime API (`sqlx::query`), never the
//! `query!` macros, which need a live database or a checked-in cache to compile.
//!
//! What [`Database::open`] does that a plain `connect` does not:
//!
//! - **WAL is entered once, on a connection of its own**, because it takes an
//!   exclusive lock that `busy_timeout` cannot wait on.
//! - **The file is restricted to its owner on every open**, because SQLite
//!   creates it world-readable and a service manager only restricts a directory
//!   it created itself.
//! - **Every pending migration of every [`Chain`] applies in one transaction.**
//!   See [`migrate`].
//! - **Write transactions take the write lock up front, and check foreign keys
//!   at the commit.** See [`Database::begin`].
//!
//! Every instant is stored through [`stamp`], whose fixed width lets SQLite
//! order and compare the columns as text.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use sqlx::migrate::MigrateError;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePool, SqlitePoolOptions};
use sqlx::{Sqlite, Transaction};

pub mod migrate;
pub mod settings;
pub mod stamp;

pub use migrate::Chain;
pub use settings::Settings;

/// The whole of sqlx, so an app's own queries need no sqlx of their own.
///
/// **It cannot serve `migrate!`, and no re-export could.** That macro emits
/// `::sqlx::migrate::Migrator { … }`, and a leading `::` resolves only against
/// the extern prelude, where a `use` puts nothing. So an app declares `sqlx` in
/// its own manifest for that one call and **pins the same version this crate
/// does**: the guarantee is the pin, not the re-export.
pub use sqlx;

const BUSY_TIMEOUT: Duration = Duration::from_secs(5);

/// Why a database operation could not be completed.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    #[error("database: {0}")]
    Db(#[from] sqlx::Error),

    /// A migration of `chain` failed, an applied one was modified
    /// (`VersionMismatch`), or one applied is not in the chain (`VersionMissing`).
    #[error("migration chain {chain}: {source}")]
    Migrate {
        chain: String,
        #[source]
        source: MigrateError,
    },

    /// [`Database::open_existing`] found no file.
    #[error("no database at {0}")]
    NoDatabase(PathBuf),

    /// [`Database::open_existing`] found `chain` not fully applied.
    #[error("the database is behind chain {chain}: migration {version} is not applied")]
    SchemaBehind { chain: String, version: i64 },

    /// A stored value this build cannot read.
    #[error("unreadable {what} in {table}: {because}")]
    Unreadable {
        table: &'static str,
        what: &'static str,
        because: String,
    },

    /// A chain or table name that is not `[a-z][a-z0-9_]*`.
    #[error("{0:?} is not a plain lower-case name: a letter, then letters, digits or _")]
    InvalidName(String),

    #[error("two chains are named {0:?}")]
    DuplicateChain(String),

    /// A pending migration marked `-- no-transaction`.
    #[error(
        "migration {version} of chain {chain} is marked no-transaction, and every pending \
         migration applies in one transaction"
    )]
    NoTransaction { chain: String, version: i64 },

    /// A `_sqlx_migrations` row being imported that no chain has.
    #[error("_sqlx_migrations has migration {version}, which no chain has")]
    Unclaimed { version: i64 },

    /// A `_sqlx_migrations` row being imported that two chains have.
    #[error("_sqlx_migrations has migration {version}, which chains {chain} and {other} both have")]
    Ambiguous {
        version: i64,
        chain: String,
        other: String,
    },

    /// A migration of an imported chain whose version `_sqlx_migrations`
    /// already holds for `other`, or another chain is about to write.
    #[error(
        "migration {version} of chain {chain} would be recorded in _sqlx_migrations, \
         which already has it for {other}"
    )]
    Collision {
        version: i64,
        chain: String,
        other: String,
    },

    /// A settings key in the secret or local namespace, handed to a plain setting call.
    #[error(
        "the settings key {0:?} is reserved: a secret goes through Settings::secret and \
         set_secret, local state through Settings::local and set_local, each by its name \
         without the prefix"
    )]
    Reserved(String),

    /// A local prefix that is empty, does not end in `.`, or overlaps `secret.`.
    #[error("{0:?} cannot be the local prefix: it ends in '.' and does not overlap \"secret.\"")]
    LocalPrefix(String),

    #[error("the document for {key} will not serialise: {source}")]
    Serialise {
        key: String,
        #[source]
        source: serde_json::Error,
    },
}

/// An app's database: a pool, and the migration chains it was opened with.
#[derive(Debug, Clone)]
pub struct Database {
    pool: SqlitePool,
    chain_versions: Arc<BTreeMap<String, i64>>,
}

#[derive(Debug, Clone, Copy)]
enum Schema {
    Migrate,
    Verify,
}

impl Database {
    /// Open (creating if absent), apply every pending migration of `chains`,
    /// and restrict the file to its owner.
    pub async fn open(path: impl AsRef<Path>, chains: &[Chain]) -> Result<Self, Error> {
        Self::open_at(path.as_ref(), chains, Schema::Migrate).await
    }

    /// [`open`](Self::open) for a process beside the one that owns the
    /// database, which neither creates it nor migrates it.
    ///
    /// No file is [`Error::NoDatabase`]. A chain not fully applied is
    /// [`Error::SchemaBehind`]; an applied migration a chain lacks or has
    /// modified is [`Error::Migrate`]. Run it as the owner's account: the file is
    /// restricted to its owner.
    pub async fn open_existing(path: impl AsRef<Path>, chains: &[Chain]) -> Result<Self, Error> {
        let path = path.as_ref();
        if !path.try_exists().map_err(sqlx::Error::Io)? {
            return Err(Error::NoDatabase(path.to_path_buf()));
        }
        Self::open_at(path, chains, Schema::Verify).await
    }

    /// An in-memory database with `chains` applied, for tests.
    ///
    /// **One connection, not a pool**: each connection to `sqlite::memory:` is
    /// its own empty database, and closing it loses it, so idle timeout and
    /// lifetime are off. A query on [`Database::pool`] while a
    /// [`Database::begin`] is held waits for the transaction to end, and fails
    /// with `PoolTimedOut` after 30 seconds; it always does in the same task.
    pub async fn open_in_memory(chains: &[Chain]) -> Result<Self, Error> {
        migrate::check_names(chains)?;
        let opts = SqliteConnectOptions::from_str("sqlite::memory:")
            .expect("a literal in-memory URL parses")
            .foreign_keys(true);
        Self::pooled(opts, 1, chains, Schema::Migrate).await
    }

    async fn open_at(path: &Path, chains: &[Chain], schema: Schema) -> Result<Self, Error> {
        migrate::check_names(chains)?;
        let opts = SqliteConnectOptions::new()
            .filename(path)
            .create_if_missing(matches!(schema, Schema::Migrate))
            // WAL's documented pairing: NORMAL cannot corrupt the database, it
            // risks only the latest commit on power loss, and FULL fsyncs every one.
            .synchronous(sqlx::sqlite::SqliteSynchronous::Normal)
            .foreign_keys(true)
            .busy_timeout(BUSY_TIMEOUT);

        enter_wal(&opts).await?;
        restrict_to_owner(path);
        let db = Self::pooled(opts, 5, chains, schema).await?;
        restrict_to_owner(path);
        Ok(db)
    }

    async fn pooled(
        opts: SqliteConnectOptions,
        max_connections: u32,
        chains: &[Chain],
        schema: Schema,
    ) -> Result<Self, Error> {
        let pool = SqlitePoolOptions::new()
            .max_connections(max_connections)
            .min_connections(1)
            .idle_timeout(None)
            .max_lifetime(None)
            .connect_with(opts)
            .await?;
        let ready = match schema {
            Schema::Migrate => migrate::apply(&pool, chains).await,
            Schema::Verify => migrate::verify(&pool, chains).await,
        };
        if let Err(e) = ready {
            close_once_returned(&pool).await;
            return Err(e);
        }
        let chain_versions = chains
            .iter()
            .filter_map(|chain| Some((chain.name().to_string(), chain.version()?)))
            .collect();
        Ok(Self {
            pool,
            chain_versions: Arc::new(chain_versions),
        })
    }

    /// The newest version in the chain named `name`, as opened; `None` for a
    /// chain not opened or with no migrations. What a backup is stamped with.
    pub fn chain_version(&self, name: &str) -> Option<i64> {
        self.chain_versions.get(name).copied()
    }

    pub fn pool(&self) -> &SqlitePool {
        &self.pool
    }

    /// Begin a write transaction, **taking the write lock up front**, with
    /// foreign keys checked at the commit.
    ///
    /// `BEGIN IMMEDIATE`, not sqlx's plain `BEGIN`: a deferred transaction that
    /// reads before it writes must upgrade its lock, and SQLite answers
    /// `SQLITE_BUSY` to that at once rather than through the busy timeout,
    /// because waiting on an upgrade is how two readers deadlock.
    ///
    /// Deferred foreign keys let one transaction replace parent and child rows
    /// in any order. A violation fails the commit rather than the statement, and
    /// `ON DELETE RESTRICT` acts at the commit too; `SET NULL`, `SET DEFAULT` and
    /// `CASCADE` still act at the statement.
    pub async fn begin(&self) -> Result<Transaction<'_, Sqlite>, Error> {
        begin(&self.pool).await
    }

    /// Close every connection and wait for it, for a process that exits after
    /// its last query, so no `-wal` or `-shm` is left beside the database.
    ///
    /// A connection still checked out is waited for up to five seconds, then
    /// left open with a warning. Then one connection is opened and closed alone,
    /// since SQLite removes the two files only when the last connection closes
    /// and the pool can close two at once. On Windows it then waits up to a
    /// second for them to go.
    pub async fn close(&self) {
        use sqlx::{ConnectOptions, Connection};

        close_once_returned(&self.pool).await;
        let alone = self
            .pool
            .connect_options()
            .as_ref()
            .clone()
            .create_if_missing(false);
        if let Ok(mut conn) = alone.connect().await {
            // A read, so the WAL is open to remove at the close.
            sqlx::query("PRAGMA schema_version")
                .execute(&mut conn)
                .await
                .ok();
            conn.close().await.ok();
            #[cfg(windows)]
            wait_for_removal(alone.get_filename()).await;
        }
    }
}

async fn begin(pool: &SqlitePool) -> Result<Transaction<'static, Sqlite>, Error> {
    let mut tx = pool.begin_with("BEGIN IMMEDIATE").await?;
    // Per transaction: SQLite switches it back off at the commit or rollback.
    sqlx::query("PRAGMA defer_foreign_keys = ON")
        .execute(&mut *tx)
        .await?;
    Ok(tx)
}

fn is_plain_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    bytes.next().is_some_and(|b| b.is_ascii_lowercase())
        && bytes.all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

/// WAL is a property of the file, and entering it takes an exclusive lock the
/// busy timeout cannot wait on, so two pooled connections entering it at once
/// on a new database would both fail with `database is locked`.
async fn enter_wal(opts: &SqliteConnectOptions) -> Result<(), Error> {
    use sqlx::{ConnectOptions, Connection};

    let conn = opts
        .clone()
        .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal)
        .connect()
        .await?;
    conn.close().await?;
    Ok(())
}

async fn close_once_returned(pool: &SqlitePool) {
    // Shuts out `acquire` at the call; awaited, it waits on checked-out
    // connections without limit, so it is awaited only once every one is idle.
    let close_idle = pool.close();
    let all_returned = async {
        while pool.num_idle() < pool.size() as usize {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    };
    if tokio::time::timeout(Duration::from_secs(5), all_returned)
        .await
        .is_err()
    {
        tracing::warn!(
            open = pool.size(),
            "closing the database with connections open"
        );
        return;
    }
    close_idle.await;
}

/// Run once WAL is entered and again once the pool is up, so `-wal` and `-shm`
/// exist to be restricted; on Windows they inherit the directory's ACL, so the
/// directory must itself be private.
fn restrict_to_owner(path: &Path) {
    for file in ["", "-wal", "-shm"].map(|suffix| sibling(path, suffix)) {
        match wslib_file_atomic::owner_only(&file) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => tracing::warn!(
                error = %e, path = %file.display(),
                "could not restrict the database to its owner"
            ),
        }
    }
}

fn sibling(db: &Path, suffix: &str) -> PathBuf {
    let mut name = db.as_os_str().to_os_string();
    name.push(suffix);
    PathBuf::from(name)
}

#[cfg(windows)]
async fn wait_for_removal(db: &Path) {
    let [wal, shm] = ["-wal", "-shm"].map(|suffix| sibling(db, suffix));
    let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
    while (wal.exists() || shm.exists()) && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}
