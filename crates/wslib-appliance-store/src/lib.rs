//! The tables every appliance has, in one SQLite file a product's own tables
//! share, so one backup, one permission and one transaction cover both.
//!
//! Every query uses sqlx's runtime API, never the `query!` macros.
//!
//! What [`Store::open`] and [`Store::open_existing`] do that a plain `connect`
//! does not:
//!
//! - **WAL is entered once, on a connection of its own**, because it takes an
//!   exclusive lock that `busy_timeout` cannot wait on.
//! - **The file is restricted to its owner on every open**, because a service
//!   manager only restricts a directory it created itself.
//! - **Write transactions take the write lock up front, and check foreign keys
//!   at the commit.** See [`Store::begin`].
//!
//! Every instant is stored through [`stamp`], whose fixed width lets SQLite
//! order and compare the columns as text.
//!
//! # The platform's schema object names are reserved
//!
//! Tables, indexes and views share one namespace in SQLite. A product's
//! migrations must not create, alter or drop these tables:
//! `_sqlx_migrations`, `app_roles`, `asserted_roles`, `audit`, `passkeys`,
//! `recovery_codes`, `settings`, `totp`, `totp_required`, `trusted_cas`,
//! `trusted_certs`, `users`; nor these indexes: `audit_at`, `passkeys_user`.
//!
//! Every platform object not listed above is named `platform_…`, so a
//! product's own must not start with it.

use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePool, SqlitePoolOptions};
use sqlx::{Sqlite, Transaction};
use tokio::sync::watch;
use wslib_auth::{SqliteSessionStore, TableName};

/// The account a guarded write names, unless it is a host admin's and the store
/// spares them: binds `!spares_host_admins`, then the id.
macro_rules! the_target {
    () => {
        "(? OR role != 'hostadmin') AND id = ?"
    };
}

mod asserted;
mod audit;
mod certs;
mod factors;
mod migrate;
mod reset;
mod settings;
mod users;

pub use asserted::AssertedCaller;
pub use factors::{NewPasskey, Passkey, PasskeyUse, SecondFactors, Totp};
pub use migrate::APP_FLOOR;
pub use users::Account;
/// The one spelling of an instant in this database: fixed-width RFC 3339 in
/// UTC, which sorts as text.
pub use wslib_db_sqlite::stamp::format as stamp;
pub use wslib_db_sqlite::stamp::now;

/// The whole of sqlx; `migrate!` still needs `sqlx` in the product's own
/// manifest, at this crate's version.
pub use sqlx;
pub use sqlx::migrate::Migrator;

/// The table the sessions are rows of, for the session store; never in a backup.
pub const SESSIONS_TABLE: &str = "platform_sessions";

const BUSY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Why a store operation could not be completed.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum StoreError {
    #[error("database: {0}")]
    Db(#[from] sqlx::Error),

    /// A settings key inside the `secret.` or `box.` namespace, handed to
    /// [`Store::setting`] or [`Store::set_setting`].
    #[error(
        "the settings key {0:?} is in a reserved namespace — a secret.* key goes \
         through Store::secret/set_secret and a box.* key through \
         Store::box_state/set_box_state, each by the name without its prefix"
    )]
    Reserved(String),

    #[error("migration: {0}")]
    Migrate(#[from] sqlx::migrate::MigrateError),

    /// [`Store::open_existing`] found no file.
    #[error(
        "no database at {0} — the appliance has not started yet, or this is not its \
         state directory: run under the unit's STATE_DIRECTORY"
    )]
    NoDatabase(PathBuf),

    /// [`Store::open_existing`] found a database this build's chain has not
    /// finished with.
    #[error(
        "the database is behind this build (migration {version} is not applied) — start, \
         or restart, the appliance, which migrates it"
    )]
    SchemaBehind { version: i64 },

    /// An app migration numbered inside the platform's range. See [`APP_FLOOR`].
    #[error(
        "the app migration {version} ({description:?}) is below {APP_FLOOR}, \
         which is the platform's range — number an app's migrations from {APP_FLOOR}"
    )]
    MigrationVersion { version: i64, description: String },

    #[error("no such user: {0}")]
    NoSuchUser(String),

    #[error("the username {0:?} is already taken")]
    UsernameTaken(String),

    /// A demotion, disable or delete that would leave a box that has an enabled
    /// host admin with none.
    #[error(
        "this is the last enabled host admin, and a box that has one keeps one; make \
         another host admin first"
    )]
    LastHostAdmin,

    /// A write on a host admin's account through
    /// [`Store::sparing_host_admins`].
    #[error("only a host admin, signed in, changes a host admin's account")]
    HostAdminsOnly,

    /// A per-app role of `hostadmin`, which only an account's own role may be.
    #[error("an account's role in an app is viewer, operator or admin")]
    NotAnAppRole,

    /// A passkey whose credential is already registered here.
    #[error("that passkey is already registered on this appliance")]
    PasskeyTaken,

    /// A stored row this build cannot read.
    #[error("unreadable {what} in {table}: {because}")]
    Unreadable {
        table: &'static str,
        what: &'static str,
        because: String,
    },

    /// A paging cursor that did not come from this store: the caller's
    /// mistake, where [`StoreError::Unreadable`] is the box's.
    #[error("that cursor did not come from this appliance: {0:?}")]
    BadCursor(String),
}

impl StoreError {
    fn unreadable(table: &'static str, what: &'static str, because: impl ToString) -> Self {
        Self::Unreadable {
            table,
            what,
            because: because.to_string(),
        }
    }
}

/// Read a column [`stamp`] wrote.
pub fn parse_stamp(
    table: &'static str,
    what: &'static str,
    raw: &str,
) -> Result<DateTime<Utc>, StoreError> {
    DateTime::parse_from_rfc3339(raw)
        .map(|t| t.with_timezone(&Utc))
        .map_err(|e| StoreError::unreadable(table, what, e))
}

/// [`parse_stamp`] straight off a row, borrowing the column.
pub fn row_stamp(
    row: &sqlx::sqlite::SqliteRow,
    table: &'static str,
    column: &'static str,
) -> Result<DateTime<Utc>, StoreError> {
    use sqlx::Row;
    parse_stamp(table, column, row.try_get::<&str, _>(column)?)
}

/// The appliance's database.
#[derive(Debug, Clone)]
pub struct Store {
    pool: SqlitePool,
    sessions: SqliteSessionStore<String>,
    app_schema: u32,
    spares_host_admins: bool,
    settings: Arc<watch::Sender<u64>>,
}

#[derive(Debug, Clone, Copy)]
enum Schema {
    Migrate,
    Verify,
}

impl Store {
    /// Open (creating if absent), migrate, and restrict the file to its owner;
    /// `app`, the product's own chain, runs after the platform's.
    pub async fn open(path: impl AsRef<Path>, app: Option<Migrator>) -> Result<Self, StoreError> {
        Self::open_at(path.as_ref(), app, Schema::Migrate).await
    }

    /// [`open`](Self::open) for a process beside the daemon, run as its
    /// account, which neither creates nor migrates: no file is
    /// [`StoreError::NoDatabase`] and a database behind this build
    /// [`StoreError::SchemaBehind`].
    pub async fn open_existing(
        path: impl AsRef<Path>,
        app: Option<Migrator>,
    ) -> Result<Self, StoreError> {
        let path = path.as_ref();
        let there = path
            .try_exists()
            .map_err(|e| StoreError::Db(sqlx::Error::Io(e)))?;
        if !there {
            return Err(StoreError::NoDatabase(path.to_path_buf()));
        }
        Self::open_at(path, app, Schema::Verify).await
    }

    async fn open_at(
        path: &Path,
        app: Option<Migrator>,
        schema: Schema,
    ) -> Result<Self, StoreError> {
        let opts = SqliteConnectOptions::new()
            .filename(path)
            .create_if_missing(matches!(schema, Schema::Migrate))
            .synchronous(sqlx::sqlite::SqliteSynchronous::Normal)
            .foreign_keys(true)
            .busy_timeout(BUSY_TIMEOUT);

        enter_wal(&opts).await?;
        restrict_to_owner(path);
        let store = Self::pooled(opts, 5, app, schema).await?;
        restrict_to_owner(path);
        Ok(store)
    }

    /// Close every connection, for a process that exits after its last query;
    /// it leaves no `-wal` or `-shm` once no connection, in this process or
    /// another, has the database open. One still checked out is waited for up
    /// to five seconds, then left open with a warning.
    pub async fn close(&self) {
        use sqlx::{ConnectOptions, Connection};

        close_once_returned(&self.pool).await;
        let alone = self
            .pool
            .connect_options()
            .as_ref()
            .clone()
            .create_if_missing(false);
        // Closed alone, as SQLite removes `-wal` and `-shm` only at the last close.
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

    /// An in-memory database with the same tables, for tests, on **one
    /// connection**: a query while a [`Store::begin`] is held waits for it, and
    /// in the same task fails with `PoolTimedOut` after 30 seconds.
    pub async fn open_in_memory(app: Option<Migrator>) -> Result<Self, StoreError> {
        let opts = SqliteConnectOptions::from_str("sqlite::memory:")
            .expect("a literal in-memory URL parses")
            .foreign_keys(true);
        Self::pooled(opts, 1, app, Schema::Migrate).await
    }

    async fn pooled(
        opts: SqliteConnectOptions,
        max_connections: u32,
        app: Option<Migrator>,
        schema: Schema,
    ) -> Result<Self, StoreError> {
        let pool = SqlitePoolOptions::new()
            .max_connections(max_connections)
            .min_connections(1)
            .idle_timeout(None)
            .max_lifetime(None)
            .connect_with(opts)
            .await?;

        let app_schema = app
            .iter()
            .flat_map(|app| app.iter())
            .map(|m| u32::try_from(m.version).unwrap_or(u32::MAX))
            .max()
            .unwrap_or(0);
        let chain = migrate::compose(app).await?;
        let ready = match schema {
            Schema::Migrate => chain.run(&pool).await.map_err(StoreError::from),
            Schema::Verify => migrate::verify_applied(&chain, &pool).await,
        };
        if let Err(e) = ready {
            close_once_returned(&pool).await;
            return Err(e);
        }
        Ok(Self {
            sessions: SqliteSessionStore::new(pool.clone(), TableName::new(SESSIONS_TABLE)),
            pool,
            app_schema,
            spares_host_admins: false,
            settings: Arc::new(watch::Sender::new(0)),
        })
    }

    /// This store, whose account writes leave a host admin's account untouched
    /// and answer [`StoreError::HostAdminsOnly`]: for a caller that is not one.
    pub fn sparing_host_admins(&self) -> Self {
        Self {
            spares_host_admins: true,
            ..self.clone()
        }
    }

    /// The version of the newest migration in the product's own chain, `0`
    /// for none: what a backup is stamped with.
    pub fn app_schema_version(&self) -> u32 {
        self.app_schema
    }

    /// The pool, for a product's own queries against the same file.
    pub fn pool(&self) -> &SqlitePool {
        &self.pool
    }

    /// Begin a write transaction with `BEGIN IMMEDIATE`, **taking the write
    /// lock up front** so a read-then-write waits through the busy timeout
    /// rather than failing `SQLITE_BUSY`.
    ///
    /// Foreign keys are checked at the commit, so a restore or a reset replaces
    /// the platform's rows and a product's in any order; `ON DELETE RESTRICT`
    /// acts at the commit too, `SET NULL` and `CASCADE` at the statement.
    pub async fn begin(&self) -> Result<Transaction<'_, Sqlite>, StoreError> {
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        // Per transaction: SQLite switches it back off at the commit or rollback.
        sqlx::query("PRAGMA defer_foreign_keys = ON")
            .execute(&mut *tx)
            .await?;
        Ok(tx)
    }
}

async fn enter_wal(opts: &SqliteConnectOptions) -> Result<(), StoreError> {
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
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    };
    if tokio::time::timeout(std::time::Duration::from_secs(5), all_returned)
        .await
        .is_err()
    {
        tracing::warn!(
            open = pool.size(),
            "closing the store with database connections open"
        );
        return;
    }
    close_idle.await;
}

/// On Windows `-wal` and `-shm` inherit the directory's ACL, so the directory
/// must itself be private.
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
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(1);
    while (wal.exists() || shm.exists()) && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    pub(crate) fn app_migrations() -> Migrator {
        sqlx::migrate!("./test-migrations/app")
    }

    pub(crate) async fn store() -> Store {
        Store::open_in_memory(Some(app_migrations()))
            .await
            .expect("in-memory store")
    }

    pub(crate) async fn tables(store: &Store) -> Vec<String> {
        sqlx::query_scalar(
            "SELECT name FROM sqlite_master WHERE type = 'table' \
             AND name NOT LIKE 'sqlite_%' ORDER BY name",
        )
        .fetch_all(store.pool())
        .await
        .expect("list tables")
    }

    pub(crate) async fn schema_objects(store: &Store) -> Vec<String> {
        sqlx::query_scalar(
            "SELECT name FROM sqlite_master WHERE name NOT GLOB 'sqlite_*' ORDER BY name",
        )
        .fetch_all(store.pool())
        .await
        .expect("list schema objects")
    }

    pub(crate) async fn session(store: &Store, user_id: &str) {
        sqlx::query(&format!(
            "INSERT INTO {SESSIONS_TABLE} VALUES (?1, ?2, ?3, ?3, ?3, ?3)"
        ))
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(user_id)
        .bind(stamp(now()))
        .execute(store.pool())
        .await
        .expect("a session row");
    }

    #[tokio::test]
    async fn in_memory_a_pool_query_waits_until_the_transaction_ends() {
        let store = store().await;
        let tx = store.begin().await.expect("begin");
        let query = || sqlx::query("SELECT 1").execute(store.pool());
        let waited = tokio::time::timeout(std::time::Duration::from_millis(200), query()).await;
        assert!(
            waited.is_err(),
            "still waiting while the transaction is held"
        );
        drop(tx);
        query().await.expect("answered once the transaction ends");
    }

    #[tokio::test]
    async fn the_reserved_names_in_the_crate_doc_are_the_platforms_schema_objects() {
        let doc = include_str!("lib.rs").replace("\r\n", "\n");
        let list = doc
            .split_once("must not create, alter or drop these")
            .and_then(|(_, rest)| rest.split_once("\n//!\n"))
            .map(|(list, _)| list)
            .expect("the reserved list in the crate doc");
        let mut documented: Vec<&str> = list.split('`').skip(1).step_by(2).collect();
        documented.sort_unstable();
        let platform_only = Store::open_in_memory(None).await.expect("store");
        let unprefixed: Vec<String> = schema_objects(&platform_only)
            .await
            .into_iter()
            .filter(|name| !name.starts_with("platform_"))
            .collect();
        assert_eq!(documented, unprefixed);
    }

    #[tokio::test]
    async fn the_platforms_tables_and_an_apps_share_one_database() {
        let store = store().await;
        let mut expected = vec!["_sqlx_migrations", "app_notes", "app_widgets"];
        expected.extend(crate::reset::PLATFORM_TABLES);
        expected.sort_unstable();
        assert_eq!(tables(&store).await, expected);
    }

    #[tokio::test]
    async fn a_transaction_from_begin_does_not_check_foreign_keys_per_statement() {
        let store = store().await;
        let user = store
            .create_user(
                "admin",
                "not-a-real-hash",
                wslib_appliance_types::Role::Admin,
            )
            .await
            .expect("create");
        sqlx::query("INSERT INTO app_widgets (name, owner) VALUES ('a widget', ?)")
            .bind(&user.id)
            .execute(store.pool())
            .await
            .expect("an app row");

        let mut tx = store.begin().await.expect("begin");
        store
            .replace_accounts(&mut tx, &[], &[], &[])
            .await
            .expect("the parent rows go first");
        sqlx::query("DELETE FROM app_widgets")
            .execute(&mut *tx)
            .await
            .expect("the child rows after");
        tx.commit()
            .await
            .expect("nothing is left dangling at the commit");
    }

    #[tokio::test]
    async fn an_apps_table_can_reference_the_platforms() {
        let store = store().await;
        let user = store
            .create_user(
                "admin",
                "not-a-real-hash",
                wslib_appliance_types::Role::Admin,
            )
            .await
            .expect("create");

        sqlx::query("INSERT INTO app_widgets (name, owner) VALUES (?, ?)")
            .bind("a widget")
            .bind(&user.id)
            .execute(store.pool())
            .await
            .expect("an app row referencing a platform row");

        let orphan = sqlx::query("INSERT INTO app_widgets (name, owner) VALUES (?, ?)")
            .bind("an orphan")
            .bind("nobody")
            .execute(store.pool())
            .await;
        assert!(
            orphan.is_err(),
            "foreign keys must be on, or the reference is decorative"
        );
    }

    #[tokio::test]
    async fn a_second_open_of_one_file_finds_what_the_first_wrote() {
        let dir = TempDir::new().expect("temp dir");
        let path = dir.path().join("appliance.db");

        let refused = Store::open_existing(&path, Some(app_migrations())).await;
        assert!(
            matches!(refused, Err(StoreError::NoDatabase(_))),
            "{refused:?}"
        );
        assert!(!path.exists());

        // Made and never migrated, then migrated by a build without the app's chain.
        std::fs::write(&path, b"").expect("an empty file");
        let behind = Store::open_existing(&path, Some(app_migrations())).await;
        assert!(
            matches!(behind, Err(StoreError::SchemaBehind { version: 1 })),
            "{behind:?}"
        );
        Store::open(&path, None)
            .await
            .expect("platform only")
            .close()
            .await;
        let behind = Store::open_existing(&path, Some(app_migrations())).await;
        assert!(
            matches!(behind, Err(StoreError::SchemaBehind { version: 1000 })),
            "{behind:?}"
        );

        let first = Store::open(&path, Some(app_migrations()))
            .await
            .expect("open");
        first
            .set_setting("branding.app_name", "Widget Monitor")
            .await
            .expect("set");
        first.close().await;

        let ahead = Store::open_existing(&path, None).await;
        assert!(
            matches!(
                ahead,
                Err(StoreError::Migrate(
                    sqlx::migrate::MigrateError::VersionMissing(1000)
                ))
            ),
            "{ahead:?}"
        );

        let second = Store::open_existing(&path, Some(app_migrations()))
            .await
            .expect("re-open, checking the applied chain rather than running it");
        assert_eq!(
            second.setting("branding.app_name").await.expect("get"),
            Some("Widget Monitor".to_string())
        );

        let mode: String = sqlx::query_scalar("PRAGMA journal_mode")
            .fetch_one(second.pool())
            .await
            .expect("journal_mode");
        assert_eq!(mode.to_lowercase(), "wal");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for name in ["appliance.db", "appliance.db-wal", "appliance.db-shm"] {
                let file = std::fs::metadata(dir.path().join(name)).expect(name);
                let mode = file.permissions().mode();
                assert_eq!(mode & 0o777, 0o600, "{name} is owner-only");
            }
        }
    }

    #[tokio::test]
    async fn a_closed_store_leaves_nothing_beside_the_database() {
        let dir = TempDir::new().expect("temp dir");
        let store = Store::open(dir.path().join("appliance.db"), None)
            .await
            .expect("open");
        store
            .set_setting("branding.app_name", "Widget Monitor")
            .await
            .expect("set");
        store.close().await;
        for name in ["appliance.db-wal", "appliance.db-shm"] {
            assert!(!dir.path().join(name).exists(), "{name}");
        }
    }

    /// A file store whose pool has every connection checked out, at least two.
    async fn every_connection_held(
        dir: &TempDir,
    ) -> (Store, PathBuf, Vec<sqlx::pool::PoolConnection<Sqlite>>) {
        let path = dir.path().join("appliance.db");
        let store = Store::open(&path, None).await.expect("open");
        let pool = store.pool();
        while pool.num_idle() < pool.size() as usize {
            tokio::time::sleep(std::time::Duration::from_millis(1)).await;
        }
        let mut held = Vec::new();
        for _ in 0..pool.size().max(2) {
            held.push(pool.acquire().await.expect("acquire"));
        }
        (store, sibling(&path, "-wal"), held)
    }

    #[tokio::test]
    async fn closing_removes_the_wal_though_a_connection_was_mid_return() {
        let dir = TempDir::new().expect("temp dir");
        let (store, wal, mut held) = every_connection_held(&dir).await;
        let returning = held.pop().expect("two held");
        for conn in held {
            conn.close().await.expect("close");
        }
        drop(returning);
        tokio::task::yield_now().await;
        store.close().await;
        assert!(!wal.exists());
    }

    #[tokio::test]
    async fn closing_waits_for_a_connection_still_checked_out() {
        let dir = TempDir::new().expect("temp dir");
        let (store, wal, mut held) = every_connection_held(&dir).await;
        let out = held.pop().expect("two held");
        drop(held);
        while store.pool().num_idle() == 0 {
            tokio::time::sleep(std::time::Duration::from_millis(1)).await;
        }
        tokio::join!(store.close(), async {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            drop(out);
        });
        assert!(!wal.exists());
    }

    #[tokio::test]
    async fn closing_gives_up_on_a_connection_never_returned() {
        let dir = TempDir::new().expect("temp dir");
        let (store, _, held) = every_connection_held(&dir).await;
        tokio::time::timeout(std::time::Duration::from_secs(10), store.close())
            .await
            .expect("close waits five seconds, not for ever");
        drop(held);
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn on_windows_the_database_is_its_owners_and_systems_alone() {
        let dir = TempDir::new().expect("temp dir");
        let store = Store::open(dir.path().join("appliance.db"), None)
            .await
            .expect("open");
        store
            .set_setting("branding.app_name", "Widget Monitor")
            .await
            .expect("set");

        for name in ["appliance.db", "appliance.db-wal", "appliance.db-shm"] {
            let file = dir.path().join(name);
            assert!(file.exists(), "{name}");
            wslib_file_atomic::testing::assert_owner_only(&file);
        }
        store.close().await;
    }

    #[test]
    fn an_instant_survives_the_round_trip() {
        let at = DateTime::from_timestamp(1_757_000_000, 123_456_000).unwrap();
        assert_eq!(parse_stamp("t", "at", &stamp(at)).unwrap(), at);
        assert!(matches!(
            parse_stamp("t", "at", "yesterday"),
            Err(StoreError::Unreadable {
                table: "t",
                what: "at",
                ..
            })
        ));
    }
}
