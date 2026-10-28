//! The tables every appliance has, in one SQLite file a product's own tables
//! share, so one backup, one permission and one transaction cover both.
//!
//! Every query uses sqlx's runtime API, never the `query!` macros.
//!
//! Opening, closing and write transactions are `wslib_db_sqlite::Database`'s:
//! WAL, owner-only files, and [`Store::open`] applies every pending migration,
//! the platform's and the product's, in one transaction.
//!
//! Every instant is stored through [`stamp`], whose fixed width lets SQLite
//! order and compare the columns as text.
//!
//! # The platform's schema object names are reserved
//!
//! Tables, indexes and views share one namespace in SQLite. A product's
//! migrations must not create, alter or drop these tables:
//! `_app_migrations`, `_migration_chains`, `_platform_migrations`,
//! `_sqlx_migrations`, `app_roles`, `asserted_roles`, `audit`, `passkeys`,
//! `recovery_codes`, `settings`, `totp`, `totp_required`, `trusted_cas`,
//! `trusted_certs`, `users`; nor these indexes: `audit_at`, `passkeys_user`.
//!
//! Every platform object not listed above is named `platform_…`, so a
//! product's own must not start with it.

use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use sqlx::migrate::MigrateError;
use sqlx::sqlite::SqlitePool;
use sqlx::{Sqlite, Transaction};
use wslib_auth::{SqliteSessionStore, TableName};
use wslib_db_sqlite::{Database, Settings};

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
    Migrate(#[from] MigrateError),

    /// [`Store::open_existing`] found no file.
    #[error(
        "no database at {0} — the appliance has not started yet, or this is not its \
         state directory: run under the unit's STATE_DIRECTORY"
    )]
    NoDatabase(PathBuf),

    /// [`Store::open_existing`] found a migration of this build's not applied.
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

    /// What the migration chains refuse beyond the variants above.
    #[error(transparent)]
    Database(wslib_db_sqlite::Error),
}

impl From<wslib_db_sqlite::Error> for StoreError {
    fn from(e: wslib_db_sqlite::Error) -> Self {
        use wslib_db_sqlite::Error as E;
        match e {
            E::Db(e) => Self::Db(e),
            E::Migrate { source, .. } => Self::Migrate(source),
            E::Unclaimed { version } => Self::Migrate(MigrateError::VersionMissing(version)),
            E::NoDatabase(path) => Self::NoDatabase(path),
            E::SchemaBehind { version, .. } => Self::SchemaBehind { version },
            E::Reserved(key) => Self::Reserved(key),
            E::Unreadable {
                table,
                what,
                because,
            } => Self::unreadable(table, what, because),
            E::Serialise { key, source } => {
                Self::unreadable("settings", "document", format!("{key}: {source}"))
            }
            other => Self::Database(other),
        }
    }
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
    db: Database,
    settings: Settings,
    sessions: SqliteSessionStore<String>,
    spares_host_admins: bool,
}

impl Store {
    /// Open (creating if absent), migrate, and restrict the file to its owner;
    /// `app`, the product's own chain, runs after the platform's.
    pub async fn open(path: impl AsRef<Path>, app: Option<Migrator>) -> Result<Self, StoreError> {
        let chains = migrate::chains(app.as_ref())?;
        Ok(Self::over(Database::open(path, &chains).await?))
    }

    /// [`open`](Self::open) for a process beside the daemon, run as its
    /// account, which neither creates nor migrates: no file is
    /// [`StoreError::NoDatabase`] and a database behind this build
    /// [`StoreError::SchemaBehind`].
    pub async fn open_existing(
        path: impl AsRef<Path>,
        app: Option<Migrator>,
    ) -> Result<Self, StoreError> {
        let chains = migrate::chains(app.as_ref())?;
        Ok(Self::over(Database::open_existing(path, &chains).await?))
    }

    /// An in-memory database with the same tables, for tests, on one
    /// connection: a [`Store::pool`] query while a [`Store::begin`] is held
    /// waits for it, and in the same task fails with `PoolTimedOut`.
    pub async fn open_in_memory(app: Option<Migrator>) -> Result<Self, StoreError> {
        let chains = migrate::chains(app.as_ref())?;
        Ok(Self::over(Database::open_in_memory(&chains).await?))
    }

    fn over(db: Database) -> Self {
        let settings = Settings::new(&db)
            .local_prefix(settings::BOX_PREFIX)
            .expect("box. is a local prefix");
        Self {
            sessions: SqliteSessionStore::new(db.pool().clone(), TableName::new(SESSIONS_TABLE)),
            db,
            settings,
            spares_host_admins: false,
        }
    }

    /// Close every connection, for a process that exits after its last query;
    /// it leaves no `-wal` or `-shm` once no connection, in this process or
    /// another, has the database open.
    pub async fn close(&self) {
        self.db.close().await;
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
        self.db
            .chain_version(migrate::APP)
            .map_or(0, |v| u32::try_from(v).unwrap_or(u32::MAX))
    }

    /// The pool, for a product's own queries against the same file.
    pub fn pool(&self) -> &SqlitePool {
        self.db.pool()
    }

    /// Begin a write transaction that takes the write lock up front and checks
    /// foreign keys at the commit, so a restore or a reset replaces the
    /// platform's rows and a product's in any order.
    pub async fn begin(&self) -> Result<Transaction<'_, Sqlite>, StoreError> {
        Ok(self.db.begin().await?)
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

    fn spawnable<F: Future + Send + 'static>(future: F) -> F {
        future
    }

    #[test]
    fn opening_is_spawnable() {
        drop(spawnable(Store::open(PathBuf::new(), None)));
        drop(spawnable(Store::open_existing(PathBuf::new(), None)));
        drop(spawnable(Store::open_in_memory(None)));
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

    async fn schema_objects(store: &Store) -> Vec<String> {
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
    async fn the_reserved_names_in_the_crate_doc_are_the_platforms_schema_objects() {
        let doc = include_str!("lib.rs").replace("\r\n", "\n");
        let list = doc
            .split_once("must not create, alter or drop these")
            .and_then(|(_, rest)| rest.split_once("\n//!\n"))
            .map(|(list, _)| list)
            .expect("the reserved list in the crate doc");
        let mut documented: Vec<&str> = list.split('`').skip(1).step_by(2).collect();
        documented.sort_unstable();
        let unprefixed: Vec<String> = schema_objects(&store().await)
            .await
            .into_iter()
            .filter(|name| !name.starts_with("platform_"))
            .filter(|name| !["app_notes", "app_widgets"].contains(&name.as_str()))
            .collect();
        assert_eq!(documented, unprefixed);

        // Frozen: every later platform object is named `platform_…`.
        let frozen = [
            "_app_migrations",
            "_migration_chains",
            "_platform_migrations",
            "_sqlx_migrations",
            "app_roles",
            "asserted_roles",
            "audit",
            "audit_at",
            "passkeys",
            "passkeys_user",
            "recovery_codes",
            "settings",
            "totp",
            "totp_required",
            "trusted_cas",
            "trusted_certs",
            "users",
        ];
        assert_eq!(documented, frozen);
    }

    #[tokio::test]
    async fn the_platforms_tables_and_an_apps_share_one_database() {
        let store = store().await;
        let mut expected = vec![
            "_app_migrations",
            "_migration_chains",
            "_platform_migrations",
            "_sqlx_migrations",
            "app_notes",
            "app_widgets",
        ];
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

        let no_app = Store::open_existing(&path, None).await;
        assert!(
            matches!(
                &no_app,
                Err(StoreError::Database(wslib_db_sqlite::Error::UnknownChain(chain)))
                    if chain == "app"
            ),
            "{no_app:?}"
        );
        let shorter = Store::open_existing(&path, Some(Migrator::DEFAULT)).await;
        assert!(
            matches!(
                shorter,
                Err(StoreError::Migrate(MigrateError::VersionMissing(1000)))
            ),
            "{shorter:?}"
        );

        let second = Store::open_existing(&path, Some(app_migrations()))
            .await
            .expect("re-open, checking the applied chain rather than running it");
        assert_eq!(
            second.setting("branding.app_name").await.expect("get"),
            Some("Widget Monitor".to_string())
        );
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
