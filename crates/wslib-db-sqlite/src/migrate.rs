//! Migration chains, applied together in one transaction.
//!
//! A [`Chain`] is a name and an sqlx `Migrator`, usually an app's own
//! `sqlx::migrate!("./migrations")`, and each records what it has applied in
//! its own table, `_<name>_migrations`. Versions are the chain's own: two chains
//! may both start at 1. Every chain is registered in `_migration_chains` when
//! its table is made, and an open that does not pass a registered chain is
//! refused ([`Error::UnknownChain`]).
//!
//! [`Database::open`](crate::Database::open) applies every pending migration of
//! every chain, in the order the chains are given and each chain's own order,
//! in **one transaction**: a failure anywhere leaves the database as it was,
//! earlier chains included. A migration marked `-- no-transaction` cannot join
//! it and is refused. A modified applied migration is refused, and so is an
//! applied version its chain no longer has. A migration added to an earlier
//! chain after a later one applied simply applies at the next open.
//!
//! # Builds on sqlx's own runner
//!
//! sqlx's runner records one chain in `_sqlx_migrations`. A *mirrored* chain
//! also writes each migration it applies there, in sqlx's own columns, so a
//! build on sqlx's runner over the same chains concatenated finds every version
//! it knows and runs, and refuses a newer schema with `VersionMissing`. A chain
//! is mirrored when it asks to be ([`Chain::mirrored`]) or when it is made by
//! the import, and the registry keeps that from then on. A version two
//! mirrored chains would both write refuses the open before anything applies
//! ([`Error::Collision`]).
//!
//! **The import** runs on the open that creates the registry, if
//! `_sqlx_migrations` has rows then, and again on every open while a chain is
//! mirrored, for the rows sqlx's runner wrote after a rollback: each row no
//! mirrored chain has recorded goes to the mirrored chain that has its version,
//! with its checksum checked, inside the same transaction, and is never run. A
//! row no mirrored chain has ([`Error::Unclaimed`]) or two have
//! ([`Error::Ambiguous`]) refuses the open.
//! [`Database::open_existing`](crate::Database::open_existing) verifies by the
//! same rules, and writes nothing.
//!
//! Migrations run with foreign keys off, as SQLite's table-rebuild recipe
//! asks, so their actions such as `ON DELETE CASCADE` do not fire; a reference
//! one leaves dangling still fails that migration, as under sqlx's runner.
//! The connection goes back to the pool with foreign keys on, or is closed.
//!
//! The tables this module keeps, `_<name>_migrations`, `_migration_chains` and
//! `_sqlx_migrations`, are not an app's to create, alter or drop.

use std::borrow::Cow;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::time::Instant;

use sqlx::error::{DatabaseError, ErrorKind};
use sqlx::migrate::{MigrateError, Migration, Migrator};
use sqlx::sqlite::SqlitePool;
use sqlx::{Connection, SqliteConnection};

use crate::{Error, is_plain_name, stamp};

const LEGACY: &str = "_sqlx_migrations";
const REGISTRY: &str = "_migration_chains";

/// A named migration chain; the name is `[a-z][a-z0-9_]*`, checked at open.
#[derive(Debug, Clone)]
pub struct Chain {
    name: String,
    migrations: Vec<Migration>,
    mirrored: bool,
}

impl Chain {
    pub fn new(name: impl Into<String>, migrator: &Migrator) -> Self {
        Self {
            name: name.into(),
            migrations: migrator
                .iter()
                .filter(|m| m.migration_type.is_up_migration())
                .cloned()
                .collect(),
            mirrored: false,
        }
    }

    /// Also record this chain in `_sqlx_migrations` from its first migration,
    /// for a database an older build on sqlx's runner may open.
    ///
    /// Chosen when the chain is first registered: asked for later it is refused
    /// ([`Error::MirroredTooLate`]), and a chain registered as mirrored stays
    /// mirrored whether or not it asks.
    pub fn mirrored(mut self) -> Self {
        self.mirrored = true;
        self
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    /// The newest version in the chain, `None` for an empty one.
    pub fn version(&self) -> Option<i64> {
        self.migrations.iter().map(|m| m.version).max()
    }

    fn get(&self, version: i64) -> Option<&Migration> {
        self.migrations.iter().find(|m| m.version == version)
    }

    fn table(&self) -> String {
        format!("_{}_migrations", self.name)
    }

    fn error(&self, source: MigrateError) -> Error {
        Error::Migrate {
            chain: self.name.clone(),
            source,
        }
    }
}

/// Applied versions and their hex checksums.
type Applied = BTreeMap<i64, String>;

/// A row of `_sqlx_migrations`.
struct LegacyRow {
    version: i64,
    description: String,
    installed_on: String,
    checksum: Vec<u8>,
    success: bool,
}

pub(crate) fn check_names(chains: &[Chain]) -> Result<(), Error> {
    for (i, chain) in chains.iter().enumerate() {
        if !is_plain_name(&chain.name) {
            return Err(Error::InvalidName(chain.name.clone()));
        }
        if [LEGACY, REGISTRY].contains(&chain.table().as_str()) {
            return Err(Error::ReservedChain(chain.name.clone()));
        }
        if chains[..i].iter().any(|c| c.name == chain.name) {
            return Err(Error::DuplicateChain(chain.name.clone()));
        }
    }
    Ok(())
}

pub(crate) async fn verify(pool: &SqlitePool, chains: &[Chain]) -> Result<(), Error> {
    let mut conn = pool.acquire().await?;
    let conn = &mut *conn;
    let legacy = legacy_rows(conn).await?;
    let (_, mirrored) = registry(conn, chains, &legacy).await?;
    let (applied_by_chain, _) = applied_by_chain(conn, chains, &mirrored, &legacy).await?;
    for (chain, applied) in chains.iter().zip(&applied_by_chain) {
        if let Some(behind) = chain
            .migrations
            .iter()
            .find(|m| !applied.contains_key(&m.version))
        {
            return Err(Error::SchemaBehind {
                chain: chain.name.clone(),
                version: behind.version,
            });
        }
        check_applied(chain, applied)?;
    }
    Ok(())
}

pub(crate) async fn apply(pool: &SqlitePool, chains: &[Chain]) -> Result<(), Error> {
    let mut conn = pool.acquire().await?;
    let applied = apply_with_foreign_keys_off(&mut conn, chains).await;
    if let Err(e) = restore_foreign_keys(&mut conn).await {
        conn.close().await.ok();
        return applied.and(Err(e));
    }
    applied
}

async fn apply_with_foreign_keys_off(
    conn: &mut SqliteConnection,
    chains: &[Chain],
) -> Result<(), Error> {
    // Before BEGIN, where it is a no-op: SQLite's table-rebuild recipe, since a
    // dropped parent counts against the commit even once its rows are restored.
    sqlx::query("PRAGMA foreign_keys = OFF")
        .execute(&mut *conn)
        .await?;
    let mut tx = conn.begin_with("BEGIN IMMEDIATE").await?;
    let conn = &mut *tx;

    let legacy = legacy_rows(conn).await?;
    let (registered, mirrored) = registry(conn, chains, &legacy).await?;
    if registered.is_none() {
        sqlx::query(&format!(
            "CREATE TABLE {REGISTRY} (
                name       TEXT PRIMARY KEY,
                mirrored   BOOLEAN NOT NULL,
                created_on TEXT NOT NULL
            )"
        ))
        .execute(&mut *conn)
        .await?;
    }
    for chain in chains {
        if registered
            .as_ref()
            .is_some_and(|r| r.contains_key(&chain.name))
        {
            continue;
        }
        sqlx::query(&format!(
            "CREATE TABLE {} (
                version      BIGINT PRIMARY KEY,
                description  TEXT NOT NULL,
                checksum     TEXT NOT NULL,
                installed_on TEXT NOT NULL
            )",
            chain.table()
        ))
        .execute(&mut *conn)
        .await?;
        sqlx::query(&format!(
            "INSERT INTO {REGISTRY} (name, mirrored, created_on) VALUES (?, ?, ?)"
        ))
        .bind(&chain.name)
        .bind(mirrored.contains(chain.name.as_str()))
        .bind(stamp::format(stamp::now()))
        .execute(&mut *conn)
        .await?;
    }
    if !mirrored.is_empty() && !table_exists(conn, LEGACY).await? {
        // sqlx 0.8's own DDL, so its runner finds the table it would have made.
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS _sqlx_migrations (
    version BIGINT PRIMARY KEY,
    description TEXT NOT NULL,
    installed_on TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    success BOOLEAN NOT NULL,
    checksum BLOB NOT NULL,
    execution_time BIGINT NOT NULL
);",
        )
        .execute(&mut *conn)
        .await?;
    }

    let (applied_by_chain, unrecorded) = applied_by_chain(conn, chains, &mirrored, &legacy).await?;
    for (i, row) in unrecorded {
        let installed_on =
            chrono::NaiveDateTime::parse_from_str(&row.installed_on, "%Y-%m-%d %H:%M:%S")
                .map_err(|e| Error::unreadable(LEGACY, "installed_on", e))?;
        record(
            conn,
            &chains[i],
            row.version,
            &row.description,
            &hex(&row.checksum),
            &stamp::format(installed_on.and_utc()),
        )
        .await?;
    }

    let mut owners = HashMap::new();
    let mut pending = Vec::new();
    for (chain, applied) in chains.iter().zip(&applied_by_chain) {
        check_applied(chain, applied)?;
        if mirrored.contains(chain.name.as_str()) {
            owners.extend(applied.keys().map(|&v| (v, chain.name.as_str())));
        }
        for m in &chain.migrations {
            if applied.contains_key(&m.version) {
                continue;
            }
            if m.no_tx {
                return Err(Error::NoTransaction {
                    chain: chain.name.clone(),
                    version: m.version,
                });
            }
            pending.push((chain, m));
        }
    }
    check_collisions(&pending, &mirrored, owners)?;

    let dangling_before = if pending.is_empty() {
        Vec::new()
    } else {
        dangling(conn).await?
    };
    for (chain, m) in pending {
        let started = Instant::now();
        // `raw_sql(..).execute(conn)` makes `Database::open`'s future not `Send`.
        sqlx::Executor::execute(&mut *conn, sqlx::raw_sql(&m.sql))
            .await
            .map_err(|e| chain.error(MigrateError::ExecuteMigration(e, m.version)))?;
        if let Some(new) = dangling(conn)
            .await?
            .into_iter()
            .find(|d| !dangling_before.contains(d))
        {
            let violation = sqlx::Error::Database(Box::new(new));
            return Err(chain.error(MigrateError::ExecuteMigration(violation, m.version)));
        }
        record(
            conn,
            chain,
            m.version,
            &m.description,
            &hex(&m.checksum),
            &stamp::format(stamp::now()),
        )
        .await?;
        if mirrored.contains(chain.name.as_str()) {
            // So an older build on sqlx's runner finds a version it lacks and
            // refuses, rather than running on a schema newer than it knows.
            sqlx::query(&format!(
                "INSERT INTO {LEGACY} (version, description, success, checksum, execution_time) \
                 VALUES (?, ?, TRUE, ?, ?)"
            ))
            .bind(m.version)
            .bind(&*m.description)
            .bind(&*m.checksum)
            .bind(i64::try_from(started.elapsed().as_nanos()).unwrap_or(i64::MAX))
            .execute(&mut *conn)
            .await?;
        }
    }
    tx.commit().await?;
    Ok(())
}

/// A no-op still inside a transaction, so read back rather than trusted.
async fn restore_foreign_keys(conn: &mut SqliteConnection) -> Result<(), Error> {
    sqlx::query("PRAGMA foreign_keys = ON")
        .execute(&mut *conn)
        .await?;
    let on: bool = sqlx::query_scalar("PRAGMA foreign_keys")
        .fetch_one(conn)
        .await?;
    if !on {
        let stuck = "foreign keys stayed off after the migrations";
        return Err(sqlx::Error::Protocol(stuck.into()).into());
    }
    Ok(())
}

/// The registry, `None` before it exists, checked against `chains`, and the
/// chains that are or will be registered as mirrored: those that ask, and every
/// one an import makes.
async fn registry<'c>(
    conn: &mut SqliteConnection,
    chains: &'c [Chain],
    legacy: &[LegacyRow],
) -> Result<(Option<BTreeMap<String, bool>>, HashSet<&'c str>), Error> {
    let registered = registered(conn).await?;
    if let Some(registered) = &registered {
        check_registered(registered, chains)?;
    }
    let importing = registered.is_none() && !legacy.is_empty();
    let mirrored = chains
        .iter()
        .filter(|c| {
            registered
                .as_ref()
                .and_then(|r| r.get(&c.name).copied())
                .unwrap_or(c.mirrored || importing)
        })
        .map(|c| c.name.as_str())
        .collect();
    Ok((registered, mirrored))
}

/// Each chain's applied migrations, counting the `_sqlx_migrations` rows
/// claimed by a mirrored chain that has not recorded them, which are returned
/// to record.
async fn applied_by_chain<'r>(
    conn: &mut SqliteConnection,
    chains: &[Chain],
    mirrored: &HashSet<&str>,
    legacy: &'r [LegacyRow],
) -> Result<(Vec<Applied>, Vec<(usize, &'r LegacyRow)>), Error> {
    let mut applied_by_chain = Vec::new();
    for chain in chains {
        applied_by_chain.push(applied(conn, chain).await?);
    }
    if mirrored.is_empty() {
        return Ok((applied_by_chain, Vec::new()));
    }
    let recorded: HashSet<i64> = chains
        .iter()
        .zip(&applied_by_chain)
        .filter(|(c, _)| mirrored.contains(c.name.as_str()))
        .flat_map(|(_, applied)| applied.keys().copied())
        .collect();
    let unrecorded = legacy
        .iter()
        .filter(|row| !row.success || !recorded.contains(&row.version));
    let claimed = claim(unrecorded, chains, mirrored)?;
    for &(i, row) in &claimed {
        applied_by_chain[i].insert(row.version, hex(&row.checksum));
    }
    Ok((applied_by_chain, claimed))
}

/// Each `_sqlx_migrations` row with the index of the one mirrored chain that
/// has its version, checksum checked and a failed row refused, as sqlx's
/// runner does.
fn claim<'r>(
    rows: impl IntoIterator<Item = &'r LegacyRow>,
    chains: &[Chain],
    mirrored: &HashSet<&str>,
) -> Result<Vec<(usize, &'r LegacyRow)>, Error> {
    let mut claimed = Vec::new();
    for row in rows {
        let version = row.version;
        let mut claimants = chains
            .iter()
            .enumerate()
            .filter(|(_, c)| mirrored.contains(c.name.as_str()) && c.get(version).is_some());
        let (i, chain) = claimants.next().ok_or(Error::Unclaimed { version })?;
        if let Some((_, other)) = claimants.next() {
            return Err(Error::Ambiguous {
                version,
                chain: chain.name.clone(),
                other: other.name.clone(),
            });
        }
        if !row.success {
            return Err(chain.error(MigrateError::Dirty(version)));
        }
        if *chain.get(version).expect("claimed").checksum != *row.checksum {
            return Err(chain.error(MigrateError::VersionMismatch(version)));
        }
        claimed.push((i, row));
    }
    Ok(claimed)
}

fn check_registered(registered: &BTreeMap<String, bool>, chains: &[Chain]) -> Result<(), Error> {
    if let Some(name) = registered
        .keys()
        .find(|name| !chains.iter().any(|c| &c.name == *name))
    {
        return Err(Error::UnknownChain(name.clone()));
    }
    match chains
        .iter()
        .find(|c| c.mirrored && registered.get(&c.name) == Some(&false))
    {
        Some(chain) => Err(Error::MirroredTooLate(chain.name.clone())),
        None => Ok(()),
    }
}

/// Refuse a pending migration of a mirrored chain whose version another
/// mirrored chain has applied or will write, given the applied ones' owners.
fn check_collisions<'c>(
    pending: &[(&'c Chain, &Migration)],
    mirrored: &HashSet<&str>,
    mut owners: HashMap<i64, &'c str>,
) -> Result<(), Error> {
    for (chain, m) in pending
        .iter()
        .filter(|(c, _)| mirrored.contains(c.name.as_str()))
    {
        if let Some(other) = owners.insert(m.version, &chain.name) {
            return Err(Error::Collision {
                version: m.version,
                chain: chain.name.clone(),
                other: other.to_string(),
            });
        }
    }
    Ok(())
}

/// A row of `PRAGMA foreign_key_check`, reported as the error SQLite raises
/// for an immediate foreign key.
#[derive(Debug, PartialEq)]
struct Dangling {
    table: String,
    rowid: Option<i64>,
    parent: String,
    fkid: i64,
}

impl std::fmt::Display for Dangling {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "FOREIGN KEY constraint failed: a {} row references a missing {} row",
            self.table, self.parent
        )
    }
}

impl std::error::Error for Dangling {}

impl DatabaseError for Dangling {
    fn message(&self) -> &str {
        "FOREIGN KEY constraint failed"
    }

    fn code(&self) -> Option<Cow<'_, str>> {
        Some("787".into())
    }

    fn as_error(&self) -> &(dyn std::error::Error + Send + Sync + 'static) {
        self
    }

    fn as_error_mut(&mut self) -> &mut (dyn std::error::Error + Send + Sync + 'static) {
        self
    }

    fn into_error(self: Box<Self>) -> Box<dyn std::error::Error + Send + Sync + 'static> {
        self
    }

    fn kind(&self) -> ErrorKind {
        ErrorKind::ForeignKeyViolation
    }
}

async fn dangling(conn: &mut SqliteConnection) -> Result<Vec<Dangling>, Error> {
    let rows: Vec<(String, Option<i64>, String, i64)> = sqlx::query_as("PRAGMA foreign_key_check")
        .fetch_all(conn)
        .await?;
    Ok(rows
        .into_iter()
        .map(|(table, rowid, parent, fkid)| Dangling {
            table,
            rowid,
            parent,
            fkid,
        })
        .collect())
}

async fn record(
    conn: &mut SqliteConnection,
    chain: &Chain,
    version: i64,
    description: &str,
    checksum: &str,
    installed_on: &str,
) -> Result<(), Error> {
    sqlx::query(&format!(
        "INSERT INTO {} (version, description, checksum, installed_on) VALUES (?, ?, ?, ?)",
        chain.table()
    ))
    .bind(version)
    .bind(description)
    .bind(checksum)
    .bind(installed_on)
    .execute(conn)
    .await?;
    Ok(())
}

fn check_applied(chain: &Chain, applied: &Applied) -> Result<(), Error> {
    for (&version, checksum) in applied {
        let source = match chain.get(version) {
            None => MigrateError::VersionMissing(version),
            Some(m) if hex(&m.checksum) != *checksum => MigrateError::VersionMismatch(version),
            Some(_) => continue,
        };
        return Err(chain.error(source));
    }
    Ok(())
}

/// Empty when the chain's table does not exist.
async fn applied(conn: &mut SqliteConnection, chain: &Chain) -> Result<Applied, Error> {
    if !table_exists(conn, &chain.table()).await? {
        return Ok(Applied::new());
    }
    let rows: Vec<(i64, String)> =
        sqlx::query_as(&format!("SELECT version, checksum FROM {}", chain.table()))
            .fetch_all(conn)
            .await?;
    Ok(rows.into_iter().collect())
}

/// `None` before the registry exists.
async fn registered(conn: &mut SqliteConnection) -> Result<Option<BTreeMap<String, bool>>, Error> {
    if !table_exists(conn, REGISTRY).await? {
        return Ok(None);
    }
    let rows: Vec<(String, bool)> =
        sqlx::query_as(&format!("SELECT name, mirrored FROM {REGISTRY}"))
            .fetch_all(conn)
            .await?;
    Ok(Some(rows.into_iter().collect()))
}

async fn legacy_rows(conn: &mut SqliteConnection) -> Result<Vec<LegacyRow>, Error> {
    if !table_exists(conn, LEGACY).await? {
        return Ok(Vec::new());
    }
    let rows: Vec<(i64, String, String, Vec<u8>, bool)> = sqlx::query_as(&format!(
        "SELECT version, description, CAST(installed_on AS TEXT), checksum, success \
         FROM {LEGACY} ORDER BY version"
    ))
    .fetch_all(conn)
    .await?;
    Ok(rows
        .into_iter()
        .map(
            |(version, description, installed_on, checksum, success)| LegacyRow {
                version,
                description,
                installed_on,
                checksum,
                success,
            },
        )
        .collect())
}

async fn table_exists(conn: &mut SqliteConnection, name: &str) -> Result<bool, Error> {
    let count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?")
            .bind(name)
            .fetch_one(conn)
            .await?;
    Ok(count > 0)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;

    use sqlx::migrate::MigrationType;
    use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};

    use super::*;

    fn app(migrations: &[(i64, &str)]) -> Chain {
        Chain {
            name: "app".into(),
            migrations: migrations
                .iter()
                .map(|&(version, sql)| {
                    Migration::new(
                        version,
                        Cow::Owned(format!("migration {version}")),
                        MigrationType::Simple,
                        Cow::Owned(sql.to_string()),
                        false,
                    )
                })
                .collect(),
            mirrored: false,
        }
    }

    const PARENTS_AND_CHILDREN: &str = "CREATE TABLE parents (id INTEGER PRIMARY KEY);
         CREATE TABLE children (id INTEGER PRIMARY KEY, parent INTEGER REFERENCES parents (id));";

    /// One connection, so the next query runs on the one that migrated.
    async fn one_connection() -> SqlitePool {
        let opts = SqliteConnectOptions::new()
            .in_memory(true)
            .foreign_keys(true);
        SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(opts)
            .await
            .unwrap()
    }

    async fn enforces_foreign_keys(pool: &SqlitePool) -> bool {
        sqlx::query("INSERT INTO children (parent) VALUES (9)")
            .execute(pool)
            .await
            .is_err()
    }

    #[tokio::test]
    async fn the_pool_enforces_foreign_keys_after_a_successful_run() {
        let pool = one_connection().await;
        apply(&pool, &[app(&[(1, PARENTS_AND_CHILDREN)])])
            .await
            .expect("applies");
        assert!(enforces_foreign_keys(&pool).await);
    }

    #[tokio::test]
    async fn the_pool_enforces_foreign_keys_after_a_failed_run() {
        let pool = one_connection().await;
        apply(&pool, &[app(&[(1, PARENTS_AND_CHILDREN)])])
            .await
            .expect("applies");
        let failed = apply(
            &pool,
            &[app(&[
                (1, PARENTS_AND_CHILDREN),
                (2, "INSERT INTO children (parent) VALUES (9)"),
            ])],
        )
        .await;
        assert!(
            matches!(
                &failed,
                Err(Error::Migrate {
                    source: MigrateError::ExecuteMigration(_, 2),
                    ..
                })
            ),
            "{failed:?}"
        );
        assert!(enforces_foreign_keys(&pool).await);
    }
}
