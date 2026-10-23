//! Migration chains, applied together in one transaction.
//!
//! A [`Chain`] is a name and an sqlx `Migrator`, usually an app's own
//! `sqlx::migrate!("./migrations")`, and each records what it has applied in
//! its own table, `<name>_migrations`. Versions are the chain's own: two chains
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
//! the import, and the registry keeps that from then on. A version
//! `_sqlx_migrations` already holds, or that two mirrored chains would both
//! write, refuses the open before anything applies ([`Error::Collision`]).
//!
//! **The import** runs once, on the open that creates the registry, if
//! `_sqlx_migrations` has rows then: each row goes to the chain that has its
//! version, with its checksum checked, inside the same transaction. A row no
//! chain has ([`Error::Unclaimed`]) or two chains have ([`Error::Ambiguous`])
//! refuses the open. Before then,
//! [`Database::open_existing`](crate::Database::open_existing) verifies against
//! `_sqlx_migrations` by the same rules, and writes nothing.
//!
//! The tables this module keeps, `<name>_migrations`, `_migration_chains` and
//! `_sqlx_migrations`, are not an app's to create, alter or drop.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::time::Instant;

use sqlx::SqliteConnection;
use sqlx::migrate::{MigrateError, Migration, Migrator};
use sqlx::sqlite::SqlitePool;

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
        format!("{}_migrations", self.name)
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
}

pub(crate) fn check_names(chains: &[Chain]) -> Result<(), Error> {
    for (i, chain) in chains.iter().enumerate() {
        if !is_plain_name(&chain.name) {
            return Err(Error::InvalidName(chain.name.clone()));
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
    let applied_by_chain = match registered(conn).await? {
        Some(registered) => {
            check_registered(&registered, chains)?;
            let mut applied_by_chain = Vec::new();
            for chain in chains {
                applied_by_chain.push(applied(conn, chain).await?);
            }
            applied_by_chain
        }
        None => {
            let mut applied_by_chain = vec![Applied::new(); chains.len()];
            for (i, row) in claim(&legacy_rows(conn).await?, chains)? {
                applied_by_chain[i].insert(row.version, hex(&row.checksum));
            }
            applied_by_chain
        }
    };
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
    let mut tx = crate::begin(pool).await?;
    let conn = &mut *tx;

    let (mut registered, to_import) = match registered(conn).await? {
        Some(registered) => {
            check_registered(&registered, chains)?;
            (registered, Vec::new())
        }
        None => {
            sqlx::query(&format!(
                "CREATE TABLE {REGISTRY} (
                    name       TEXT PRIMARY KEY,
                    mirrored   BOOLEAN NOT NULL,
                    created_on TEXT NOT NULL
                )"
            ))
            .execute(&mut *conn)
            .await?;
            (BTreeMap::new(), legacy_rows(conn).await?)
        }
    };
    for chain in chains {
        if registered.contains_key(&chain.name) {
            continue;
        }
        let mirrored = chain.mirrored || !to_import.is_empty();
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
        .bind(mirrored)
        .bind(stamp::format(stamp::now()))
        .execute(&mut *conn)
        .await?;
        registered.insert(chain.name.clone(), mirrored);
    }
    for (i, row) in claim(&to_import, chains)? {
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

    let mirrored: HashSet<&str> = chains
        .iter()
        .map(|c| c.name.as_str())
        .filter(|name| registered[*name])
        .collect();
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

    let mut owners = HashMap::new();
    let mut pending = Vec::new();
    for chain in chains {
        let applied = applied(conn, chain).await?;
        check_applied(chain, &applied)?;
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
    check_collisions(conn, &pending, &mirrored, &owners).await?;

    for (chain, m) in pending {
        let started = Instant::now();
        sqlx::raw_sql(&m.sql)
            .execute(&mut *conn)
            .await
            .map_err(|e| chain.error(MigrateError::ExecuteMigration(e, m.version)))?;
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

/// Each `_sqlx_migrations` row with the index of the one chain that has its
/// version, checksum checked.
fn claim<'r>(
    rows: &'r [LegacyRow],
    chains: &[Chain],
) -> Result<Vec<(usize, &'r LegacyRow)>, Error> {
    let mut claimed = Vec::new();
    for row in rows {
        let version = row.version;
        let mut claimants = chains
            .iter()
            .enumerate()
            .filter(|(_, c)| c.get(version).is_some());
        let (i, chain) = claimants.next().ok_or(Error::Unclaimed { version })?;
        if let Some((_, other)) = claimants.next() {
            return Err(Error::Ambiguous {
                version,
                chain: chain.name.clone(),
                other: other.name.clone(),
            });
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

/// Refuse a pending migration of a mirrored chain whose version
/// `_sqlx_migrations` holds, or another mirrored chain will write.
async fn check_collisions(
    conn: &mut SqliteConnection,
    pending: &[(&Chain, &Migration)],
    mirrored: &HashSet<&str>,
    owners: &HashMap<i64, &str>,
) -> Result<(), Error> {
    if mirrored.is_empty() {
        return Ok(());
    }
    let legacy: HashSet<i64> = sqlx::query_scalar(&format!("SELECT version FROM {LEGACY}"))
        .fetch_all(conn)
        .await?
        .into_iter()
        .collect();
    let mut writing = HashMap::new();
    for (chain, m) in pending
        .iter()
        .filter(|(c, _)| mirrored.contains(c.name.as_str()))
    {
        let other = if legacy.contains(&m.version) {
            Some(owners.get(&m.version).map(|o| o.to_string()))
        } else {
            writing
                .insert(m.version, chain.name.as_str())
                .map(|o| Some(o.to_string()))
        };
        if let Some(other) = other {
            return Err(Error::Collision {
                version: m.version,
                chain: chain.name.clone(),
                other,
            });
        }
    }
    Ok(())
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
    let rows: Vec<(i64, String, String, Vec<u8>)> = sqlx::query_as(&format!(
        "SELECT version, description, CAST(installed_on AS TEXT), checksum \
         FROM {LEGACY} ORDER BY version"
    ))
    .fetch_all(conn)
    .await?;
    Ok(rows
        .into_iter()
        .map(|(version, description, installed_on, checksum)| LegacyRow {
            version,
            description,
            installed_on,
            checksum,
        })
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
