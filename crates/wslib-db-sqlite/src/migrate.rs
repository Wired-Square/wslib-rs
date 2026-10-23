//! Migration chains, applied together in one transaction.
//!
//! A [`Chain`] is a name and an sqlx `Migrator`, usually an app's own
//! `sqlx::migrate!("./migrations")`, and each records what it has applied in
//! its own table, `<name>_migrations`. Versions are the chain's own: two chains
//! may both start at 1.
//!
//! [`Database::open`](crate::Database::open) applies every pending migration of
//! every chain, in the order the chains are given and each chain's own order,
//! in **one transaction**: a failure anywhere leaves the database as it was,
//! earlier chains included. A migration marked `-- no-transaction` cannot join
//! it and is refused. A modified applied migration is refused, and so is an
//! applied version its chain no longer has. A migration added to an earlier
//! chain after a later one applied simply applies at the next open.
//!
//! # Moving off sqlx's own runner
//!
//! sqlx's runner records one chain in `_sqlx_migrations`. When that table
//! exists and a chain's table does not, its rows are imported, inside the same
//! transaction: each to the chain that has its version, with its checksum
//! checked. A row no chain has ([`Error::Unclaimed`]) or two chains have
//! ([`Error::Ambiguous`]) refuses the open.
//!
//! Every chain whose table is made by the first import is *imported*, even
//! one that took no row, and from then on each migration it applies is also written to `_sqlx_migrations` in sqlx's own
//! columns, so an older build on sqlx's runner refuses the newer schema with
//! `VersionMissing`. A version that table already holds for another chain, or
//! that two imported chains would both write, refuses the open before anything
//! applies ([`Error::Collision`]). A chain first seen after that is never
//! imported, never touches `_sqlx_migrations`, and may number from anywhere.
//!
//! The tables this module keeps, `<name>_migrations`, `_imported_chains` and
//! `_sqlx_migrations`, are not an app's to create, alter or drop.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::time::Instant;

use sqlx::SqliteConnection;
use sqlx::migrate::{MigrateError, Migration, Migrator};
use sqlx::sqlite::SqlitePool;

use crate::{Error, is_plain_name, stamp};

const LEGACY: &str = "_sqlx_migrations";
const IMPORTED: &str = "_imported_chains";

/// A named migration chain; the name is `[a-z][a-z0-9_]*`, checked at open.
#[derive(Debug, Clone)]
pub struct Chain {
    name: String,
    migrations: Vec<Migration>,
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
        }
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
    for chain in chains {
        let applied = applied(&mut conn, chain).await?.unwrap_or_default();
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
        check_applied(chain, &applied)?;
    }
    Ok(())
}

pub(crate) async fn apply(pool: &SqlitePool, chains: &[Chain]) -> Result<(), Error> {
    let mut tx = crate::begin(pool).await?;
    let conn = &mut *tx;

    let mut imported = imported_chains(conn).await?;
    let mut fresh = Vec::new();
    for chain in chains {
        if !table_exists(conn, &chain.table()).await? {
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
            fresh.push(chain);
        }
    }
    if !fresh.is_empty() && table_exists(conn, LEGACY).await? {
        import(conn, chains, &fresh, &mut imported).await?;
    }

    let mut owners = HashMap::new();
    let mut pending = Vec::new();
    for chain in chains {
        let applied = applied(conn, chain).await?.unwrap_or_default();
        check_applied(chain, &applied)?;
        if imported.contains(&chain.name) {
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

    check_collisions(conn, &pending, &imported, &owners).await?;

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
        if imported.contains(&chain.name) {
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

/// Move `_sqlx_migrations`' rows into the `fresh` chains' tables, skipping
/// those an imported chain already holds. On the first import every fresh
/// chain becomes `imported`, so one with no rows yet still dual-writes later.
async fn import(
    conn: &mut SqliteConnection,
    chains: &[Chain],
    fresh: &[&Chain],
    imported: &mut HashSet<String>,
) -> Result<(), Error> {
    let mut accounted = HashSet::new();
    for chain in chains.iter().filter(|c| imported.contains(&c.name)) {
        accounted.extend(applied(conn, chain).await?.unwrap_or_default().into_keys());
    }
    let rows: Vec<(i64, String, String, Vec<u8>)> = sqlx::query_as(&format!(
        "SELECT version, description, CAST(installed_on AS TEXT), checksum \
         FROM {LEGACY} ORDER BY version"
    ))
    .fetch_all(&mut *conn)
    .await?;
    for (version, description, installed_on, checksum) in rows {
        if accounted.contains(&version) {
            continue;
        }
        let mut claimants = fresh.iter().filter(|c| c.get(version).is_some());
        let chain = claimants.next().ok_or(Error::Unclaimed { version })?;
        if let Some(other) = claimants.next() {
            return Err(Error::Ambiguous {
                version,
                chain: chain.name.clone(),
                other: other.name.clone(),
            });
        }
        if *chain.get(version).expect("claimed").checksum != *checksum {
            return Err(chain.error(MigrateError::VersionMismatch(version)));
        }
        let installed_on =
            chrono::NaiveDateTime::parse_from_str(&installed_on, "%Y-%m-%d %H:%M:%S").map_err(
                |e| Error::Unreadable {
                    table: LEGACY,
                    what: "installed_on",
                    because: e.to_string(),
                },
            )?;
        record(
            conn,
            chain,
            version,
            &description,
            &hex(&checksum),
            &stamp::format(installed_on.and_utc()),
        )
        .await?;
    }
    if table_exists(conn, IMPORTED).await? {
        return Ok(());
    }
    sqlx::query(&format!(
        "CREATE TABLE {IMPORTED} (
            name        TEXT PRIMARY KEY,
            imported_on TEXT NOT NULL
        )"
    ))
    .execute(&mut *conn)
    .await?;
    for name in fresh.iter().map(|c| c.name.clone()) {
        sqlx::query(&format!(
            "INSERT INTO {IMPORTED} (name, imported_on) VALUES (?, ?)"
        ))
        .bind(&name)
        .bind(stamp::format(stamp::now()))
        .execute(&mut *conn)
        .await?;
        imported.insert(name);
    }
    Ok(())
}

/// Refuse a pending migration of an imported chain whose version
/// `_sqlx_migrations` holds, or another imported chain will write.
async fn check_collisions(
    conn: &mut SqliteConnection,
    pending: &[(&Chain, &Migration)],
    imported: &HashSet<String>,
    owners: &HashMap<i64, &str>,
) -> Result<(), Error> {
    if imported.is_empty() {
        return Ok(());
    }
    let legacy: HashSet<i64> = sqlx::query_scalar(&format!("SELECT version FROM {LEGACY}"))
        .fetch_all(conn)
        .await?
        .into_iter()
        .collect();
    let mut writing = HashMap::new();
    for (chain, m) in pending.iter().filter(|(c, _)| imported.contains(&c.name)) {
        let other = if legacy.contains(&m.version) {
            Some(owners.get(&m.version).copied().unwrap_or("no chain"))
        } else {
            writing.insert(m.version, chain.name.as_str())
        };
        if let Some(other) = other {
            return Err(Error::Collision {
                version: m.version,
                chain: chain.name.clone(),
                other: other.to_string(),
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

/// `None` when the chain's table does not exist.
async fn applied(conn: &mut SqliteConnection, chain: &Chain) -> Result<Option<Applied>, Error> {
    if !table_exists(conn, &chain.table()).await? {
        return Ok(None);
    }
    let rows: Vec<(i64, String)> =
        sqlx::query_as(&format!("SELECT version, checksum FROM {}", chain.table()))
            .fetch_all(conn)
            .await?;
    Ok(Some(rows.into_iter().collect()))
}

async fn imported_chains(conn: &mut SqliteConnection) -> Result<HashSet<String>, Error> {
    if !table_exists(conn, IMPORTED).await? {
        return Ok(HashSet::new());
    }
    let names: Vec<String> = sqlx::query_scalar(&format!("SELECT name FROM {IMPORTED}"))
        .fetch_all(conn)
        .await?;
    Ok(names.into_iter().collect())
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
