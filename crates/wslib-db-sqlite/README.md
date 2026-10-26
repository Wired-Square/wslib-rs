# wslib-db-sqlite

One SQLite database for an app: opened in WAL and restricted to its owner,
write transactions that take the lock up front, migration chains applied
together in one transaction, and a settings table whose secrets and local
state never leave in an export.

```rust
use wslib_db_sqlite::{Chain, Database, Settings};

static APP: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

let db = Database::open(state_dir.join("app.db"), &[Chain::new("app", &APP)]).await?;
let mut tx = db.begin().await?;
sqlx::query("INSERT INTO widgets (name) VALUES (?)").bind(name).execute(&mut *tx).await?;
tx.commit().await?;

let settings = Settings::new(&db);
settings.set_setting("branding.app_name", "Widgets").await?;
let key = settings.init_secret("signing_key", &generated).await?;
settings.set_local("backup.last_run", &wslib_db_sqlite::stamp::format(now)).await?;

// In a helper process beside the service, which must not migrate:
let db = Database::open_existing(path, &[Chain::new("app", &APP)]).await?;
db.close().await;
```

Queries use sqlx's runtime API (`sqlx::query`), never the `query!` macros.
The crate re-exports `sqlx`, but `sqlx::migrate!` needs `sqlx` in the app's
own manifest, pinned to the same version as this crate's.

## Opening

- `open` creates the file if absent and applies every pending migration.
  `open_existing` creates nothing and migrates nothing: no file is
  `NoDatabase`, a chain not fully applied is `SchemaBehind`, an applied
  migration a chain lacks or has modified is `Migrate`, and a registered
  chain not given is `UnknownChain`.
- WAL is entered once on its own connection, then a pool of five with
  synchronous `NORMAL`, foreign keys on and a five-second busy timeout. The
  file, `-wal` and `-shm` are made owner-only on every open; on Windows they
  inherit the directory's ACL, so keep the directory private.
- `begin` is `BEGIN IMMEDIATE` with `PRAGMA defer_foreign_keys = ON`: a
  transaction that reads before writing waits through the busy timeout, and
  a foreign-key violation, `ON DELETE RESTRICT` included, fails the commit
  rather than the statement.
- `close` waits up to five seconds for checked-out connections, then closes
  one connection alone so `-wal` and `-shm` are removed.
- `open_in_memory` is one connection, for tests: a pool query while a
  `begin` is held waits for it.
- `chain_version(name)` is the newest version of a chain, for stamping a
  backup.
- Store instants with `stamp::format`, read them with `stamp::parse` or
  `stamp::from_row`, and take the time with `stamp::now`.

## Migration chains

A `Chain` is a name (`[a-z][a-z0-9_]*`) and an sqlx `Migrator`, recorded in
its own table `_<name>_migrations` (`version`, `description`, `checksum` in
hex, `installed_on`) and registered in `_migration_chains` (`name`,
`mirrored`, `created_on`) when that table is made. Versions are each chain's
own, from anywhere. A chain named `sqlx`, whose table would be
`_sqlx_migrations`, is `ReservedChain`.

- Every pending migration of every chain applies in **one transaction**, in
  the order the chains are given: a failure anywhere leaves the database as
  it was. A pending migration marked `-- no-transaction` is refused.
- Foreign keys are deferred as in `begin`, but a reference a migration
  leaves dangling fails that migration, as under sqlx's runner: an
  `ExecuteMigration` with a foreign-key violation, naming its version. One
  dangling before the open is not blamed.
- A modified applied migration is refused, and so is an applied version its
  chain no longer has, naming the chain and version. A registered chain the
  open isn't given is `UnknownChain`, from `open` and `open_existing` alike.
- **Mirrored chains** also write each migration they apply to
  `_sqlx_migrations`, in sqlx's own table and columns. A chain is mirrored if
  it asks (`Chain::new(..).mirrored()`) or if the import made it; the
  registry keeps that for good: asking later is `MirroredTooLate`, and a
  mirrored chain stays mirrored without asking. Mirrored chains share one
  version space, as sqlx's runner has only one, even on a fresh database:
  a version that two mirrored chains would both write is a `Collision`
  before anything applies.
- **The import from sqlx's runner** happens on the open that creates the
  registry, if `_sqlx_migrations` has rows, and every chain made then is
  mirrored, even one with no rows yet. While any chain is mirrored it
  happens again on every open, so a migration an older build applied after
  a rollback is adopted, not run again. Each row no mirrored chain has
  recorded goes to the mirrored chain whose `Migrator` has its version,
  checksum checked, in the same transaction. A row no mirrored chain has is
  `Unclaimed`, as sqlx's runner refuses a version it lacks; one two have is
  `Ambiguous`; a failed one is `Dirty`. With no chain mirrored,
  `_sqlx_migrations` is ignored.
- `open_existing` checks by the same rules and writes nothing: current by
  sqlx's rules is current, a missing migration is `SchemaBehind`.

**What an older build on sqlx's runner does**, given the same chains
concatenated:

- On an imported database, or a fresh one whose chains are all mirrored, it
  finds every version it knows and runs; once a newer migration has
  applied, it refuses with `VersionMissing`.
- On a fresh database with chains not mirrored there is no
  `_sqlx_migrations`, so it tries to apply its first migration over the
  existing schema and fails, usually on a table that already exists,
  leaving an empty `_sqlx_migrations` this crate then ignores. Mirror
  the chains of a product whose installs might be rolled back to such a
  build.

`_<name>_migrations`, `_migration_chains` and `_sqlx_migrations` are the
crate's; an app's migrations leave them alone.

## Settings

`Settings::new(&db)` uses the table `settings` with local state under
`local.`; `table(name)` and `local_prefix(prefix)` change them. The app's own
migration creates the table:

```sql
CREATE TABLE settings (
    key        TEXT PRIMARY KEY NOT NULL,
    value      TEXT NOT NULL,
    updated_at TEXT NOT NULL
) STRICT;
```

- `setting`, `set_setting` and their `_doc` (JSON) forms for configuration.
  A document absent or unparseable reads as `T::default()`, the second with
  a warning.
- `secret`, `set_secret`, `clear_secret`, `init_secret` (one writer wins and
  every caller gets its value), `secret_names(prefix)`, and `secret_in`,
  `set_secret_in`, `clear_secret_in` on a transaction, by the bare name;
  stored as `secret.<name>`.
- `local`, `set_local`, `clear_local` and their `_doc` forms, by the bare name.
- The plain calls refuse a `secret.` or local key with `Reserved`.
- `exportable()` is every other setting. `replace_exportable(tx, rows)`
  replaces exactly those: secrets and local state are neither deleted nor
  written, and a carried reserved key is skipped with a warning.
- `changed()` sees each plain write through this `Settings` or a clone, and
  each `replaced()`; a secret or local write is not a change. Make one
  `Settings` and clone it.
