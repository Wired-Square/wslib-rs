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
  `NoDatabase`, a chain not fully applied is `SchemaBehind`, and an applied
  migration a chain lacks or has modified is `Migrate`.
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
its own table `<name>_migrations` (`version`, `description`, `checksum` in
hex, `installed_on`). Versions are each chain's own, from anywhere.

- Every pending migration of every chain applies in **one transaction**, in
  the order the chains are given: a failure anywhere leaves the database as
  it was. A pending migration marked `-- no-transaction` is refused.
- A modified applied migration is refused, and so is an applied version its
  chain no longer has, naming the chain and version.
- **Moving off sqlx's runner.** If `_sqlx_migrations` exists and a chain's
  table does not, its rows are imported in the same transaction, each to the
  chain whose `Migrator` has its version, checksum checked. A row no chain
  has is `Unclaimed`, one two chains have is `Ambiguous`.
- Every chain whose table the first import makes is recorded in
  `_imported_chains`, even one with no rows yet, and each migration it
  applies afterwards is also written to `_sqlx_migrations`, so a build still
  on sqlx's runner refuses the newer schema with `VersionMissing`. A version
  that table already holds, or that two imported chains would both write, is
  a `Collision` before anything applies. A chain first seen later never
  touches `_sqlx_migrations` and may number from anywhere.

`<name>_migrations`, `_imported_chains` and `_sqlx_migrations` are the
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
