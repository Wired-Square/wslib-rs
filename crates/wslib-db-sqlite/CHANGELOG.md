# Changelog

## 0.2.2

- `Database::open`, `open_existing` and `open_in_memory` return `Send`
  futures, so they can be spawned or boxed.

## 0.2.1

- Migrations run with foreign keys off, so a rebuild of a referenced table
  commits, and a reference one leaves dangling fails that migration.

## 0.2.0

- While a chain is mirrored, every open adopts the `_sqlx_migrations` rows
  an older build wrote after a rollback, and refuses one no mirrored chain
  has (`Unclaimed`); `open_existing` agrees. `Collision::other` is now a
  `String`.
- A reference a migration leaves dangling fails that migration
  (`ExecuteMigration`, a foreign-key violation), not the commit.
- Breaking: chain tables are `_<name>_migrations`, under the reserved
  prefix. A chain whose table would be the crate's own is `ReservedChain`.
- A test pins the file, `-wal` and `-shm` as owner-only on every platform,
  Windows included.

## 0.1.0

- `Database`: `open` (creating, migrating), `open_existing` (neither, and
  refusing a database behind or ahead of a chain), `open_in_memory`, `begin`
  (`BEGIN IMMEDIATE`, foreign keys checked at the commit), `close`, `pool`
  and `chain_version`. On open, WAL is entered on a connection of its own,
  synchronous is `NORMAL`, foreign keys are on, the busy timeout is five
  seconds, and the file, `-wal` and `-shm` are restricted to their owner.
- `Error`, and `stamp`: `format`, `now`, `parse` and `from_row`, fixed-width
  RFC 3339 in UTC that sorts as text. `sqlx` is re-exported.
- `Chain`: a named sqlx `Migrator`, recorded in `<name>_migrations` and
  registered in `_migration_chains`. Every pending migration of every chain
  applies in one transaction; a pending `-- no-transaction` migration, a
  modified applied one, an applied version a chain lacks and a registered
  chain the open isn't given are refused.
- `Chain::mirrored` also records a chain in `_sqlx_migrations`, so an older
  build on sqlx's runner runs on a schema it knows and refuses a newer one;
  a version that would collide there refuses the open.
- A database from sqlx's own runner is imported from `_sqlx_migrations`
  once, in the same transaction, row by row to the chain that has the
  version, and its chains are mirrored. Until then `open_existing` verifies
  against `_sqlx_migrations` without writing.
- `Error::unreadable` builds `Unreadable` for a wrapper's own rows.
- `Settings`: a key/value table the app creates, with secrets
  (`secret.`, through `wslib-secret`) and local state (`local.`, or a prefix
  of the app's) refused by the plain calls, never exported and never
  replaced by `replace_exportable`. Documents as JSON, `init_secret`,
  `secret_names`, the `_in` calls on a transaction, and `changed`/`replaced`.
