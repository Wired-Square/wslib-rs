# Changelog

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
