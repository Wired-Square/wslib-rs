# Changelog

## 0.1.0

Moved from `appliance-store` 0.17.1 in wslib-appliance-rs; what differs:

- `stamp` and `now` are `wslib-db-sqlite`'s, and a revocation or
  `replace_accounts` ends sessions through `wslib-auth`'s
  `SqliteSessionStore::remove_user_in` in the same transaction as the write.
  `replace_accounts` takes `&self`.
- Opened through `wslib-db-sqlite`'s `Database`, with the platform's and the
  product's migrations as two chains, `platform` and `app`. The database gains
  `_migration_chains` and `platform_migrations`, and `app_migrations` once an
  app chain is passed; `_migration_chains` and `app_migrations` are reserved
  names. Both chains are mirrored into `_sqlx_migrations`, so
  `appliance-store` 0.17.1 still opens a database this crate has migrated and
  refuses a newer one. A database 0.17.1 made is imported from
  `_sqlx_migrations` at the first `open`; `open_existing` never imports.
- Every pending migration applies in one transaction, and the write lock is
  held for the whole upgrade: the import, 0007 where it is pending, and every
  pending app migration, in one `BEGIN IMMEDIATE`.
- A database whose `app` chain is registered (once imported or created by this
  crate), opened without one, is refused as `StoreError::Database`
  (`UnknownChain`), where 0.17.1 answered `Migrate(VersionMissing)`. Before the
  import it is still `Migrate(VersionMissing)`, as is an applied app version
  this build lacks, before or after.
- A pending `-- no-transaction` migration is refused as
  `StoreError::Database` (`NoTransaction`).
- `open_existing` refuses a `success = 0` row before the import as
  `Migrate(Dirty)`, and a modified applied migration as
  `Migrate(VersionMismatch)`, before and after the import.
- `StoreError::Database` is new: what `wslib-db-sqlite` refuses beyond the
  existing variants.
- Settings are `wslib-db-sqlite`'s `Settings`, with local state under `box.`.
  `secret_in`, `set_secret_in`, `clear_secret_in` and
  `replace_exportable_settings` take `&self`. `replace_exportable_settings`
  stamps each row as it writes it, not all with one instant, and logs a
  carried reserved key as "an import carried a key in a reserved namespace;
  it was not applied" (was "a backup carried …").
- `close` warns "closing the database with connections open" (was "closing
  the store with database connections open"). The warnings about the file,
  closing, documents and imports log under `wslib_db_sqlite`'s targets.
