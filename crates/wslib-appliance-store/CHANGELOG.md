# Changelog

## 0.1.3

- Migration 0008 adds `platform_session_secrets`, `wslib-auth`'s table of
  secrets bound to a session, which cascades from `platform_sessions`; a
  factory reset empties it. `SESSION_SECRETS_TABLE` names it. A build before
  this one refuses a database it has migrated.

## 0.1.2

- The README says why a product with migrations declares sqlx itself. No
  code change.

## 0.1.1

- Dependency floors: `wslib-secret` and `wslib-appliance-types` 0.1.1 (were
  0.1.0), and `uuid` 1.1 (was 1), the floors the rest of the family takes. No
  change to the API.

## 0.1.0

Moved from `appliance-store` 0.17.1 in wslib-appliance-rs; what differs:

- `stamp` and `now` are `wslib-db-sqlite`'s, and a revocation or
  `replace_accounts` ends sessions through `wslib-auth`'s
  `SqliteSessionStore::remove_user_in` in the same transaction as the write.
  `replace_accounts` takes `&self`, as `replace_exportable_settings` does
  below, so a restore needs the `Store` as well as its transaction.
- The store logs nothing itself: its warnings about the file, closing,
  documents and imports, once under `appliance_store`, come from
  `wslib_db_sqlite`'s targets, so a log capture filtering on `appliance_*` no
  longer sees them, and nothing fails.
- Opened through `wslib-db-sqlite`'s `Database`, with the platform's and the
  product's migrations as two chains, `platform` and `app`. The database gains
  `_migration_chains` and `_platform_migrations`, and `_app_migrations` once
  an app chain is passed; all three are reserved names. Both chains are
  mirrored into `_sqlx_migrations`, so `appliance-store` 0.17.1 still opens a
  database this crate has migrated and refuses a newer one. A database 0.17.1
  made is imported from `_sqlx_migrations` at the first `open`, and a
  migration 0.17.1 applies after a rollback is adopted at the next `open`, not
  run again; `open_existing` checks the same rows and writes nothing.
- Every pending migration applies in one transaction, and the write lock is
  held for the whole upgrade: the import, 0007 where it is pending, and every
  pending app migration, in one `BEGIN IMMEDIATE`.
- A database whose `app` chain is registered (once imported or created by this
  crate), opened without one, is refused as `StoreError::Database`
  (`UnknownChain`), where 0.17.1 answered `Migrate(VersionMissing)`. Before the
  import it is still `Migrate(VersionMissing)`, as is an applied app version
  this build lacks, before or after the import, including one 0.17.1 applied
  after a rollback.
- A pending `-- no-transaction` migration is refused as
  `StoreError::Database` (`NoTransaction`).
- Migrations run with foreign keys off and checked at the end of each one,
  where 0.17.1 enforced them per statement. A reference one leaves dangling
  is still that migration's `Migrate(ExecuteMigration)`, but a rebuild of a
  referenced table, which 0.17.1 refused, applies. `ON DELETE CASCADE` and
  the other actions do not fire inside a migration, where under 0.17.1 they
  did.
- `open_existing` refuses a `success = 0` row of a version this build has as
  `Migrate(Dirty)`, and a modified applied migration as
  `Migrate(VersionMismatch)`, before and after the import.
- `open_existing` checks the `_sqlx_migrations` rows no chain has recorded
  (before the import, or 0.17.1's after a rollback) before anything pending:
  `VersionMissing`, `Dirty` or `VersionMismatch` comes before `SchemaBehind`,
  where 0.17.1 answered `SchemaBehind` first.
- `StoreError::Database` is new: what `wslib-db-sqlite` refuses beyond the
  existing variants.
- Settings are `wslib-db-sqlite`'s `Settings`, with local state under `box.`.
  `secret_in`, `set_secret_in`, `clear_secret_in` and
  `replace_exportable_settings` take `&self`. `replace_exportable_settings`
  stamps each row as it writes it, not all with one instant, and logs a
  carried reserved key as "an import carried a key in a reserved namespace;
  it was not applied" (was "a backup carried …").
- `close` warns "closing the database with connections open" (was "closing
  the store with database connections open").
