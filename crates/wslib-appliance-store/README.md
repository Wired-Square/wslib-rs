# wslib-appliance-store

An appliance's database: the tables every appliance has, in one SQLite file
a product's own tables share, so one backup, one file permission and one
transaction cover both.

```rust
use wslib_appliance_store::{Store, sqlx};

let store = Store::open(&boot.db, Some(sqlx::migrate!("./migrations"))).await?;
let admin = store.create_user("admin", &phc_hash, Role::Admin).await?;
store.set_setting("branding.app_name", "Widgets").await?;

let mut tx = store.begin().await?;
sqlx::query("INSERT INTO widgets (name, owner) VALUES (?, ?)")
    .bind("a widget")
    .bind(&admin.id)
    .execute(&mut *tx)
    .await?;
tx.commit().await?;
```

`sqlx` is re-exported for queries, but `sqlx::migrate!` expands to
`::sqlx::…`, which resolves only against a crate the product names itself. A
product with migrations declares sqlx in its own manifest, at this crate's
requirement:

```toml
sqlx = { version = "0.8.5", default-features = false, features = ["macros", "migrate", "runtime-tokio", "sqlite"] }
```

## Opening and migrating

`open` opens in WAL, owner-only, and migrates; `open_existing` neither creates
nor migrates. `begin` is `BEGIN IMMEDIATE` with foreign keys checked at the
commit, and `close` leaves no `-wal` or `-shm` once no connection, in this
process or another, has the database open.

The platform's migrations are numbered below `APP_FLOOR` (1000) and a
product's from it; a product migration numbered below it is refused at open.
Pass `open` `None` until the product has a schema of its own. The two are
`wslib-db-sqlite` chains, applied in one transaction and mirrored into
`_sqlx_migrations`, so a build on sqlx's own runner still opens the
database. The platform's `.sql` files are frozen byte for byte, and its
table and index names are reserved (the crate doc lists them); later
platform objects are named `platform_…`. Once a database is
imported the chains are the record, so a test that fakes an older database by
deleting `_sqlx_migrations` rows must drop `_migration_chains`,
`_platform_migrations` and `_app_migrations` too.

## The tables

- **Accounts**, created from an argon2id hash; the store never sees a
  password. A password change and a disable move `sessions_valid_from` and
  end the account's sessions in the same transaction. The last enabled host
  admin cannot be demoted, disabled or deleted. `set_password` is an
  administrator's reset, blind to who asks; a change that verified the
  current password first writes with `set_password_if_unchanged`, so it
  cannot land over a reset that overtook it.
- **Per-app roles** for a host running several apps: `set_app_role`,
  `app_roles` and `role_in_app`, a host admin being Admin in every app.
- **Second factors**: TOTP, recovery code hashes, passkeys, and a requirement
  to enrol TOTP. Steps and counters are written compare-and-swap.
- **Settings**, in three families by what may leave the box:
  `setting`/`set_setting` is configuration and travels in a backup;
  `secret` and its siblings never leave; `box_state` and its siblings are
  this box's own state (when a task last ran), which a backup skips and a
  restore neither deletes nor writes. `settings_changed()` changes after each
  `set_setting`, so a loop holding a setting waits on it and reads again;
  configuration kept in a product's own tables calls `settings_replaced()`
  once its write commits.
- **Audit**, cursor-paged and swept; **trusted** certificates and authorities;
  **asserted callers'** roles.
- **Sessions**: `platform_sessions`, `wslib-auth`'s table.

A restore replaces accounts, settings and trust in one transaction with the
`replace_*` calls; a factory reset empties every platform table with
`erase_platform`.
