# Changelog

## 0.1.0

- Moved from `appliance-store` 0.17.1 in wslib-appliance-rs, with the same
  tables, migrations, behaviour and error messages. `stamp` and `now` are now
  `wslib-db-sqlite`'s, and a revocation or `replace_accounts` ends sessions
  through `wslib-auth`'s `SqliteSessionStore::remove_user_in` in the same
  transaction as the write. `replace_accounts` takes `&self`.
