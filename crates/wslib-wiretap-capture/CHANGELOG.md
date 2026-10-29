# Changelog

## 0.1.0

- Behind the `sqlite` feature: `Store`, async over `wslib-db-sqlite`, with
  frames, bytes, metadata, events, inventory, search, `payloads` by
  `Sampling`, `read_rows` with a `Cancel`, the plain `rows`, and copy, delete
  and sweep; `chain()`, the schema as one migration; `tuning()`; and
  `upgrade_legacy`, the frozen ladder for files written before the chain.
  `Store::open` runs both, stamps `user_version` 6 and returns the legacy
  steps it applied; `Store::open_copy` opens a copy of a file. `sqlx` is
  re-exported.
- `Sql`, `SqlValue`, `FrameRowFilter` (with `sql_where_named` for any stored
  protocol name) and `CaptureProtocol`, and the event row types, with the
  serde shapes and TS declarations they had before the move.
