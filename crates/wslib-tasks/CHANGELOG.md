# Changelog

## 0.1.0

- `TaskTable<K, T>`: one task per row of a desired set, keyed by `K` and
  restarted when its `T` changes or its task has ended. A row's old task ends
  before its replacement starts.
- `run` reconciles at once, on `notify`, and every 60 s otherwise, and stops
  and waits for every task when its token is cancelled; `reconcile` is one
  pass, returning `Reconciled` counts.
