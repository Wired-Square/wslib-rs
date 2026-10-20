# Changelog

## 0.1.2

- `Options::hidden_staging(true)` stages as `.<file>.<suffix>`, so
  `/data/options.json` stages as `/data/.options.json.new`; `staged_path`,
  `stage` and `write` follow it, and clear a stale staged file of that name
  first. Off by default; `Transaction` staged names are unchanged.
- `Options::promote_staged(path)` and `Options::discard_staged(path)` finish
  a staged file a restart finds, in whatever form the options name it.
- `Staged::target()` is the file it is renamed over.
- `PromoteError::Unmoved` no longer names the paths in its message, as
  `Unsynced` never did; a caller adds the path once.

## 0.1.1

- `Transaction`: several files, in any directories, replaced together or
  not at all, across a crash. `begin`, `stage` or `stage_with` per file with
  its own `Options`, then `commit`; `abort` or dropping it uncommitted rolls
  back. A `<name>.txn` record in one directory (`Transaction::record`),
  pending then committed, is the commit point; each file is staged beside its
  target as `<file>.<name>.txn`.
- `recover(dir, name)` finishes what a crash left: a pending transaction is
  rolled back and a committed one forward, as `Recovered` says.
- `commit` fails with `CommitError`: `RolledBack` before the commit point,
  `Committed` after it, with the record left for `recover`. It converts to
  an `io::Error` of the same kind.

## 0.1.0

- `write_private`, `replace_private` and `replace_readable`: whole-file writes
  staged as `<name>.new`, synced, renamed over the target, and the directory
  synced on Unix. `0600` or `0644` whatever the umask; on Windows a protected
  owner and SYSTEM DACL, or the directory's ACL.
- `Options` for the rest: `Readers`, create-new, create parents, the staging
  suffix; `write` takes bytes and `write_with` a closure on the `File`.
- `stage` gives a `Staged` to `promote` or `discard`; `promote(path, suffix)`
  and `discard(path, suffix)` finish one a restart finds, and
  `Options::staged_path` names it.
- A promote fails with `PromoteError`: `Unmoved` hands the `Staged` back,
  `Unsynced` means the file landed but its directory wasn't synced. It
  converts to an `io::Error` of the same kind.
- `promote_unsynced` and `sync_dir` let a caller renaming several files sync
  the directory once, after the last.
- A failed write removes the staged file, a failed rename included. A failed
  directory sync removes nothing, and a directory that can't be opened to
  sync (`PermissionDenied`) is skipped.
- `owner_only` restricts an existing file; `beside` names a staged one.
