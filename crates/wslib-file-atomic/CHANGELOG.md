# Changelog

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
