# Changelog

## 0.1.0

- `write_private`, `replace_private` and `replace_readable`: whole-file writes
  staged as `<name>.new`, synced, renamed over the target, and the directory
  synced on Unix. `0600` or `0644` whatever the umask; on Windows a protected
  owner and SYSTEM DACL, or the directory's ACL.
- `Options` for the rest: `Readers`, create-new, create parents, the staging
  suffix; `write` takes bytes and `write_with` a closure on the `File`.
- `stage` gives a `Staged` to `promote` or `discard`; `promote(path, suffix)`
  finishes one a restart finds.
- A failed write removes the staged file, a failed rename included; a failed
  `Staged::promote` keeps it for a retry.
- `owner_only` restricts an existing file; `beside` names a staged one.
