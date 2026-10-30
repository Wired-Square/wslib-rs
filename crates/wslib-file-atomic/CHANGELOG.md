# Changelog

## 0.1.9

- libc's floor is 0.2.183, the workspace's.

## 0.1.8

- On Windows, a roll-back leaves a junction or directory symlink found at a
  staged path, as it does a directory, rather than failing on it.

## 0.1.7

- A transaction's roll-back, and `recover`'s, leave a directory found at a
  staged path rather than failing on it, so a failed stage no longer strands
  a pending record.

## 0.1.6

- `keep_mode(dir, mode)`: sets `dir`'s permission bits to `mode` only when
  they differ, and returns the bits it replaced, so the caller can log the
  change. A no-op off Unix.

## 0.1.5

- `Refused`: the source a refusal by `recover`, `recover_expecting` or
  `recover_identified` carries inside its `PermissionDenied`, with the
  `path()` of the record or staged file refused, so a caller tells a refusal
  from a failed rename by downcasting rather than by the error's kind.

## 0.1.4

- `recover` refuses a record this process could not have written, as
  `PermissionDenied` naming it: a symbolic link, anything but a regular file
  (a FIFO is not waited on), or one owned by another user or writable by
  group or others; on Windows one owned by neither the process token's user
  nor its default owner. It reads the record from the file it checked, and
  checks each staged file a committed record renames the same way.
  `recover_expecting(dir, name, targets)` also refuses a record naming a
  file outside `targets`.
- A create-new write whose directory sync fails removes the file it made, so
  a retry is not refused with `AlreadyExists`.
- `Transaction::commit_identified` is `commit` handing back a
  `RecordIdentity` for a record left for recovery, and
  `recover_identified(dir, name, targets, identity)` finishes that record
  without the owner and mode checks while it is still that file, returning
  `None` and touching nothing when it is another.
- `libc` is now a normal dependency on Unix (>= 0.2.174).

## 0.1.3

- `administrators_read_and_delete` (Windows): `owner_only`'s protected DACL,
  with Administrators also granted read and delete; a file Administrators own
  stays theirs in full.
- Feature `testing`: `testing::assert_owner_only` checks `0600`, or on Windows
  reads the DACL back and checks it is protected and grants the owner and
  SYSTEM alone; `testing::assert_administrators_read_and_delete` (Windows)
  checks the DACL `administrators_read_and_delete` sets.

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
