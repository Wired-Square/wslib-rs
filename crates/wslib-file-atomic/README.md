# wslib-file-atomic

Crash-safe whole-file writes: a file is replaced whole or not at all, and who
may read it is settled before anything is written to it.

```rust
use wslib_file_atomic::{Options, Readers};

wslib_file_atomic::replace_private(path, b"secret")?;
wslib_file_atomic::replace_readable(path, keys.as_bytes())?;

Options::new()
    .readers(Readers::Readable)
    .create_parents(true)
    .write_with(path, |file| serde_json::to_writer(file, &value).map_err(Into::into))?;

// Staged now, renamed over the target later:
let staged = Options::new().staging_suffix("next").stage(path, password)?;
staged.promote()?;
// After a restart that found `<path>.next`, keep it or drop it:
wslib_file_atomic::promote(path, "next")?;
wslib_file_atomic::discard(path, "next")?;
```

## What it guarantees

- **Whole or not at all.** The contents go to `<name>.new` (or your suffix),
  appended to the whole name so `app.crt` and `app.key` never share one, are
  synced, and renamed over the target. On Unix the directory is synced too, so
  a power cut leaves the old file or the new one, never a name with nothing
  behind it. A directory that is writable but can't be opened (`0300`) is
  not synced, and that isn't an error.
- **Readers from creation.** The file is created `0600` (`Readers::Private`)
  or `0644` (`Readers::Readable`) and set again on the open file, so a
  restrictive umask such as `UMask=0077` doesn't change it. On Windows a
  private file is opened unshared and given a protected DACL granting its
  owner and SYSTEM; a readable one inherits the directory's ACL.
- **A failure leaves nothing.** A failed write, sync or rename removes the
  staged file, and the old file is untouched. A failed directory sync after
  the rename removes nothing: the file has landed, so an error from `write`
  can mean the new file is in place. A staged file an earlier run
  left is cleared first rather than reused, so its mode never carries over.
- **`write_private`** (or `Options::create_new`) writes at the path itself and
  refuses one that exists; a failed write removes what it made.
- **`stage`** returns a `Staged` you `promote()` or `discard()`, and
  `Options::staged_path` names where it goes. Dropping it leaves the file, so
  a restart can find it with `promote(path, suffix)` or
  `discard(path, suffix)`. A promote's `PromoteError` says which half failed: `Unmoved`
  hands the `Staged` back for a retry or discard, and `Unsynced` means the
  file is in place but its directory wasn't synced. It converts to an
  `io::Error` of the same kind for `?`.
- **`promote_unsynced`** renames without the directory sync, and
  **`sync_dir`** syncs once after the last of several renames. That narrows
  the window in which a power cut leaves a key and its certificate
  mismatched; it doesn't make the pair atomic: `Transaction` does.
- **`owner_only`** restricts an existing file the same way, for files
  something else created.

## Several files together: `Transaction`

```rust
use wslib_file_atomic::{Options, Readers, Transaction};

wslib_file_atomic::recover(state_dir, "tls")?;

let mut tls = Transaction::begin(state_dir, "tls")?;
tls.stage(key_path, key, &Options::new())?;
tls.stage(cert_path, cert, &Options::new().readers(Readers::Readable))?;
tls.commit()?;
```

- **All or none, across a crash.** The record lives in one directory; the
  files may be anywhere. Each is staged beside its target as
  `<file>.<name>.txn`, so every rename stays within its own directory.
- **The commit point is the record.** `<name>.txn` lists each target's
  absolute path and reads `pending` while files are staged, then `committed`
  once all of them are synced. The renames follow, then a sync of each
  target's directory, then the record is removed. Each version of the record
  is written whole, as any `replace` is.
- **Readers call `recover(dir, name)` first**, once at start. It rolls a
  pending transaction back (`Recovered::RolledBack`: its staged files are
  deleted) and a committed one forward (`Recovered::RolledForward`). It only
  ever renames or deletes a target's `<file>.<name>.txn`. A record it can't
  read, or one naming a relative path, is `InvalidData`, and nothing is touched.
- **`begin` refuses while a record is there** (`AlreadyExists`): recover first.
- **A failure before the commit point rolls back**, a failed `stage`
  included, and so does `abort` or dropping the transaction uncommitted. A
  failure after it leaves the record for `recover`.
- **Callers serialise transactions of one name**, as they do writers of one
  path.

## Writers to one path are serialised by the caller

The staged name is fixed, not random: two writers to one path at once clear
each other's staged file. Hold a lock, or keep one writer per path.

## Not covered

- The parent directories `create_parents` makes are not synced.
- Windows doesn't sync the directory after the rename: `File::open` refuses a
  directory there. NTFS keeps the rename atomic, but a power cut can undo it.
- No arbitrary mode, owner or group: chown a staged file through
  `Staged::path()` before promoting it.
- Synchronous only; from async code, call it in `spawn_blocking`.
