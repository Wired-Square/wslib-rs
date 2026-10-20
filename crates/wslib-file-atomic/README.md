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
// After a restart that found `<path>.next`:
wslib_file_atomic::promote(path, "next")?;
```

## What it guarantees

- **Whole or not at all.** The contents go to `<name>.new` (or your suffix),
  appended to the whole name so `app.crt` and `app.key` never share one, are
  synced, and renamed over the target. On Unix the directory is synced too, so
  a power cut leaves the old file or the new one, never a name with nothing
  behind it.
- **Readers from creation.** The file is created `0600` (`Readers::Private`)
  or `0644` (`Readers::Readable`) and set again on the open file, so a
  restrictive umask such as `UMask=0077` doesn't change it. On Windows a
  private file is opened unshared and given a protected DACL granting its
  owner and SYSTEM; a readable one inherits the directory's ACL.
- **A failure leaves nothing.** A failed write, sync or rename removes the
  staged file, and the old file is untouched. A staged file an earlier run
  left is cleared first rather than reused, so its mode never carries over.
- **`write_private`** (or `Options::create_new`) writes at the path itself and
  refuses one that exists; a failure removes what it made.
- **`stage`** returns a `Staged` you `promote()` or `discard()`. Dropping it
  leaves the file, and a failed `promote()` keeps it, so a restart can find it
  with `promote(path, suffix)`.
- **`owner_only`** restricts an existing file the same way, for files
  something else created.

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
