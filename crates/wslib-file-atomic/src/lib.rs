//! Crash-safe whole-file writes: a file is replaced whole or not at all, and
//! who may read it is settled before anything is written to it.
//!
//! ```no_run
//! use std::path::Path;
//! use wslib_file_atomic::Options;
//!
//! wslib_file_atomic::replace_private(Path::new("/var/lib/app/token"), b"secret")?;
//!
//! let password = Path::new("/var/lib/app/password");
//! let staged = Options::new().staging_suffix("next").stage(password, b"rotated")?;
//! staged.promote()?;
//! # Ok::<(), std::io::Error>(())
//! ```
//!
//! The staged name is fixed, so writers to one path are serialised by the
//! caller: two at once clear each other's staged file.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

#[cfg(windows)]
mod windows;

/// Create `path` readable by its owner alone and write `contents` to it
/// durably, refusing a path that exists.
pub fn write_private(path: &Path, contents: &[u8]) -> io::Result<()> {
    Options::new().create_new(true).write(path, contents)
}

/// Replace `path` with `contents`, readable by its owner alone, whole or not at all.
pub fn replace_private(path: &Path, contents: &[u8]) -> io::Result<()> {
    Options::new().write(path, contents)
}

/// As [`replace_private`], for a file anyone may read.
pub fn replace_readable(path: &Path, contents: &[u8]) -> io::Result<()> {
    Options::new()
        .readers(Readers::Readable)
        .write(path, contents)
}

/// `path` with `.suffix` appended to its whole file name.
///
/// Appended rather than `with_extension`, which replaces: `app.crt` and
/// `app.key` would both stage as `app.new`.
pub fn beside(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(".");
    name.push(suffix);
    path.with_file_name(name)
}

/// Rename the file staged beside `path` under `suffix` over it, as a restart finds one.
pub fn promote(path: &Path, suffix: &str) -> io::Result<()> {
    rename_into(&beside(path, suffix), path)
}

/// Make `path` readable by its owner alone: `0600`, or on Windows a protected
/// DACL granting its owner and SYSTEM.
pub fn owner_only(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
    }
    #[cfg(windows)]
    windows::owner_only(path)
}

/// Who may read a file.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Readers {
    /// Its owner alone: `0600`, or on Windows its owner and SYSTEM.
    #[default]
    Private,
    /// Anyone: `0644`, or on Windows the directory's ACL.
    Readable,
}

/// How a file is written; by default replaced, private, and staged as `<name>.new`.
#[derive(Clone, Debug)]
pub struct Options {
    readers: Readers,
    create_new: bool,
    create_parents: bool,
    suffix: String,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            readers: Readers::Private,
            create_new: false,
            create_parents: false,
            suffix: "new".into(),
        }
    }
}

impl Options {
    /// The defaults.
    pub fn new() -> Self {
        Self::default()
    }

    /// Who may read the file.
    pub fn readers(mut self, readers: Readers) -> Self {
        self.readers = readers;
        self
    }

    /// Write at the path itself and refuse one that exists, rather than stage and rename over it.
    pub fn create_new(mut self, create_new: bool) -> Self {
        self.create_new = create_new;
        self
    }

    /// Create missing parent directories first.
    pub fn create_parents(mut self, create_parents: bool) -> Self {
        self.create_parents = create_parents;
        self
    }

    /// Stage as `<name>.<suffix>`.
    pub fn staging_suffix(mut self, suffix: impl Into<String>) -> Self {
        self.suffix = suffix.into();
        self
    }

    /// Write `contents` to `path` durably, whole or not at all.
    pub fn write(&self, path: &Path, contents: &[u8]) -> io::Result<()> {
        self.write_with(path, |file| file.write_all(contents))
    }

    /// As [`Options::write`], with `write` filling the file.
    pub fn write_with(
        &self,
        path: &Path,
        write: impl FnOnce(&mut File) -> io::Result<()>,
    ) -> io::Result<()> {
        if self.create_new {
            self.make_parents(path)?;
            create(path, self.readers, write)?;
            return sync_parent(path).inspect_err(|_| {
                let _ = fs::remove_file(path);
            });
        }
        let staged = self.stage_with(path, write)?;
        rename_into(&staged.path, path).inspect_err(|_| {
            let _ = fs::remove_file(&staged.path);
        })
    }

    /// Write `contents` durably beside `path`, for [`Staged::promote`] to rename over it.
    pub fn stage(&self, path: &Path, contents: &[u8]) -> io::Result<Staged> {
        self.stage_with(path, |file| file.write_all(contents))
    }

    /// As [`Options::stage`], with `write` filling the file; refused under [`Options::create_new`].
    pub fn stage_with(
        &self,
        path: &Path,
        write: impl FnOnce(&mut File) -> io::Result<()>,
    ) -> io::Result<Staged> {
        if self.create_new {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "a staged file is renamed over whatever is there, so it cannot be create-new",
            ));
        }
        self.make_parents(path)?;
        let staged = beside(path, &self.suffix);
        // One an interrupted run left, which `create_new` would refuse for ever.
        let _ = fs::remove_file(&staged);
        create(&staged, self.readers, write)?;
        Ok(Staged {
            path: staged,
            target: path.to_owned(),
        })
    }

    fn make_parents(&self, path: &Path) -> io::Result<()> {
        match path.parent() {
            Some(dir) if self.create_parents => fs::create_dir_all(dir),
            _ => Ok(()),
        }
    }
}

/// A file written durably beside its target and not yet renamed over it;
/// dropping it leaves the file.
#[must_use = "a staged file stays until it is promoted or discarded"]
#[derive(Debug)]
pub struct Staged {
    path: PathBuf,
    target: PathBuf,
}

impl Staged {
    /// Where the staged file is.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Rename the staged file over its target; on failure it is left for [`promote`] to retry.
    pub fn promote(self) -> io::Result<()> {
        rename_into(&self.path, &self.target)
    }

    /// Remove the staged file.
    pub fn discard(self) -> io::Result<()> {
        fs::remove_file(&self.path)
    }
}

fn create(
    path: &Path,
    readers: Readers,
    write: impl FnOnce(&mut File) -> io::Result<()>,
) -> io::Result<()> {
    let mut file = open_new(path, readers)?;
    // Synced before any rename: a rename is ordered against the directory entry
    // and not against the data, so a power cut after it can leave a correctly
    // named empty file.
    let written = restrict(&file, path, readers)
        .and_then(|()| write(&mut file))
        .and_then(|()| file.sync_all());
    if written.is_err() {
        drop(file);
        let _ = fs::remove_file(path);
    }
    written
}

fn rename_into(staged: &Path, path: &Path) -> io::Result<()> {
    fs::rename(staged, path)?;
    sync_parent(path)
}

#[cfg(unix)]
impl Readers {
    fn mode(self) -> u32 {
        match self {
            Self::Private => 0o600,
            Self::Readable => 0o644,
        }
    }
}

#[cfg(unix)]
fn open_new(path: &Path, readers: Readers) -> io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(readers.mode())
        .open(path)
}

/// Set on the open file as well as at the open: a umask such as systemd's
/// `UMask=0077` masks what `open(2)` is asked for, and `fchmod` ignores it.
#[cfg(unix)]
fn restrict(file: &File, _: &Path, readers: Readers) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    file.set_permissions(fs::Permissions::from_mode(readers.mode()))
}

#[cfg(unix)]
fn sync_parent(path: &Path) -> io::Result<()> {
    let dir = path.parent().filter(|dir| !dir.as_os_str().is_empty());
    File::open(dir.unwrap_or(Path::new(".")))?.sync_all()
}

/// A private file is opened unshared, so nothing can open its contents before
/// the DACL is set; access is checked at the open.
#[cfg(windows)]
fn open_new(path: &Path, readers: Readers) -> io::Result<File> {
    use std::os::windows::fs::OpenOptionsExt;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    if readers == Readers::Private {
        options.share_mode(0);
    }
    options.open(path)
}

#[cfg(windows)]
fn restrict(_: &File, path: &Path, readers: Readers) -> io::Result<()> {
    match readers {
        Readers::Private => windows::owner_only(path),
        Readers::Readable => Ok(()),
    }
}

/// `File::open` refuses a directory on Windows, so the rename is not flushed
/// there; NTFS keeps it atomic, but a power cut can undo it.
#[cfg(windows)]
fn sync_parent(_: &Path) -> io::Result<()> {
    Ok(())
}
