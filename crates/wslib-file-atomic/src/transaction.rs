use std::fs::{self, File};
use std::io::{self, Write};
use std::mem;
use std::path::{Path, PathBuf};
use std::{error, fmt};

use crate::{Options, PromoteError, beside, remove_if_there, sync_dir, sync_parent};

const PENDING: &str = "pending";
const COMMITTED: &str = "committed";

/// Several files replaced together or not at all, across a crash, once
/// [`recover`] has run.
///
/// Its record is `<name>.txn` in the directory it was begun in, and each file
/// is staged beside its target as `<file>.<name>.txn`.
#[must_use = "a transaction dropped without commit is aborted"]
#[derive(Debug)]
pub struct Transaction {
    record: PathBuf,
    suffix: String,
    targets: Vec<PathBuf>,
    open: bool,
}

/// Which file a committed record is, compared on an open handle: the device
/// and inode, or on Windows the volume serial and file index.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecordIdentity(u64, u64);

impl RecordIdentity {
    #[cfg(unix)]
    fn of(file: &File) -> io::Result<Self> {
        use std::os::unix::fs::MetadataExt;
        let metadata = file.metadata()?;
        Ok(Self(metadata.dev(), metadata.ino()))
    }

    #[cfg(windows)]
    fn of(file: &File) -> io::Result<Self> {
        crate::windows::file_id(file).map(|(volume, index)| Self(volume, index))
    }
}

/// What [`recover`] found.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Recovered {
    /// No unfinished transaction.
    Nothing,
    /// One that had not committed: its staged files are gone and no target changed.
    RolledBack,
    /// One that had committed: every target now holds its new contents.
    RolledForward,
}

/// Why a [`Transaction::commit`] failed, and on which side of the commit point.
#[non_exhaustive]
#[derive(Debug)]
pub enum CommitError {
    /// Before it: every target is untouched, and anything left is a pending
    /// record [`recover`] rolls back.
    RolledBack(io::Error),
    /// After it: the committed record is left, and [`recover`] rolls it forward,
    /// unless the failure was syncing the record's directory and a power cut
    /// then undoes the commit, leaving every target as it was.
    Committed(io::Error),
}

impl CommitError {
    fn io(&self) -> &io::Error {
        match self {
            Self::RolledBack(error) | Self::Committed(error) => error,
        }
    }
}

impl fmt::Display for CommitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RolledBack(error) => write!(f, "not committed, and rolled back: {error}"),
            Self::Committed(error) => {
                write!(f, "committed, but left for recovery to finish: {error}")
            }
        }
    }
}

impl error::Error for CommitError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        Some(self.io())
    }
}

impl From<CommitError> for io::Error {
    fn from(e: CommitError) -> Self {
        io::Error::new(e.io().kind(), e)
    }
}

/// Why [`recover`] would not act on a record, or on a staged file a committed
/// record renames: the source of the `PermissionDenied` it returns.
#[derive(Debug)]
pub struct Refused {
    path: PathBuf,
    why: String,
}

impl Refused {
    /// The record or staged file refused.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl fmt::Display for Refused {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} is refused: {}", self.path.display(), self.why)
    }
}

impl error::Error for Refused {}

impl Transaction {
    /// Start a transaction named `name` with its record in `dir`, refused while
    /// an unfinished one of that name is there.
    pub fn begin(dir: &Path, name: &str) -> io::Result<Self> {
        let record = record_path(&fs::canonicalize(or_here(dir))?, name)?;
        if record.try_exists()? {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!("{} is unfinished: recover it first", record.display()),
            ));
        }
        let transaction = Self {
            record,
            suffix: suffix(name),
            targets: Vec::new(),
            open: true,
        };
        transaction.write_record(PENDING)?;
        Ok(transaction)
    }

    /// Stage `contents` for `path`; a failure to write it rolls the whole
    /// transaction back.
    pub fn stage(&mut self, path: &Path, contents: &[u8], options: &Options) -> io::Result<()> {
        self.stage_with(path, options, |file| file.write_all(contents))
    }

    /// As [`Transaction::stage`], with `write` filling the file.
    pub fn stage_with(
        &mut self,
        path: &Path,
        options: &Options,
        write: impl FnOnce(&mut File) -> io::Result<()>,
    ) -> io::Result<()> {
        let target = self.absolute_target(path, options)?;
        self.targets.push(target.clone());
        // Listed before it exists, so a crash from here on leaves a record naming it.
        let staged = self.write_record(PENDING).and_then(|()| {
            options
                .clone()
                .staging_suffix(&self.suffix)
                .hidden_staging(false)
                .stage_with(&target, write)
        });
        if staged.is_err() {
            let _ = self.roll_back();
        }
        staged.map(drop)
    }

    /// Replace every staged file's target, or, failing before the commit
    /// point, none of them.
    pub fn commit(self) -> Result<(), CommitError> {
        self.commit_identified().map_err(|(error, _)| error)
    }

    /// As [`Transaction::commit`], with the identity of a committed record
    /// left for [`recover_identified`].
    pub fn commit_identified(mut self) -> Result<(), (CommitError, Option<RecordIdentity>)> {
        let mut identity = None;
        let contents = self.contents(COMMITTED);
        let staged = self
            .ensure_open()
            // Under a committed record a missing staged file must mean renamed.
            .and_then(|()| sync_parents(&self.targets))
            .and_then(|()| {
                Options::new().stage_with(&self.record, |file| {
                    file.write_all(contents.as_bytes())?;
                    identity = Some(RecordIdentity::of(file)?);
                    Ok(())
                })
            });
        let staged = match staged {
            Ok(staged) => staged,
            Err(e) => {
                let _ = self.roll_back();
                return Err((CommitError::RolledBack(e), None));
            }
        };
        // The rename of the committed record is the commit point: from there
        // the only correct direction is forward.
        match staged.promote() {
            Err(PromoteError::Unmoved { staged, error }) => {
                let _ = staged.discard();
                let _ = self.roll_back();
                Err((CommitError::RolledBack(error), None))
            }
            promoted => {
                self.open = false;
                promoted
                    .map_err(io::Error::from)
                    .and_then(|()| roll_forward(&self.record, &self.suffix, &self.targets))
                    .map_err(|error| (CommitError::Committed(error), identity))
            }
        }
    }

    /// Where the record is.
    pub fn record(&self) -> &Path {
        &self.record
    }

    /// Remove the staged files and the record, leaving every target as it was.
    pub fn abort(mut self) -> io::Result<()> {
        self.roll_back()
    }

    fn absolute_target(&self, path: &Path, options: &Options) -> io::Result<PathBuf> {
        self.ensure_open()?;
        let invalid = |why: &str| {
            Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{}: {why}", path.display()),
            ))
        };
        if options.create_new {
            return invalid(
                "a staged file is renamed over whatever is there, so it cannot be create-new",
            );
        }
        let Some(name) = path.file_name() else {
            return invalid("not a file");
        };
        options.make_parents(path)?;
        let parent = path.parent().map_or(Path::new("."), or_here);
        let target = fs::canonicalize(parent)?.join(name);
        if target.to_str().is_none_or(|text| !plain_line(text)) {
            return invalid("not UTF-8 free of tabs and newlines");
        }
        if target == self.record {
            return invalid("the transaction's own record");
        }
        if self.targets.contains(&target) {
            return invalid("already staged in this transaction");
        }
        Ok(target)
    }

    fn ensure_open(&self) -> io::Result<()> {
        if self.open {
            Ok(())
        } else {
            Err(io::Error::other("the transaction was rolled back"))
        }
    }

    fn contents(&self, state: &str) -> String {
        let mut contents = format!("{state}\n");
        for target in &self.targets {
            contents.push_str(&format!("{}\n", target.display()));
        }
        contents
    }

    fn write_record(&self, state: &str) -> io::Result<()> {
        Options::new().write(&self.record, self.contents(state).as_bytes())
    }

    fn roll_back(&mut self) -> io::Result<()> {
        if !mem::replace(&mut self.open, false) {
            return Ok(());
        }
        roll_back(&self.record, &self.suffix, &self.targets)
    }
}

impl Drop for Transaction {
    fn drop(&mut self) {
        let _ = self.roll_back();
    }
}

/// Finish what a crash left of the transaction named `name` with its record in
/// `dir`; call it before reading the files a transaction writes.
///
/// A record is refused, as `PermissionDenied`, unless it is a regular file,
/// not a symbolic link, owned by this process's user and writable by no one
/// else; on Windows, owned by this process's user or its default owner. So is
/// a staged file a committed record would rename over its target. A refusal
/// carries a [`Refused`].
pub fn recover(dir: &Path, name: &str) -> io::Result<Recovered> {
    recover_checked(dir, name, None, None).map(checked_in_full)
}

/// As [`recover`], also refusing a record that names a file outside `targets`.
pub fn recover_expecting(dir: &Path, name: &str, targets: &[&Path]) -> io::Result<Recovered> {
    let expected = expected(targets);
    recover_checked(dir, name, Some(&expected), None).map(checked_in_full)
}

/// As [`recover_expecting`] without the owner and mode checks, for a record
/// that is still the file `identity` names; `None`, touching nothing, when it
/// is another.
pub fn recover_identified(
    dir: &Path,
    name: &str,
    targets: &[&Path],
    identity: &RecordIdentity,
) -> io::Result<Option<Recovered>> {
    let expected = expected(targets);
    recover_checked(dir, name, Some(&expected), Some(identity))
}

fn expected(targets: &[&Path]) -> Vec<PathBuf> {
    targets.iter().map(|target| as_recorded(target)).collect()
}

fn checked_in_full(recovered: Option<Recovered>) -> Recovered {
    recovered.expect("only an identified record is passed over")
}

fn recover_checked(
    dir: &Path,
    name: &str,
    expected: Option<&[PathBuf]>,
    identity: Option<&RecordIdentity>,
) -> io::Result<Option<Recovered>> {
    let record = record_path(dir, name)?;
    let contents = match read_record(&record, identity) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Some(Recovered::Nothing)),
        Ok(None) => return Ok(None),
        Ok(Some(contents)) => contents,
        Err(e) => return Err(e),
    };
    let malformed = || {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{} is not a transaction record", record.display()),
        )
    };
    let mut lines = contents.lines();
    let state = lines.next().ok_or_else(malformed)?;
    let targets = lines
        .map(|line| {
            Some(PathBuf::from(line))
                .filter(|target| {
                    plain_line(line) && target.is_absolute() && target.file_name().is_some()
                })
                .ok_or_else(malformed)
        })
        .collect::<io::Result<Vec<_>>>()?;
    if let Some(unexpected) = targets
        .iter()
        .find(|target| expected.is_some_and(|expected| !expected.contains(target)))
    {
        return Err(refused(
            &record,
            &format!("it names {}, which is not expected", unexpected.display()),
        ));
    }
    let suffix = suffix(name);
    match state {
        PENDING => roll_back(&record, &suffix, &targets).map(|()| Recovered::RolledBack),
        COMMITTED => roll_forward(&record, &suffix, &targets).map(|()| Recovered::RolledForward),
        _ => Err(malformed()),
    }
    .map(Some)
}

/// As [`Transaction`] lists it: the parent canonical, so a link there names the same file.
fn as_recorded(target: &Path) -> PathBuf {
    let parent = target.parent().map_or(Path::new("."), or_here);
    match (fs::canonicalize(parent), target.file_name()) {
        (Ok(parent), Some(name)) => parent.join(name),
        _ => target.to_path_buf(),
    }
}

fn refused(path: &Path, why: &str) -> io::Error {
    let refused = Refused {
        path: path.to_path_buf(),
        why: why.to_string(),
    };
    io::Error::new(io::ErrorKind::PermissionDenied, refused)
}

/// Read from the file that was checked, so nothing can be swapped in between.
fn read_record(record: &Path, identity: Option<&RecordIdentity>) -> io::Result<Option<String>> {
    let file = open_record(record)?;
    match identity {
        Some(identity) if RecordIdentity::of(&file)? != *identity => return Ok(None),
        Some(_) => {}
        None => refuse_unless_ours(record, &file)?,
    }
    io::read_to_string(file).map(Some)
}

fn refuse_unless_ours(path: &Path, file: &File) -> io::Result<()> {
    if !file.metadata()?.is_file() {
        return Err(refused(path, "not a regular file"));
    }
    match untrusted(file)? {
        Some(why) => Err(refused(path, why)),
        None => Ok(()),
    }
}

/// Non-blocking, so a FIFO planted as the record is refused rather than waited on.
#[cfg(unix)]
fn open_record(record: &Path) -> io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    match fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(record)
    {
        Err(e) if e.raw_os_error() == Some(libc::ELOOP) => Err(refused(record, "a symbolic link")),
        opened => opened,
    }
}

#[cfg(unix)]
fn untrusted(file: &File) -> io::Result<Option<&'static str>> {
    use std::os::unix::fs::MetadataExt;
    let metadata = file.metadata()?;
    // SAFETY: a plain syscall with no arguments.
    Ok(if metadata.uid() != unsafe { libc::geteuid() } {
        Some("owned by another user")
    } else if metadata.mode() & 0o022 != 0 {
        Some("writable by others")
    } else {
        None
    })
}

/// A link is opened as itself, which is then not a regular file.
#[cfg(windows)]
fn open_record(record: &Path) -> io::Result<File> {
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
    };
    fs::OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS)
        .open(record)
}

#[cfg(windows)]
fn untrusted(file: &File) -> io::Result<Option<&'static str>> {
    Ok((!crate::windows::owned_by_this_process(file)?).then_some("owned by another user"))
}

fn record_path(dir: &Path, name: &str) -> io::Result<PathBuf> {
    if !plain_line(name) || Path::new(name).file_name() != Some(name.as_ref()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{name:?} is not a file name free of tabs and newlines"),
        ));
    }
    Ok(dir.join(format!("{name}.txn")))
}

fn or_here(dir: &Path) -> &Path {
    if dir.as_os_str().is_empty() {
        Path::new(".")
    } else {
        dir
    }
}

fn suffix(name: &str) -> String {
    format!("{name}.txn")
}

fn plain_line(text: &str) -> bool {
    !text.is_empty() && !text.contains(['\t', '\n', '\r'])
}

/// The staged files go, and are synced gone, before the record: a record
/// lost first would strand a staged secret with nothing naming it.
fn roll_back(record: &Path, suffix: &str, targets: &[PathBuf]) -> io::Result<()> {
    for target in targets {
        remove_if_there(&beside(target, suffix))?;
    }
    sync_parents(targets)?;
    remove_if_there(record)
}

/// A staged file already gone under a committed record was renamed before the
/// crash, so replaying is idempotent; one there is checked as the record is, as
/// a file planted under its name would be renamed over the target.
fn roll_forward(record: &Path, suffix: &str, targets: &[PathBuf]) -> io::Result<()> {
    for target in targets {
        let staged = beside(target, suffix);
        match open_record(&staged) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            opened => refuse_unless_ours(&staged, &opened?)?,
        }
        match fs::rename(&staged, target) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            renamed => renamed?,
        }
    }
    sync_parents(targets)?;
    fs::remove_file(record)?;
    sync_parent(record)
}

fn sync_parents(targets: &[PathBuf]) -> io::Result<()> {
    let mut dirs: Vec<_> = targets
        .iter()
        .filter_map(|target| target.parent())
        .collect();
    dirs.sort();
    dirs.dedup();
    dirs.into_iter().try_for_each(sync_dir)
}
