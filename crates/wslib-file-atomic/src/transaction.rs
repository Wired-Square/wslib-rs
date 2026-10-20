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
    pub fn commit(mut self) -> Result<(), CommitError> {
        let staged = self
            .ensure_open()
            // Under a committed record a missing staged file must mean renamed.
            .and_then(|()| sync_parents(&self.targets))
            .and_then(|()| Options::new().stage(&self.record, self.contents(COMMITTED).as_bytes()));
        let staged = match staged {
            Ok(staged) => staged,
            Err(e) => {
                let _ = self.roll_back();
                return Err(CommitError::RolledBack(e));
            }
        };
        // The rename of the committed record is the commit point: from there
        // the only correct direction is forward.
        match staged.promote() {
            Err(PromoteError::Unmoved { staged, error }) => {
                let _ = staged.discard();
                let _ = self.roll_back();
                Err(CommitError::RolledBack(error))
            }
            promoted => {
                self.open = false;
                promoted
                    .map_err(io::Error::from)
                    .and_then(|()| roll_forward(&self.record, &self.suffix, &self.targets))
                    .map_err(CommitError::Committed)
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
pub fn recover(dir: &Path, name: &str) -> io::Result<Recovered> {
    let record = record_path(dir, name)?;
    let contents = match fs::read_to_string(&record) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Recovered::Nothing),
        read => read?,
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
    let suffix = suffix(name);
    match state {
        PENDING => roll_back(&record, &suffix, &targets).map(|()| Recovered::RolledBack),
        COMMITTED => roll_forward(&record, &suffix, &targets).map(|()| Recovered::RolledForward),
        _ => Err(malformed()),
    }
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
/// crash, so replaying is idempotent.
fn roll_forward(record: &Path, suffix: &str, targets: &[PathBuf]) -> io::Result<()> {
    for target in targets {
        match fs::rename(beside(target, suffix), target) {
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
