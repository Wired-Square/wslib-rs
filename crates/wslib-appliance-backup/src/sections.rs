//! The seam where a product adds its own sections to a bundle and takes them
//! back.
//!
//! A section is a name and a JSON value: rows as an array, or a directory of
//! files as an array of `{ "path": …, "bytes": … }`. A `path` is text out of
//! somebody's file, on the first-run route anyone's on the network: write only
//! under a directory of the product's own.
//!
//! A restore asks [`Sections::blocked`] with nothing open, writes the
//! platform's half, then [`Sections::restore`] in the same transaction,
//! commits, installs the pair and the key files, and runs
//! [`Sections::after_restore`]. Rows go in `restore`; anything a rollback cannot
//! undo goes in `after_restore`. Their sentences reach the restore's report and
//! nothing else. A product table referencing `users` keeps its rows for every
//! account the bundle carries, and loses them, under `CASCADE`, for the rest.
//!
//! A host's factory reset calls [`Sections::erase`] in its transaction and
//! [`Sections::after_reset`] once it has committed.

use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;

use wslib_appliance_store::Store;
use wslib_appliance_store::sqlx::{Sqlite, Transaction};
use wslib_appliance_types::backup::Chosen;

use crate::{BackupError, Bundle, Snapshot};

/// What a product keeps that a bundle should carry. A restore runs on a task
/// of its own, so `restore` and `after_restore` must not read task-locals.
pub trait Sections: Clone + Send + Sync + 'static {
    /// Every section name [`capture`](Self::capture) may put and every name
    /// [`restore`](Self::restore) reads, a renamed section's old name too.
    ///
    /// A restore applies only these, and refuses one whose sections are all
    /// another product's, unless a console restores it. Asked once by each take,
    /// inspect and restore, so the set may change while the product runs.
    fn names(&self) -> impl Future<Output = Result<BTreeSet<String>, BackupError>> + Send;

    /// Put each section into `into` with [`Snapshot::put`], by a name in the
    /// take's [`Snapshot::names`]; one the take
    /// [leaves out](Snapshot::leaves_out) need not be read.
    fn capture(
        &self,
        store: &Store,
        into: &mut Snapshot,
    ) -> impl Future<Output = Result<(), BackupError>> + Send;

    /// Write the sections named in `chosen` from `from` with [`Bundle::take`],
    /// inside `tx`, after the platform's half; one not chosen is left as it is.
    /// `chosen` names only sections `from` carries. The sentences are warnings
    /// for the report. An `Err` rolls the whole restore back.
    fn restore(
        &self,
        tx: &mut Transaction<'_, Sqlite>,
        from: &Bundle,
        chosen: &BTreeSet<String>,
    ) -> impl Future<Output = Result<Vec<String>, BackupError>> + Send;

    /// What this build would not understand about the rows `from` carries, shown
    /// at inspect and carried in the restore's report. Warnings, never refusals.
    fn warnings(&self, _from: &Bundle) -> Vec<String> {
        Vec::new()
    }

    /// Which of `names` cannot be restored right now, each with a sentence
    /// saying why, including any [`names`](Self::names) does not answer, such
    /// as an app not installed.
    ///
    /// Asked with no transaction open, before anything is proved or written; a
    /// restore choosing one is refused with [`BackupError::Refused`].
    /// [`restore`](Self::restore) has the last word.
    fn blocked(
        &self,
        _store: &Store,
        _names: &BTreeSet<String>,
    ) -> impl Future<Output = BTreeMap<String, String>> + Send {
        async { BTreeMap::new() }
    }

    /// Once a restore has committed and the pair and key files have been tried:
    /// write the sections in `applied.app` that are not rows, and restart what
    /// ran against rows now gone. Awaited before the restore answers; what
    /// could not be done is a sentence for the report.
    fn after_restore(
        &self,
        _store: &Store,
        _from: &Bundle,
        _applied: &Chosen,
    ) -> impl Future<Output = Vec<String>> + Send {
        async { Vec::new() }
    }

    /// Empty every table the product owns, inside the factory reset's `tx`,
    /// after the platform's half. An `Err` rolls the whole reset back.
    fn erase(
        &self,
        tx: &mut Transaction<'_, Sqlite>,
    ) -> impl Future<Output = Result<(), BackupError>> + Send;

    /// Once a reset has committed: restart what ran against rows now gone, and
    /// clear the product's files unless `database_only`. Sentences for the
    /// report.
    fn after_reset(
        &self,
        _store: &Store,
        _database_only: bool,
    ) -> impl Future<Output = Vec<String>> + Send {
        async { Vec::new() }
    }
}

/// A product with nothing of its own to carry.
impl Sections for () {
    async fn names(&self) -> Result<BTreeSet<String>, BackupError> {
        Ok(BTreeSet::new())
    }

    async fn capture(&self, _: &Store, _: &mut Snapshot) -> Result<(), BackupError> {
        Ok(())
    }

    async fn restore(
        &self,
        _: &mut Transaction<'_, Sqlite>,
        _: &Bundle,
        _: &BTreeSet<String>,
    ) -> Result<Vec<String>, BackupError> {
        Ok(Vec::new())
    }

    async fn erase(&self, _: &mut Transaction<'_, Sqlite>) -> Result<(), BackupError> {
        Ok(())
    }
}
