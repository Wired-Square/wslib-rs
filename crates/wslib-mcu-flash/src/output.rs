use std::fs::File;
use std::io;
use std::path::Path;

use wslib_file_atomic::{Options, Readers};

use crate::error::{FlashError, Result};

/// Fills a file staged beside `path` and renames it over `path` only when
/// `fill` succeeds, so a failed or cancelled read leaves `path` as it was.
pub(crate) fn replace_with(path: &Path, fill: impl FnOnce(&mut File) -> Result<()>) -> Result<()> {
    let mut failure = None;
    let written = Options::new()
        .readers(Readers::Readable)
        .write_with(path, |file| {
            fill(file).map_err(|e| {
                failure = Some(e);
                io::Error::other("read failed")
            })
        });
    match failure {
        Some(e) => Err(e),
        None => written
            .map_err(|e| FlashError::Message(format!("Failed to write {}: {e}", path.display()))),
    }
}
