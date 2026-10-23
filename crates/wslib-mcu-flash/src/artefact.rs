use std::path::PathBuf;

/// A firmware file on local disk, with the kind and flash offset a backend needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaterialisedArtefact {
    pub kind: String,
    pub offset: Option<u32>,
    pub path: PathBuf,
}
