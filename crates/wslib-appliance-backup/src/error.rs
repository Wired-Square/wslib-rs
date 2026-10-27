//! Why a bundle could not be written or opened.

use wslib_appliance_core::ApiError;

/// Why a bundle could not be written or opened. `Malformed` is a file somebody
/// handed in; a fault on the write path is `Internal`.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum BackupError {
    #[error("this is not an appliance backup file")]
    NotABundle,

    #[error(
        "this backup was written in format {theirs}, and this build reads {ours} — \
         upgrade the appliance before restoring it"
    )]
    FormatTooNew { theirs: u32, ours: u32 },

    #[error(
        "this backup came from a newer version of this appliance (database schema \
         {theirs}, this build has {ours}) — upgrade before restoring it"
    )]
    SchemaTooNew { theirs: u32, ours: u32 },

    #[error("this backup is another product's")]
    OtherProduct,

    /// The seal cannot tell a wrong passphrase from an altered file.
    #[error("the passphrase did not open this backup, or the file has been altered")]
    WrongPassphrase,

    #[error("this backup is damaged: {0}")]
    Malformed(String),

    /// Priced above what a route with no session will pay; a restore with a
    /// session takes it.
    #[error(
        "this backup asks for more work to open than one this product writes — make the \
         first account, then restore it from Settings, where a larger cost is allowed"
    )]
    TooDearWithoutASession,

    /// An empty or too-short passphrase, or a key that could not be derived.
    #[error("{0}")]
    Passphrase(String),

    #[error("a backup may be at most {limit} bytes, and this is {actual}")]
    TooLarge { limit: usize, actual: usize },

    /// The box's state refuses it, in a sentence shown as it is.
    #[error("{0}")]
    Refused(String),

    #[error(transparent)]
    Store(#[from] wslib_appliance_store::StoreError),

    #[error("this backup could not be written: {0}")]
    Internal(String),
}

impl BackupError {
    pub(crate) fn internal(e: impl std::fmt::Display) -> Self {
        Self::Internal(e.to_string())
    }

    pub(crate) fn malformed(e: impl std::fmt::Display) -> Self {
        Self::Malformed(e.to_string())
    }
}

/// The status each refusal answers.
///
/// | Variant | Status |
/// | --- | --- |
/// | `NotABundle`, `Malformed`, `Passphrase`, `WrongPassphrase` | 400 |
/// | `TooDearWithoutASession` | 403 |
/// | `FormatTooNew`, `SchemaTooNew`, `OtherProduct`, `Refused` | 409 |
/// | `TooLarge` | 413 |
/// | `Internal` | 500, the cause in the journal |
/// | `Store` | the store's own mapping |
///
/// `WrongPassphrase` is not 401, which would send a browser to sign in again.
impl From<BackupError> for ApiError {
    fn from(e: BackupError) -> Self {
        use BackupError::*;
        match e {
            NotABundle | Malformed(_) | Passphrase(_) | WrongPassphrase => {
                ApiError::BadRequest(e.to_string())
            }
            FormatTooNew { .. } | SchemaTooNew { .. } | OtherProduct | Refused(_) => {
                ApiError::Conflict(e.to_string())
            }
            TooDearWithoutASession => ApiError::Forbidden(e.to_string()),
            TooLarge { .. } => ApiError::PayloadTooLarge(e.to_string()),
            Store(e) => e.into(),
            Internal(_) => ApiError::internal("write the backup", &e),
        }
    }
}
