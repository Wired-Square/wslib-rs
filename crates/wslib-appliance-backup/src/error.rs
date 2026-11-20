//! Why a bundle could not be written or opened.

use wslib_appliance_core::ApiError;
use wslib_appliance_core::backend::chain;

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

    /// KDF parameters the bundle carries, which the KDF refuses.
    #[error("this backup is damaged: its KDF parameters are unusable")]
    KdfParameters(#[source] Box<dyn std::error::Error + Send + Sync>),

    /// Priced above what a route with no session will pay; a restore with a
    /// session takes it.
    #[error(
        "this backup asks for more work to open than one this product writes — make the \
         first account, then restore it from Settings, where a larger cost is allowed"
    )]
    TooDearWithoutASession,

    /// An empty or too-short passphrase. Carries the sentence.
    #[error("{0}")]
    Passphrase(String),

    /// The KDF could not derive a key from the passphrase.
    #[error("could not derive a key from the passphrase")]
    Derive(#[source] Box<dyn std::error::Error + Send + Sync>),

    #[error("a backup may be at most {limit} bytes, and this is {actual}")]
    TooLarge { limit: usize, actual: usize },

    /// The box's state refuses it, in a sentence shown as it is.
    #[error("{0}")]
    Refused(String),

    #[error("the store failed")]
    Store(#[from] wslib_appliance_store::StoreError),

    /// A fault on the write path. Carries the sentence.
    #[error("this backup could not be written: {0}")]
    Internal(String),

    /// A fault on the write path, with the error behind it.
    #[error("this backup could not be written")]
    Failed(#[source] Box<dyn std::error::Error + Send + Sync>),

    /// The sealed bundle could not be written to `path`.
    #[error("this backup could not be written to {}", path.display())]
    Unwritten {
        path: std::path::PathBuf,
        source: std::io::Error,
    },

    /// The blocking work panicked; the panic hook has reported it.
    #[error("writing the backup panicked")]
    Panicked,

    /// The runtime shut down before the blocking work ran.
    #[error("the runtime shut down before the backup was written")]
    Cancelled,
}

impl BackupError {
    pub(crate) fn failed(e: impl std::error::Error + Send + Sync + 'static) -> Self {
        Self::Failed(Box::new(e))
    }

    pub(crate) fn unjoined(e: tokio::task::JoinError) -> Self {
        match e.is_panic() {
            true => Self::Panicked,
            false => Self::Cancelled,
        }
    }

    pub(crate) fn malformed(e: impl std::fmt::Display) -> Self {
        Self::Malformed(e.to_string())
    }
}

/// The status each refusal answers, its body the error with each of its
/// causes.
///
/// | Variant | Status |
/// | --- | --- |
/// | `NotABundle`, `Malformed`, `KdfParameters`, `Passphrase`, `Derive`, `WrongPassphrase` | 400 |
/// | `TooDearWithoutASession` | 403 |
/// | `FormatTooNew`, `SchemaTooNew`, `OtherProduct`, `Refused` | 409 |
/// | `TooLarge` | 413 |
/// | `Internal`, `Failed`, `Unwritten`, `Panicked`, `Cancelled` | 500, the cause in the journal |
/// | `Store` | the store's own mapping |
///
/// `WrongPassphrase` is not 401, which would send a browser to sign in again.
impl From<BackupError> for ApiError {
    fn from(e: BackupError) -> Self {
        use BackupError::*;
        match e {
            NotABundle | Malformed(_) | KdfParameters(_) | Passphrase(_) | Derive(_)
            | WrongPassphrase => ApiError::BadRequest(chain(&e)),
            FormatTooNew { .. } | SchemaTooNew { .. } | OtherProduct | Refused(_) => {
                ApiError::Conflict(e.to_string())
            }
            TooDearWithoutASession => ApiError::Forbidden(e.to_string()),
            TooLarge { .. } => ApiError::PayloadTooLarge(e.to_string()),
            Store(e) => e.into(),
            Internal(_) | Failed(_) | Unwritten { .. } | Panicked | Cancelled => {
                ApiError::internal("write the backup", &e)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_blocking_write_that_panicked_or_was_cancelled_says_which() {
        let panicked = tokio::spawn(async { panic!("boom") }).await.unwrap_err();
        assert!(matches!(
            BackupError::unjoined(panicked),
            BackupError::Panicked
        ));
        let pending = tokio::spawn(std::future::pending::<()>());
        pending.abort();
        let cancelled = pending.await.unwrap_err();
        assert!(matches!(
            BackupError::unjoined(cancelled),
            BackupError::Cancelled
        ));
    }
}
