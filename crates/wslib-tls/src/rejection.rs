use std::error::Error;
use std::sync::Arc;

use rustls::{CertificateError, OtherError};
use wslib_crypto::Fingerprint;

/// Why [`Outbound`](crate::Outbound)'s verifier refused a certificate, where rustls's own
/// [`CertificateError`] does not say.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Rejection {
    /// The host is pinned to another certificate.
    #[error("{host} presented sha256:{presented} but is pinned to sha256:{pinned}")]
    PinMismatch {
        host: String,
        presented: Fingerprint,
        pinned: Fingerprint,
    },
    /// The first read of the OS store did not land in time.
    #[error("the OS trust store has not been read yet, so {host} cannot be checked against it")]
    OsRootsNotRead { host: String },
    /// Not pinned, and no root or authority to check it against.
    #[error("{host} has no pinned certificate, and there is no authority to check it against")]
    NoAuthority { host: String },
}

impl From<Rejection> for rustls::Error {
    fn from(rejection: Rejection) -> Self {
        Self::Other(OtherError(Arc::new(rejection)))
    }
}

/// Why a handshake was refused, as [`cause`] finds it.
#[derive(Clone, Debug, PartialEq)]
#[non_exhaustive]
pub enum Cause {
    Rejected(Rejection),
    /// rustls's verdict on the chain: unknown issuer, expired, not valid for the name…
    Certificate(CertificateError),
}

/// Finds why a handshake was refused in `error` or its sources, as an HTTP
/// client wraps it: through hyper and `std::io::Error` down to the `rustls::Error`.
pub fn cause(error: &(dyn Error + 'static)) -> Option<Cause> {
    let mut next = Some(error);
    while let Some(error) = next {
        if let Some(rejection) = error.downcast_ref::<Rejection>() {
            return Some(Cause::Rejected(rejection.clone()));
        }
        next = match error.downcast_ref::<rustls::Error>() {
            Some(rustls::Error::InvalidCertificate(certificate)) => {
                return Some(Cause::Certificate(certificate.clone()));
            }
            Some(rustls::Error::Other(OtherError(other))) => Some(other.as_ref()),
            // Its `source` skips the error it wraps.
            _ => match error.downcast_ref::<std::io::Error>() {
                Some(io) => io.get_ref().map(|inner| inner as &(dyn Error + 'static)),
                None => error.source(),
            },
        };
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, thiserror::Error)]
    #[error("client error")]
    struct Client(#[source] std::io::Error);

    #[test]
    fn a_cause_is_found_through_a_client_and_io_error() {
        let rejection = Rejection::NoAuthority {
            host: "widget.local".into(),
        };
        let wrapped = |error: rustls::Error| {
            Client(std::io::Error::new(std::io::ErrorKind::InvalidData, error))
        };
        assert_eq!(
            cause(&wrapped(rejection.clone().into())),
            Some(Cause::Rejected(rejection))
        );
        assert_eq!(
            cause(&wrapped(CertificateError::UnknownIssuer.into())),
            Some(Cause::Certificate(CertificateError::UnknownIssuer))
        );
        assert_eq!(cause(&wrapped(rustls::Error::HandshakeNotComplete)), None);
        assert_eq!(cause(&std::io::Error::other("refused")), None);
    }
}
