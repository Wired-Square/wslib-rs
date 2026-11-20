//! X.509 certificates: reading and tidying PEM, inspecting and examining a
//! certificate, name coverage, chain checks and a self-signed serving
//! certificate.
//!
//! Parsing is x509-parser's and encoding rcgen's. Signing goes through a
//! [`wslib_crypto::Signer`], and chain and signature checks through the
//! signature algorithms the caller passes, so no crypto provider is enabled here.
//!
//! Inspecting and examining are a report, never a trust decision: only
//! [`chain::verify`] decides that a certificate is good.

use std::fmt;

pub mod chain;
mod constraints;
mod examine;
mod inspect;
mod mint;
mod names;
pub mod pem;
pub mod signature;
#[cfg(test)]
mod testing;

pub use constraints::{IpSubtree, NameConstraints, NameSubtree};
pub use examine::{Report, Warning, examine};
pub use inspect::{
    AttributeValue, CertificateView, ExtendedKeyUsage, KeyDescription, KeyUsage, NameAttribute,
    inspect, inspect_pem, name_attributes, rfc_4514,
};
pub use mint::mint;
pub use names::SubjectAltName;

#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// Longer than [`pem::MAX_LEN`], refused before it was parsed.
    TooLong {
        limit: usize,
        actual: usize,
    },
    /// No `-----BEGIN` line at all, as with DER or PKCS#12.
    NotPem,
    /// A section that opens and never ends: part of a file.
    Unterminated {
        label: String,
    },
    /// No section of the label wanted; `found` is the first label there was.
    Missing {
        wanted: &'static str,
        found: String,
    },
    /// A section that is not a certificate beside one, such as a private key.
    Beside {
        label: String,
    },
    /// A private key with a passphrase on it.
    Encrypted,
    MoreThanOneKey,
    /// Decodes, but not as what was wanted, in this crate's words.
    Malformed(String),
    /// Base64, DER or a certificate the decoder refuses: its error.
    Decode(Box<dyn std::error::Error + Send + Sync>),
    /// Text that is not a subject alternative name.
    Name {
        name: String,
        reason: &'static str,
    },
    NoNames,
    /// The certificate could not be made or signed: rcgen's or wslib-crypto's error.
    Mint(Box<dyn std::error::Error + Send + Sync>),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLong { limit, actual } => {
                write!(
                    f,
                    "PEM text may be at most {limit} bytes, and that is {actual}"
                )
            }
            Self::NotPem => f.write_str("not PEM: there is no -----BEGIN line"),
            Self::Unterminated { label } => {
                write!(f, "a {label} section opens and never ends")
            }
            Self::Missing { wanted, found } => {
                write!(f, "wanted a {wanted} section, and found a {found} section")
            }
            Self::Beside { label } => {
                write!(f, "a {label} section beside the certificate")
            }
            Self::Encrypted => f.write_str("the private key is encrypted"),
            Self::MoreThanOneKey => f.write_str("more than one private key"),
            Self::Malformed(why) => write!(f, "does not decode: {why}"),
            Self::Decode(_) => f.write_str("does not decode"),
            Self::Name { name, reason } => write!(f, "{name:?} is not a usable name: {reason}"),
            Self::NoNames => f.write_str("a certificate needs at least one name"),
            Self::Mint(_) => f.write_str("making the certificate failed"),
        }
    }
}

impl Error {
    fn decode(e: impl std::error::Error + Send + Sync + 'static) -> Self {
        Self::Decode(Box::new(e))
    }

    fn mint(e: impl std::error::Error + Send + Sync + 'static) -> Self {
        Self::Mint(Box::new(e))
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Decode(e) | Self::Mint(e) => Some(&**e),
            _ => None,
        }
    }
}
