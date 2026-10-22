//! OpenSSH `authorized_keys`: key lines checked as sshd reads them, `SHA256:`
//! fingerprints as `ssh-keygen -l` prints them, who added each key, and a
//! whole-file rewrite.
//!
//! ```
//! use wslib_ssh_keys::{AuthorisedKeys, Entry, Key, Provenance};
//!
//! let key: Key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA9frf+EPG/Tj073pmzcTZeK4yZ0Wf/NAWGM48zaq2HJ admin@bench".parse()?;
//! assert_eq!(key.fingerprint().to_string(), "SHA256:/7MVDOe0auFFSFk/9EBpTvK7defzpFI3ccbS8WyAmiU");
//!
//! let mut file = AuthorisedKeys::parse("").with_header("Managed by the operator's tools.");
//! assert!(file.add(Entry::new(key).with_provenance(Provenance::new("admin", None))));
//! assert!(file.to_string().contains("# added by admin\nssh-ed25519 "));
//! # Ok::<(), wslib_ssh_keys::Error>(())
//! ```

use std::fmt;

mod file;
mod fingerprint;
mod key;

pub use file::{AuthorisedKeys, Entry, Provenance};
pub use fingerprint::Fingerprint;
pub use key::{Key, KeyOption, KeyType};

/// Why a line is not a key sshd would accept, worded for whoever pasted it.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    Empty,
    PrivateKey,
    MultipleLines,
    UnsupportedType(String),
    BadOptions(String),
    MissingBlob(KeyType),
    Base64,
    Malformed,
    TypeMismatch { line: KeyType, blob: String },
    RsaSize(u32),
    NotAFingerprint,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("there is no key on the line"),
            Self::PrivateKey => f.write_str(
                "that is a private key: use the public half, the file ending in `.pub`, \
                 which starts `ssh-ed25519` or `ssh-rsa`",
            ),
            Self::MultipleLines => {
                f.write_str("a public key is a single line; this has more than one")
            }
            Self::UnsupportedType(name) if name == "ssh-dss" => {
                f.write_str("ssh-dss keys are DSA, which OpenSSH has refused by default since 7.0")
            }
            Self::UnsupportedType(name) => {
                write!(f, "`{name}` is not a supported key type; supported: ")?;
                let names: Vec<_> = KeyType::ALL.iter().map(|t| t.name()).collect();
                f.write_str(&names.join(", "))
            }
            Self::BadOptions(why) => write!(f, "the key options are not as sshd reads them: {why}"),
            Self::MissingBlob(key_type) => {
                write!(f, "`{key_type}` is not followed by any key data")
            }
            Self::Base64 => {
                f.write_str("the key data is not valid base64; it is most likely truncated")
            }
            Self::Malformed => {
                f.write_str("the key data is malformed; it is most likely truncated")
            }
            Self::TypeMismatch { line, blob } => write!(
                f,
                "the line says `{line}` but the key data says `{blob}`; the paste is probably \
                 incomplete"
            ),
            Self::RsaSize(bits) => write!(
                f,
                "the RSA key has {bits} bits, and sshd accepts 1024 to 16384"
            ),
            Self::NotAFingerprint => f.write_str("not an OpenSSH `SHA256:` fingerprint"),
        }
    }
}

impl std::error::Error for Error {}
