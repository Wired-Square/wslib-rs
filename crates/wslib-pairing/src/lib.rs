//! Primitives for pairing a client with a daemon that serves a self-signed
//! certificate: a [`OneTimeCode`] the daemon checks and spends, and the
//! [`PairingUri`] that carries the code with the pin of the daemon's key.
//!
//! The daemon's key and chain are a `wslib_tls::Serving` pair: minted once,
//! and the chain replaced over the same key once it is signed.

mod code;
mod uri;

pub use code::{CodeError, NotACode, OneTimeCode, PairingCode, Redemption};
pub use uri::{PairingUri, UriError};
