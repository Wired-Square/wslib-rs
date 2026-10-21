//! What an app trusts when it dials out, over the caller's rustls
//! [`CryptoProvider`](rustls::crypto::CryptoProvider), and the client
//! configuration that enforces it.
//!
//! [`Outbound`]'s verifier consults the pins first: a pinned host is trusted
//! for exactly that certificate, its name and expiry unchecked, because the pin
//! *is* the identity. Any other host is verified against the operating
//! system's roots and the [`Trust`]'s authorities. Every handshake reads the
//! trust last given to [`Outbound::set_trust`], so no client is rebuilt; a
//! connection already pooled is not reached, so an app that wants a removal to
//! bite at once drops its clients on [`Outbound::subscribe`].
//!
//! **Session resumption is off**: rustls does not run the verifier on a
//! resumed handshake, so a ticket would carry a removed pin or authority on.
//!
//! **The OS store is read on a background thread**, and read again on each
//! [`Outbound::set_trust`] until a read comes back whole and non-empty, then
//! kept for the life of the [`Outbound`]. An unpinned handshake waits up to
//! 30 s for the first read. `SSL_CERT_FILE` and `SSL_CERT_DIR` replace the OS
//! store rather than add to it.
//!
//! **An authority's own dates are not checked**: a trust anchor is a name and a
//! key.
//!
//! [`Serving`] is the other direction: the pair an app's own listener serves,
//! loaded or minted at startup and replaced by an operator's PEM, as a
//! `ServerConfig` on the caller's provider. A pair that cannot be used is moved
//! aside to `*.unusable` and replaced at the app's own location, and refused at
//! one an operator named.

mod os;
mod outbound;
mod probe;
mod rejection;
mod serving;
#[cfg(any(test, feature = "testing"))]
pub mod testing;
mod trust;

pub use outbound::Outbound;
pub use probe::{Presented, ProbeError};
pub use rejection::{Cause, Rejection, cause};
pub use serving::{Installed, Location, Serving, ServingError, ServingPair};
pub use trust::{AnchorError, Trust, normalise_host};
