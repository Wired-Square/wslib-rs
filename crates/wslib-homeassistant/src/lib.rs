//! An app running as a Home Assistant add-on. [`ingress`] checks that a request
//! came through the ingress proxy, and reads the caller and base path it names.
//!
//! The `testing` feature adds [`testing`]: requests as the proxy sends them.

pub mod ingress;
#[cfg(feature = "testing")]
pub mod testing;
