//! Connecting to an appliance's control pipe on Windows, and refusing a pipe its
//! service does not own, since any process can create one by that name first.
//!
//! Empty on every other target, so a cross-platform client may depend on it
//! unconditionally.

#[cfg(any(windows, test))]
mod path;
#[cfg(windows)]
mod windows;

#[cfg(windows)]
pub use windows::{ConnectError, connect};
