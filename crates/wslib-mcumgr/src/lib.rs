//! An SMP (mcumgr) client, written to Zephyr's SMP Protocol Specification:
//! the frame codec, a [`Session`] for the OS, image and file system groups,
//! and the [`Transport`] it runs over.

mod error;
mod frame;
mod fs;
mod header;
mod image;
mod router;
mod session;
mod transport;

#[cfg(feature = "ble")]
pub mod ble;
#[cfg(feature = "udp")]
pub mod udp;

pub use error::Error;
pub use fs::{FsHash, FsHashAlgorithm, FsProgress, FsVerification};
pub use header::{Group, HEADER_LEN, Header, Op, Version};
pub use image::{ImageSlot, UploadOptions, UploadProgress};
pub use session::{McumgrParams, Session};
pub use transport::{BoxFuture, Transport};
