//! A Docker Engine client over its Unix socket: inspect, create, start, stop
//! and remove containers, networks and images, and load or pull images, with
//! errors that keep an engine that isn't there, one that doesn't answer and
//! one that refuses apart.
//!
//! ```no_run
//! # async fn run() -> Result<(), wslib_docker::DockerError> {
//! let docker = wslib_docker::Docker::default();
//! let busybox = wslib_docker::ImageReference::parse("busybox:1.37").unwrap();
//! let pulled = docker.pull(&busybox).await?;
//! if docker.container("hello").await?.is_none() {
//!     let spec = serde_json::json!({"Image": pulled});
//!     docker.create("hello", &spec).await?;
//! }
//! docker.start("hello").await?;
//! # Ok(())
//! # }
//! ```
//!
//! The `testing` feature adds [`testing::FakeEngine`]. Without the default
//! `client` feature, only [`ImageReference`] is left, with no dependencies.

#[cfg(feature = "client")]
mod client;
mod reference;
#[cfg(feature = "testing")]
pub mod testing;
#[cfg(feature = "client")]
pub mod trust;

#[cfg(feature = "client")]
pub use client::{Body, Docker, DockerError, empty, exchange};
#[cfg(feature = "client")]
pub use hyper::{Method, Request, StatusCode, header};
pub use reference::{ImageReference, Pin};
