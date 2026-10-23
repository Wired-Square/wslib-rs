//! The HTTP scaffold under an axum app: its single-page bundle, a health and a
//! version route, and the standard layers. Every refusal is a
//! [`wslib_http_error`] body.
//!
//! Without the default `server` feature it is [`BasePath`] alone.

mod base_path;
#[cfg(feature = "server")]
mod compress;
#[cfg(feature = "embed")]
mod embed;
#[cfg(feature = "server")]
mod layers;
#[cfg(feature = "server")]
mod routes;
#[cfg(feature = "server")]
mod spa;

pub use base_path::BasePath;
#[cfg(feature = "server")]
pub use compress::{Capped, EncoderCap, mark_stored, restore_accept_encoding};
#[cfg(feature = "server")]
pub use layers::standard_layers;
#[cfg(feature = "server")]
pub use routes::{HEALTH, VERSION, health, health_with, version};
#[cfg(feature = "server")]
pub use spa::{Spa, first_segment_is};
#[cfg(feature = "server")]
pub use wslib_http_error;
