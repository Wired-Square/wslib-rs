//! The HTTP scaffold under an axum app: its single-page bundle, a health and a
//! version route, and the standard layers. Every refusal is a
//! [`wslib_http_error`] body.

mod base_path;
mod compress;
#[cfg(feature = "embed")]
mod embed;
mod layers;
mod routes;
mod spa;

pub use base_path::BasePath;
pub use compress::{Capped, EncoderCap};
pub use layers::standard_layers;
pub use routes::{HEALTH, VERSION, health, health_with, version};
pub use spa::Spa;
pub use wslib_http_error;
