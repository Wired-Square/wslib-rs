//! The HTTP scaffold under an axum app: its single-page bundle, a health and a
//! version route, and the standard layers. Every refusal is a
//! [`wslib_api_error`] body.

mod spa;

pub use spa::Spa;
pub use wslib_api_error;
