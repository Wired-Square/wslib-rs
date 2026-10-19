//! One error body on the wire, `{"error": <sentence>, "code"?: <snake_case>, ...}`,
//! and the error that answers it.

mod body;
mod error;
#[cfg(feature = "axum")]
pub mod extract;

pub use body::ApiErrorBody;
pub use error::ApiError;
