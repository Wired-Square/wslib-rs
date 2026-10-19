//! One error body on the wire, `{"error": <sentence>, "code"?: <snake_case>, ...}`,
//! and the error that answers it.

mod body;

pub use body::ApiErrorBody;
