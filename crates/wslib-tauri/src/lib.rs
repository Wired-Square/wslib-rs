//! Pieces for Tauri desktop apps.
//!
//! - [`quit_guard`]: a plugin that holds a quit until the app's in-flight work
//!   has finished, then exits on its own.

pub mod quit_guard;
