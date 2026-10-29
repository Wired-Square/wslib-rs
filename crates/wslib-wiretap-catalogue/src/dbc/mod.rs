//! DBC import/export — convert between the WireTAP TOML catalogue format and
//! Vector DBC.
//!
//! Both are self-contained (only `can_dbc`, `toml` and `std`), and operate on
//! TOML text, not the unified [`crate::Catalogue`] model.

pub mod export;
pub mod import;

pub use export::{MuxExportMode, render_catalogue_as_dbc, render_catalogue_as_dbc_with_mode};
pub use import::convert_dbc_to_toml;
