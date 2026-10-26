//! The appliance family in one dependency. Every `wslib-appliance*` crate is
//! released at this crate's version, and this one pins each exactly.

pub use wslib_appliance_config as config;
pub use wslib_appliance_types as types;
