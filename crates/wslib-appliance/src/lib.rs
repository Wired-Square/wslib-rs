//! The appliance family in one dependency. Every `wslib-appliance*` crate is
//! released at this crate's version, and this one pins each exactly.

#[cfg(feature = "auth")]
pub use wslib_appliance_auth as auth;
#[cfg(feature = "backup")]
pub use wslib_appliance_backup as backup;
#[cfg(feature = "client")]
pub use wslib_appliance_client as client;
pub use wslib_appliance_config as config;
#[cfg(feature = "core")]
pub use wslib_appliance_core as core;
#[cfg(feature = "https")]
pub use wslib_appliance_https as https;
#[cfg(feature = "server")]
pub use wslib_appliance_server as server;
#[cfg(feature = "service")]
pub use wslib_appliance_service as service;
#[cfg(feature = "store")]
pub use wslib_appliance_store as store;
pub use wslib_appliance_types as types;
