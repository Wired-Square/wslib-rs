//! The WireTAP gateway's HTTP API, as the JSON both ends agree on.
//!
//! A field's name, type and position are the contract. Nothing but the `client`
//! feature opens a connection, and nothing touches a database.
//!
//! No type refuses unknown fields, so a newer gateway can add one without
//! breaking an older client. Enum-like strings (`endianness`, `dir`,
//! `schema_state`, `rollup_state`, `source`, `reason`) stay `String` for the
//! same reason.

pub mod activity;
pub mod admin;
pub mod archive;
#[cfg(feature = "client")]
pub mod client;
pub mod events;
pub mod params;
pub mod query;
pub mod request;
pub mod server;
pub mod spec;

pub use activity::*;
pub use admin::*;
pub use archive::*;
pub use events::*;
pub use params::*;
pub use query::*;
pub use request::*;
pub use server::*;
pub use spec::*;
