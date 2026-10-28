//! An appliance backup on any backend: the sealed file, what goes in it, the
//! routes that take and restore one, and the schedule that writes them.
//!
//! A product implements [`Sections`] here whichever backend it runs on.
//! A backend with no accounts mounts [`LocalBackups`].
//! A product serving its own accounts, on `wslib-appliance-https`, mounts [`SessionBackups`].
//! An app behind a console serves [`LocalBackups::hooks`] to it, and
//! [`LocalBackups::proxied_routes`] to the administrators it asserts.
//! A host with a host half, and the factory reset beside it, builds on `backend`.

mod envelope;
mod error;
mod hooks;
mod local;
mod routes;
mod schedule;
mod sections;
mod session;
mod snapshot;
mod tick;
#[cfg(test)]
mod watching;

pub use error::BackupError;
pub use local::LocalBackups;
pub use sections::Sections;
pub use session::SessionBackups;
pub use snapshot::{Bundle, Snapshot};

/// What an appliance's own backups are built from, and a product never names.
#[doc(hidden)]
pub mod backend {
    pub use crate::routes::{
        BackupsState, Engine, HostHalf, PASSPHRASE_SECRET, reload_outbound_trust,
    };
    pub use crate::snapshot::check_passphrase;
}

#[cfg(test)]
fn install_test_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}
