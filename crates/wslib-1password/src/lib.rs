//! The 1Password CLI, `op`, typed: sign-in, accounts, vaults, items, documents,
//! `op://` references and `op inject`, with `op`'s failures as [`Error`]s.
//!
//! ```no_run
//! # fn run() -> Result<(), wslib_1password::Error> {
//! use wslib_1password::{Assignment, FieldType, ItemRef, Op, ShellRunner};
//!
//! let op = Op::new(ShellRunner::new(), "my.1password.com");
//! op.sign_in()?;
//! let vault = op.open_vault("Deploy")?;
//! let key = match vault.items_titled("Signing key")?.first() {
//!     Some(found) => ItemRef::from(found),
//!     None => ItemRef::from(&vault.create_item("Signing key", "Secure Note", &[
//!         Assignment::set("private_key", FieldType::Password, "-----BEGIN PRIVATE KEY-----…"),
//!     ])?),
//! };
//! let pem = vault.item(&key)?.value("private_key").cloned();
//! # Ok(())
//! # }
//! ```
//!
//! Every call blocks until `op` answers, up to [`ShellRunner`]'s timeout; the
//! `tokio` feature adds [`tokio::blocking`]. The `testing` feature adds
//! [`testing::FakeRunner`].

mod assignment;
mod error;
mod op;
mod reference;
mod runner;
#[cfg(feature = "testing")]
pub mod testing;
#[cfg(feature = "tokio")]
pub mod tokio;
mod types;

use std::path::PathBuf;

pub use assignment::{Assignment, FieldType};
pub use error::{Error, map_cli_error};
pub use op::{Op, Vault, accounts, find_account};
pub use reference::{ReadReference, is_reference, resolve};
pub use runner::{Call, Output, Runner, ShellRunner};
pub use types::{
    Account, AccountInfo, Field, Item, ItemRef, ItemSummary, SecretBytes, Section, User, VaultInfo,
    WhoAmI, is_item_id,
};
pub use wslib_secret::Secret;

/// Where `op` is on `PATH`, if it is.
pub fn cli_path() -> Option<PathBuf> {
    let name = if cfg!(windows) { "op.exe" } else { "op" };
    std::env::split_paths(&std::env::var_os("PATH")?)
        .map(|dir| dir.join(name))
        .find(|path| is_executable(path))
}

#[cfg(unix)]
fn is_executable(path: &std::path::Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    path.metadata()
        .is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
}

#[cfg(not(unix))]
fn is_executable(path: &std::path::Path) -> bool {
    path.is_file()
}
