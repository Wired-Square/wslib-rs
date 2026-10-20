//! Typed zbus proxies for systemd and its hostnamed, timedated, timesyncd and
//! logind, how to read their refusals, and hostname validation.
//!
//! ```no_run
//! # async fn run() -> zbus::Result<()> {
//! let bus = zbus::Connection::system().await?;
//! let hostname = wslib_systemd::HostnameProxy::new(&bus).await?;
//! match hostname.set_static_hostname("widget-01", false).await {
//!     Err(e) if wslib_systemd::refused(&e) => println!("not permitted"),
//!     Err(e) if wslib_systemd::nobody_owns(&e) => println!("no hostnamed here"),
//!     other => other?,
//! }
//! # Ok(())
//! # }
//! ```
//!
//! The `testing` feature adds [`testing::Fakes`], on Unix.

mod hostname;
mod proxy;
mod refusal;
#[cfg(all(unix, feature = "testing"))]
pub mod testing;

pub use hostname::{HostnameError, MAX_HOSTNAME_LEN, clean_hostname};
pub use proxy::{
    HostnameProxy, Login1Proxy, SystemdProxy, TimedateProxy, TimesyncProxy, UnitProxy, UnitRow,
};
pub use refusal::{NOBODY_OWNS_IT, REFUSALS, error_is, nobody_owns, refused};
