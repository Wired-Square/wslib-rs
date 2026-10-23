//! DNS-SD on the local network: validated names, adverts that withdraw on
//! drop, an in-process responder and browser (feature `in-process`), and
//! avahi over D-Bus (feature `avahi`).
//!
//! ```no_run
//! # #[cfg(all(feature = "avahi", feature = "in-process"))]
//! # async fn run() -> Result<(), Box<dyn std::error::Error>> {
//! use wslib_mdns::{Options, Responder, Service};
//!
//! let responder = Responder::system(Options::default()).await?;
//! let mut service = Service::new("_https._tcp".parse()?, "Widget".parse()?, 443);
//! service.txt.push("product=widget".parse()?);
//! let advert = responder.advertise(&service).await?;
//! let mut state = advert.state();
//! state.changed().await?;
//! println!("{:?}", *state.borrow());
//! # Ok(())
//! # }
//! ```
//!
//! The `testing` feature adds [`testing::FakeAvahi`], on Unix.

#[cfg(feature = "avahi")]
pub mod avahi;
#[cfg(feature = "in-process")]
mod in_process;
mod name;
#[cfg(all(feature = "avahi", feature = "in-process"))]
mod responder;
mod service;
#[cfg(all(unix, feature = "testing"))]
pub mod testing;

#[cfg(feature = "in-process")]
pub use in_process::{Browse, Host, InProcess, Interfaces, Options};
pub use name::{HostName, InstanceName, Invalid, Protocol, ServiceType, Subtype, Txt};
#[cfg(all(feature = "avahi", feature = "in-process"))]
pub use responder::Responder;
pub use service::{Advert, AdvertState, BrowseEvent, Error, Resolved, Service};
