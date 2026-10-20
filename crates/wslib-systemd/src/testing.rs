//! In-process fakes of D-Bus services, served over a socket pair.
//!
//! ```no_run
//! # async fn run() -> zbus::Result<()> {
//! struct Timesyncd;
//!
//! #[zbus::interface(name = "org.freedesktop.timesync1.Manager")]
//! impl Timesyncd {
//!     #[zbus(property)]
//!     fn server_name(&self) -> String {
//!         "ntp.example.com".into()
//!     }
//! }
//!
//! let (client, _served) = wslib_systemd::testing::Fakes::new()
//!     .at("/org/freedesktop/timesync1", Timesyncd)
//!     .connect()
//!     .await?;
//! let timesync = wslib_systemd::TimesyncProxy::new(&client).await?;
//! assert_eq!(timesync.server_name().await?, "ntp.example.com");
//! # Ok(())
//! # }
//! ```

use zbus::connection::Builder;
use zbus::object_server::Interface;
use zbus::{Connection, Guid};

type Serve = Box<dyn FnOnce(Builder<'static>) -> zbus::Result<Builder<'static>> + Send>;

/// Fake services, each an interface object at a path, collected before they
/// are served.
#[derive(Default)]
pub struct Fakes {
    serving: Vec<Serve>,
}

impl Fakes {
    pub fn new() -> Self {
        Self::default()
    }

    /// Serves `fake` at `path`; a path that is not an object path fails
    /// [`connect`](Self::connect).
    pub fn at(mut self, path: impl Into<String>, fake: impl Interface) -> Self {
        let path = path.into();
        self.serving
            .push(Box::new(move |builder| builder.serve_at(path, fake)));
        self
    }

    /// `(client, served)`: a peer-to-peer connection to the fakes, and the
    /// fakes' own end, which must be kept alive as long as the client is used.
    pub async fn connect(self) -> zbus::Result<(Connection, Connection)> {
        let (ours, theirs) = tokio::net::UnixStream::pair()?;
        let mut served = Builder::unix_stream(theirs).server(Guid::generate())?.p2p();
        for serve in self.serving {
            served = serve(served)?;
        }
        let client = Builder::unix_stream(ours).p2p().build();
        let (served, client) = tokio::try_join!(served.build(), client)?;
        Ok((client, served))
    }
}
