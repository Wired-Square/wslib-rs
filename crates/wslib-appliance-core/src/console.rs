//! An app behind a console's proxy: the app socket its routes are served on,
//! and the caller the console asserts there.
//!
//! **The header is read only behind [`ConsoleArrival`]**, set only on a
//! connection whose peer uid, read at accept, is the console's.

#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;
#[cfg(unix)]
use std::path::{Path, PathBuf};
#[cfg(any(unix, test, feature = "testing"))]
use std::sync::Arc;
#[cfg(unix)]
use std::time::Duration;

#[cfg(any(unix, test, feature = "testing"))]
use axum::Router;
#[cfg(unix)]
use axum::extract::connect_info::Connected;
#[cfg(any(unix, test, feature = "testing"))]
use axum::extract::{ConnectInfo, Request};
use axum::http::request::Parts;
#[cfg(unix)]
use axum::serve::Listener;
#[cfg(unix)]
use tokio::net::UnixStream;
#[cfg(any(unix, test, feature = "testing"))]
use tokio::sync::OwnedSemaphorePermit;
#[cfg(unix)]
use tokio::sync::Semaphore;
#[cfg(unix)]
use tokio_util::sync::CancellationToken;
use wslib_appliance_types::session::Caller;

use crate::ApiError;
#[cfg(unix)]
use crate::ServeError;
#[cfg(unix)]
use crate::bounded::Bounded;
#[cfg(unix)]
use crate::control::socket::Peers;
#[cfg(unix)]
use crate::control::{bind_socket, serve_http1};
use crate::extract::{Callers, Principal, ResolveCaller, Vouches};
use crate::hooks::asserted;

/// Longer than the control socket's: the console keeps connections open.
#[cfg(unix)]
pub(crate) const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(10);

/// Connections held at once from anybody but the console, so they cannot starve it.
#[cfg(unix)]
const OTHERS: usize = 4;

/// Proof that a request arrived on the app socket from the console's uid.
#[derive(Clone)]
#[cfg_attr(not(unix), allow(dead_code))]
pub(crate) struct ConsoleArrival;

/// An app-socket peer's uid and, for anybody but the console, its slot among `OTHERS`.
#[derive(Clone)]
#[cfg(any(unix, test, feature = "testing"))]
pub(crate) struct Peer {
    uid: Option<u32>,
    _slot: Option<Arc<OwnedSemaphorePermit>>,
}

#[cfg(unix)]
impl Connected<Bounded<AppPeers>> for Peer {
    fn connect_info(peer: Bounded<AppPeers>) -> Self {
        peer.address
    }
}

/// The only place [`ConsoleArrival`] is created.
#[cfg(any(unix, test, feature = "testing"))]
fn marked(router: Router, console_uid: u32) -> Router {
    router.layer(axum::middleware::map_request(
        move |mut request: Request| async move {
            let peer = request.extensions().get::<ConnectInfo<Peer>>();
            if peer.is_some_and(|ConnectInfo(Peer { uid, .. })| *uid == Some(console_uid)) {
                request.extensions_mut().insert(ConsoleArrival);
            }
            request
        },
    ))
}

/// `router` as a connection from `uid` reaches it on a socket whose console is
/// `console_uid`.
#[cfg(any(test, feature = "testing"))]
pub(crate) fn arriving_from(router: Router, uid: u32, console_uid: u32) -> Router {
    let peer = Peer {
        uid: Some(uid),
        _slot: None,
    };
    marked(router, console_uid).layer(axum::Extension(ConnectInfo(peer)))
}

struct Asserted;

impl ResolveCaller for Asserted {
    async fn resolve(&self, request: &Parts) -> Result<Option<Principal>, ApiError> {
        if request.extensions.get::<ConsoleArrival>().is_none() {
            return Ok(None);
        }
        Ok(asserted(&request.headers)?.map(|identity| Principal {
            id: format!("{ID_PREFIX}{}", identity.id),
            username: identity.username,
            role: identity.role,
            reauthenticated_at: identity.reauthenticated_at,
        }))
    }
}

/// Keeps the console's ids apart from the store's in the audit log's `actor_id`.
pub(crate) const ID_PREFIX: &str = "console:";

/// What `GET /api/session` answers for a principal an asserting resolver
/// vouched for under `prefix`.
pub(crate) fn asserted_caller(principal: Principal, prefix: &str) -> Caller {
    Caller::Console {
        id: principal
            .id
            .strip_prefix(prefix)
            .unwrap_or(&principal.id)
            .to_string(),
        username: principal.username,
        role: principal.role,
    }
}

impl Callers {
    /// The caller the console asserts in [`IDENTITY_HEADER`], on a request
    /// `serve_app_socket` marked as the console's.
    pub fn asserted_by_console() -> Self {
        Self {
            vouches: Vouches::Console,
            ..Self::resolved_by(Asserted)
        }
    }
}

/// Serve `router` on a Unix socket at `path` until `stop` and the grace after
/// it, marking a connection whose peer uid is `console_uid` as the console's.
/// `path` must be a filesystem path in an existing directory; the socket is `0660`.
/// A `console_uid` that is the overflow uid is refused.
#[cfg(unix)]
pub async fn serve_app_socket(
    router: Router,
    path: PathBuf,
    console_uid: u32,
    stop: CancellationToken,
) -> Result<(), ServeError> {
    let path = path.as_path();
    refuse_unusable(path, console_uid)?;
    let (listener, _unlink) = bind_socket(path)?;
    tracing::info!(path = %path.display(), console_uid, "app socket listening");
    let peers = AppPeers {
        peers: Peers(listener),
        console_uid,
        others: Arc::new(Semaphore::new(OTHERS)),
    };
    serve_http1::<AppPeers, Peer>(
        peers,
        marked(router, console_uid),
        HEADER_READ_TIMEOUT,
        stop,
    )
    .await
}

#[cfg(unix)]
pub(crate) fn refuse_unusable(path: &Path, console_uid: u32) -> Result<(), ServeError> {
    let refused = |because: String| ServeError::Socket {
        path: path.to_path_buf(),
        because,
    };
    if path.as_os_str().as_bytes().first().is_none_or(|&b| b == 0) {
        return Err(refused(
            "a socket the console connects to is a filesystem path: not empty, never the \
             abstract namespace"
                .to_string(),
        ));
    }
    if is_overflow(console_uid) {
        return Err(refused(format!(
            "console uid {console_uid} is the overflow uid, which under userns-remap every \
             process outside the namespace appears as, so it cannot tell the console apart"
        )));
    }
    Ok(())
}

/// Whether `uid` is the one an unmapped uid appears as inside a user namespace.
#[cfg(unix)]
fn is_overflow(uid: u32) -> bool {
    #[cfg(target_os = "linux")]
    let kernel = std::fs::read_to_string("/proc/sys/fs/overflowuid")
        .ok()
        .and_then(|uid| uid.trim().parse().ok());
    #[cfg(not(target_os = "linux"))]
    let kernel = None;
    uid == 65534 || kernel == Some(uid)
}

/// The app socket's connections: every one from the console, and at most
/// [`OTHERS`] at once from anybody else, the rest closed as they arrive.
#[cfg(unix)]
struct AppPeers {
    peers: Peers,
    console_uid: u32,
    others: Arc<Semaphore>,
}

#[cfg(unix)]
impl Listener for AppPeers {
    type Io = UnixStream;
    type Addr = Peer;

    async fn accept(&mut self) -> (UnixStream, Peer) {
        loop {
            let (stream, uid) = Listener::accept(&mut self.peers).await;
            if uid == Some(self.console_uid) {
                return (stream, Peer { uid, _slot: None });
            }
            if let Ok(slot) = Arc::clone(&self.others).try_acquire_owned() {
                let _slot = Some(Arc::new(slot));
                return (stream, Peer { uid, _slot });
            }
        }
    }

    fn local_addr(&self) -> std::io::Result<Peer> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "an app socket is named by its path",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::probe::{Probe, WHO};
    use crate::testing::{Req, body_text};
    use axum::http::StatusCode;
    use wslib_appliance_types::console::IDENTITY_HEADER;

    const CONSOLE: u32 = 4242;

    fn asserting(role: &str) -> String {
        format!("v1; id=a1; user=ops; role={role}")
    }

    async fn console_probe() -> Probe {
        Probe::with_callers(Callers::asserted_by_console(), true).await
    }

    #[tokio::test]
    async fn the_header_is_read_only_on_a_request_from_the_consoles_uid() {
        let probe = console_probe().await;
        let from = |uid| arriving_from(probe.https.clone(), uid, CONSOLE);
        let ask = |router| {
            Req::new(router, "GET", WHO)
                .header(IDENTITY_HEADER, &asserting("viewer"))
                .send()
        };
        let console = ask(from(CONSOLE)).await;
        assert_eq!(console.status(), StatusCode::OK);
        assert_eq!(body_text(console).await, "ops");
        for router in [from(CONSOLE + 1), probe.https.clone()] {
            assert_eq!(ask(router).await.status(), StatusCode::UNAUTHORIZED);
        }
    }

    #[tokio::test]
    async fn no_header_is_nobody_and_a_malformed_one_is_a_bad_request() {
        let probe = console_probe().await;
        let console = || arriving_from(probe.https.clone(), CONSOLE, CONSOLE);
        let bare = Req::new(console(), "GET", WHO).send().await;
        assert_eq!(bare.status(), StatusCode::UNAUTHORIZED);
        for value in ["v1; id=a; user=control-socket:root; role=admin", "v2", ""] {
            let response = Req::new(console(), "GET", WHO)
                .header(IDENTITY_HEADER, value)
                .send()
                .await;
            assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{value:?}");
        }
        let twice = Req::new(console(), "GET", WHO)
            .header(IDENTITY_HEADER, &asserting("admin"))
            .header(IDENTITY_HEADER, &asserting("admin"))
            .send()
            .await;
        assert_eq!(twice.status(), StatusCode::BAD_REQUEST);
    }
}
