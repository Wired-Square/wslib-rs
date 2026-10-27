//! Listening: TLS on the network, a redirect beside it, and the control socket.
//! The socket's authority is a request extension only `wslib-appliance-core`'s
//! `control` module inserts. The redirect serves no routes, only a 307 to the
//! TLS port. Each network listener has its own connection cap, so neither can
//! spend the descriptors the socket needs. All three drain on one token, the
//! root of every [`Server::shutdown`](crate::Server::shutdown) handle, which is
//! cancelled before the drain.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::Router;
use axum_server::tls_rustls::RustlsConfig;
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;
use wslib_appliance_config::Bootstrap;
use wslib_appliance_core::ControlRouter;
use wslib_appliance_core::backend::{self, ControlEndpoint, foreign, serve_control};
use wslib_appliance_store::Store;
use wslib_appliance_types::Role;
use wslib_http_server::{Bounds, Listener, Tls};

use crate::ServeError;

/// The configured port, or the OS's pick for 0 once bound.
#[derive(Debug, Clone)]
pub(crate) struct HttpsPort(Arc<watch::Sender<u16>>);

impl HttpsPort {
    pub(crate) fn new(port: u16) -> Self {
        Self(Arc::new(watch::Sender::new(port)))
    }

    pub(crate) fn current(&self) -> u16 {
        *self.0.borrow()
    }

    #[cfg(any(test, feature = "testing"))]
    pub(crate) fn set(&self, port: u16) {
        self.0.send_replace(port);
    }
}

impl backend::Listening for HttpsPort {
    fn https_port(&self) -> watch::Receiver<u16> {
        self.0.subscribe()
    }
}

/// Serve until `stop` and the drain; `root` fires on every return.
pub(crate) async fn run(
    https: Router,
    local: ControlRouter,
    bootstrap: &Bootstrap,
    port: HttpsPort,
    tls: RustlsConfig,
    root: CancellationToken,
    stop: impl Future<Output = ()>,
) -> Result<(), ServeError> {
    let _stopped = root.clone().drop_guard();

    let address = SocketAddr::new(bootstrap.bind_address, bootstrap.https_port);
    let redirect = bootstrap
        .redirect_port
        .map(|port| SocketAddr::new(bootstrap.bind_address, port));
    let serving = port.0.subscribe();

    #[cfg(unix)]
    if let Some(dir) = bootstrap.socket.parent() {
        std::fs::create_dir_all(dir).map_err(|e| ServeError::Socket {
            path: bootstrap.socket.clone(),
            because: e.to_string(),
        })?;
    }

    // The first listener to fail stops the appliance, rather than leaving it half up.
    let listening = async {
        tokio::try_join!(
            serve_tls(port, address, https, tls, root.clone()),
            serve_redirect(redirect, serving, root.clone()),
            serve_control(
                local,
                vec![ControlEndpoint::new(&bootstrap.socket, Role::Admin)],
                root.clone()
            ),
        )
        .map(drop)
    };
    backend::until_stop(listening, &root, stop).await
}

/// Records the bound port in `port`.
pub(crate) async fn serve_tls(
    port: HttpsPort,
    address: SocketAddr,
    router: Router,
    tls: RustlsConfig,
    stop: CancellationToken,
) -> Result<(), ServeError> {
    let listener = Listener::bind(address, Bounds::SERVING)
        .await
        .map_err(|e| bind_failed(address, &e))?;
    port.0.send_replace(listener.local_addr().port());
    wslib_http_server::serve_https(listener, router, Tls::from(tls), stop.cancelled_owned())
        .await
        .map_err(|e| ServeError::Serving(foreign(&e)))
}

/// `address` is `None` when the redirect is off: the default, and what
/// `redirect_port = 0` resolves to.
async fn serve_redirect(
    address: Option<SocketAddr>,
    https_port: watch::Receiver<u16>,
    stop: CancellationToken,
) -> Result<(), ServeError> {
    let Some(address) = address else {
        return Ok(());
    };
    let listener = Listener::bind(address, Bounds::REDIRECT)
        .await
        .map_err(|e| bind_failed(address, &e))?;
    wslib_http_server::serve_redirect(listener, https_port, stop.cancelled_owned())
        .await
        .map_err(|e| ServeError::Serving(foreign(&e)))
}

/// A port an earlier release's Settings moved the listener to, if not the
/// configured one, warned of and not honoured.
pub(crate) async fn moved_port(store: &Store, configured: u16) -> Option<u16> {
    let moved = store
        .box_state("https.port")
        .await
        .ok()??
        .parse()
        .ok()
        .filter(|&moved| moved != configured)?;
    tracing::warn!(
        moved,
        configured,
        "the HTTPS port was moved to {moved} from Settings, and a moved port is no longer honoured; serving on the configured {configured}; to keep {moved}, set https_port = {moved} in config.toml"
    );
    Some(moved)
}

fn bind_failed(address: SocketAddr, e: &std::io::Error) -> ServeError {
    ServeError::Bind {
        address: address.to_string(),
        because: foreign(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::path::{Path, PathBuf};
    use std::time::Duration;
    use tempfile::TempDir;
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};

    /// Its control socket's parent is a file (on Windows, not a pipe name).
    fn unbindable_bootstrap(dir: &Path) -> Bootstrap {
        let blocked = dir.join("not-a-directory");
        std::fs::write(&blocked, "").expect("write");
        bootstrap(dir, blocked.join("control.sock"))
    }

    /// Loopback on ports the OS picks.
    fn bootstrap(dir: &Path, socket: PathBuf) -> Bootstrap {
        let config = dir.join("config.toml");
        std::fs::write(&config, "").expect("write");
        let pair = wslib_appliance_config::Tls::default_in(dir);
        wslib_appliance_config::Resolver::new("test", "APPLIANCE_HTTPS_TEST_ONLY")
            .serving(&wslib_appliance_config::ServingArgs {
                bind_address: Some(Ipv4Addr::LOCALHOST.into()),
                https_port: Some(0),
                redirect_port: Some(0),
                tls_cert: Some(pair.cert),
                tls_key: Some(pair.key),
            })
            .resolve(&wslib_appliance_config::ApplianceArgs {
                config: Some(config),
                db: Some(dir.join("db")),
                socket: Some(socket),
                ..Default::default()
            })
            .expect("resolves")
    }

    /// Kind, flags, payload.
    async fn frame(peer: &mut (impl AsyncRead + Unpin)) -> (u8, u8, Vec<u8>) {
        let mut head = [0u8; 9];
        peer.read_exact(&mut head).await.expect("a frame header");
        let length = u32::from_be_bytes([0, head[0], head[1], head[2]]) as usize;
        let mut payload = vec![0u8; length];
        peer.read_exact(&mut payload)
            .await
            .expect("a frame payload");
        (head[3], head[4], payload)
    }

    /// A connection to [`serve_tls`] that has negotiated h2.
    async fn production_h2(dir: &Path) -> tokio_rustls::client::TlsStream<tokio::net::TcpStream> {
        crate::install_test_provider();
        let tls = backend::minted_in(dir).await;
        let port = HttpsPort::new(0);
        let mut bound = port.0.subscribe();
        tokio::spawn(serve_tls(
            port,
            (Ipv4Addr::LOCALHOST, 0).into(),
            Router::new(),
            backend::tls_config(&tls),
            CancellationToken::new(),
        ));
        let port = *bound.wait_for(|&port| port != 0).await.expect("binds");
        crate::tests::dial_tls(dir, (Ipv4Addr::LOCALHOST, port).into(), Some(b"h2")).await
    }

    /// The production wiring negotiates h2 and answers over it.
    #[tokio::test]
    async fn the_tls_listener_announces_its_stream_cap_and_answers() {
        const WSLIB_HTTP_SERVER_H2_STREAMS: u32 = 32;
        const HEADERS: u8 = 0x1;
        const END_STREAM_AND_HEADERS: u8 = 0x5;
        const SETTINGS: u8 = 0x4;
        const MAX_CONCURRENT_STREAMS: u16 = 0x3;
        // HPACK's static table: `:method GET`, `:scheme https`, `:path /`, then
        // `:authority` by index with a literal `box`.
        const GET_ROOT: [u8; 8] = [0x82, 0x87, 0x84, 0x01, 3, b'b', b'o', b'x'];
        const STATUS_404: u8 = 0x8d;

        let dir = TempDir::new().expect("a directory");
        let mut peer = production_h2(dir.path()).await;
        peer.write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
            .await
            .expect("the h2 preface");
        peer.write_all(&[0, 0, 0, SETTINGS, 0, 0, 0, 0, 0])
            .await
            .expect("an empty SETTINGS");

        let announced = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let (kind, _, payload) = frame(&mut peer).await;
                let found = (kind == SETTINGS)
                    .then(|| {
                        payload.as_chunks::<6>().0.iter().find(|setting| {
                            u16::from_be_bytes([setting[0], setting[1]]) == MAX_CONCURRENT_STREAMS
                        })
                    })
                    .flatten();
                if let Some(setting) = found {
                    break u32::from_be_bytes([setting[2], setting[3], setting[4], setting[5]]);
                }
            }
        })
        .await
        .expect("the server announces its settings");

        assert_eq!(announced, WSLIB_HTTP_SERVER_H2_STREAMS);

        let length = u8::try_from(GET_ROOT.len()).expect("a short block");
        peer.write_all(&[0, 0, length, HEADERS, END_STREAM_AND_HEADERS, 0, 0, 0, 1])
            .await
            .expect("a request's headers");
        peer.write_all(&GET_ROOT).await.expect("the header block");

        let answered = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let (kind, _, payload) = frame(&mut peer).await;
                if kind == HEADERS {
                    break payload;
                }
            }
        })
        .await
        .expect("the connection is still alive to answer a request");

        assert_eq!(answered.first(), Some(&STATUS_404), "{answered:?}");
    }

    /// A start that fails takes every consumer task with it, without anything
    /// having to remember to cancel on the error path.
    #[tokio::test]
    async fn an_error_exit_from_serving_fires_the_handle_too() {
        crate::install_test_provider();
        let dir = TempDir::new().expect("a directory");
        let tls = backend::minted_in(&dir).await;
        let bootstrap = unbindable_bootstrap(dir.path());

        let stop = CancellationToken::new();
        let consumer = stop.child_token();
        let outcome = run(
            Router::new(),
            ControlRouter::empty(),
            &bootstrap,
            HttpsPort::new(bootstrap.https_port),
            backend::tls_config(&tls),
            stop,
            std::future::pending(),
        )
        .await;

        assert!(outcome.is_err(), "{outcome:?}");
        assert!(consumer.is_cancelled());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn serving_is_ready_once_listening_and_ends_ok_at_the_stop() {
        let dir = TempDir::new().expect("a directory");
        let socket = dir.path().join("control.sock");
        let bootstrap = bootstrap(dir.path(), socket.clone());
        let store = Store::open_in_memory(None).await.expect("store");
        let branding = wslib_appliance_types::Branding::unbranded();
        let server = crate::Server::new(store, branding, "0.0.0", crate::logs(&[]));
        let (stop, manager) = wslib_service::testing::stop();
        let serving = tokio::spawn(async move { server.serve(&bootstrap, stop).await });
        tokio::time::timeout(crate::tests::WITHIN, manager.ready())
            .await
            .expect("ready once listening");
        tokio::net::UnixStream::connect(&socket)
            .await
            .expect("the control socket listens by the time it is ready");

        manager.stop();
        let served = tokio::time::timeout(crate::tests::WITHIN, serving)
            .await
            .expect("drained in time")
            .expect("joined");
        assert!(served.is_ok(), "{served:?}");
    }

    #[tokio::test]
    async fn a_port_moved_from_settings_is_reported_only_when_it_differs() {
        let store = Store::open_in_memory(None).await.expect("store");
        assert_eq!(moved_port(&store, 8443).await, None);
        for (kept, moved) in [("8443", None), ("9443", Some(9443))] {
            store.set_box_state("https.port", kept).await.expect("set");
            assert_eq!(moved_port(&store, 8443).await, moved, "{kept}");
        }
    }
}
