//! The listeners under an axum app: plain HTTP, TLS with h1 and h2, and a
//! redirect to the TLS port, each held to its own [`Bounds`] and drained once a
//! stop future completes.
//!
//! The crate enables no rustls crypto provider and never reads the process
//! default: the app builds its `ServerConfig` on the provider it chose.

mod bounded;
mod deciding;
mod redirect;
mod tls;

use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use axum::Router;
use axum::extract::connect_info::IntoMakeServiceWithConnectInfo;
use axum::http::{Request, StatusCode, header};
use axum::response::Response;
use axum_server::tls_rustls::RustlsAcceptor;
use axum_server::{Handle, Server};
use hyper_util::rt::{TokioExecutor, TokioTimer};
use hyper_util::server::conn::auto::{Builder, Http1Builder};
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;
use tower::util::MapResponse;

pub use bounded::{Bounds, Listener};
pub use redirect::{redirect_router, serve_redirect};
pub use tls::{PeerCertificates, Tls, server_config_from_pem, server_config_from_pem_files};

use bounded::Peer;
use deciding::Deciding;
use tls::Identifying;

const H2_STREAMS: u32 = 32;
// hyper's default is 400 KB per stream, so an unread response could cost a
// peer that much times the stream and connection caps.
const H2_SEND_BUFFER: usize = 64 * 1024;
const H2_KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(20);
const H2_KEEP_ALIVE_TIMEOUT: Duration = Duration::from_secs(10);

/// Serve `router` over plain HTTP on `listener` until `stop` completes and it
/// has drained.
pub async fn serve_http(
    listener: Listener,
    router: Router,
    stop: impl Future<Output = ()>,
) -> io::Result<()> {
    let bounds = listener.bounds;
    tracing::info!(address = %listener.local_addr(), "listening");
    let handle = Handle::new();
    let server = bound(Server::from_listener(listener), bounds.head).handle(handle.clone());
    until_stopped(server.serve(app(router)), handle, stop, bounds.grace).await
}

/// Serve `router` over TLS on `listener` until `stop` completes and it has
/// drained. Handlers get [`PeerCertificates`] as an extension.
pub async fn serve_https(
    listener: Listener,
    router: Router,
    tls: Tls,
    stop: impl Future<Output = ()>,
) -> io::Result<()> {
    let bounds = listener.bounds;
    tracing::info!(address = %listener.local_addr(), "listening");
    let handle = Handle::new();
    let acceptor = Identifying(RustlsAcceptor::new(tls.config()).handshake_timeout(bounds.head));
    let server = bound(
        Server::from_listener(listener).acceptor(acceptor),
        bounds.head,
    )
    .handle(handle.clone());
    until_stopped(server.serve(app(router)), handle, stop, bounds.grace).await
}

/// A TLS listener and, if asked for, the redirect to it, served together.
pub struct Https {
    listener: Listener,
    redirect: Option<Listener>,
    tls: Tls,
    port: watch::Sender<u16>,
}

impl Https {
    /// Serve `tls` on `listener`, with no redirect.
    pub fn new(listener: Listener, tls: Tls) -> Self {
        Self {
            port: watch::Sender::new(listener.local_addr().port()),
            listener,
            redirect: None,
            tls,
        }
    }

    /// Redirect every request on `listener` to the TLS port.
    pub fn redirect_from(mut self, listener: Listener) -> Self {
        self.redirect = Some(listener);
        self
    }

    /// The TLS port being served.
    pub fn port(&self) -> watch::Receiver<u16> {
        self.port.subscribe()
    }

    /// Serve `router` until `stop` completes and both listeners have drained,
    /// or one fails and the other has drained.
    pub async fn serve(self, router: Router, stop: impl Future<Output = ()>) -> io::Result<()> {
        let stopping = CancellationToken::new();
        let stops_both = |served: io::Result<()>| {
            if served.is_err() {
                stopping.cancel();
            }
            served
        };
        let https = serve_https(
            self.listener,
            router,
            self.tls,
            stopping.clone().cancelled_owned(),
        );
        let redirect = async {
            let Some(listener) = self.redirect else {
                return Ok(());
            };
            serve_redirect(
                listener,
                self.port.subscribe(),
                stopping.clone().cancelled_owned(),
            )
            .await
        };
        let serving = async {
            tokio::join!(async { stops_both(https.await) }, async {
                stops_both(redirect.await)
            })
        };
        tokio::pin!(serving, stop);
        let (https, redirect) = tokio::select! {
            served = &mut serving => served,
            () = &mut stop => {
                stopping.cancel();
                serving.await
            }
        };
        https.and(redirect)
    }
}

type App =
    IntoMakeServiceWithConnectInfo<MapResponse<Router, fn(Response) -> Response>, SocketAddr>;

fn app(router: Router) -> App {
    let service = tower::ServiceExt::<Request<axum::body::Body>>::map_response(
        router,
        bodiless_unlengthed as fn(Response) -> Response,
    );
    axum::ServiceExt::<Request<axum::body::Body>>::into_make_service_with_connect_info(service)
}

// RFC 9110 §8.6: axum writes `Content-Length` on every empty body, outside any
// layer, and hyper drops it from a 204 or 304 on http/1.1 but sends it on h2.
fn bodiless_unlengthed(mut response: Response) -> Response {
    if matches!(
        response.status(),
        StatusCode::NO_CONTENT | StatusCode::NOT_MODIFIED
    ) {
        response.headers_mut().remove(header::CONTENT_LENGTH);
    }
    response
}

fn bound<Acc>(server: Server<Peer, Acc>, head: Duration) -> Server<Peer, Deciding<Acc>> {
    let mut server = server.map(|acceptor| Deciding::within(acceptor, head));
    server
        .http_builder()
        .http2()
        .timer(TokioTimer::new())
        .max_concurrent_streams(H2_STREAMS)
        .max_send_buf_size(H2_SEND_BUFFER)
        .keep_alive_interval(H2_KEEP_ALIVE_INTERVAL)
        .keep_alive_timeout(H2_KEEP_ALIVE_TIMEOUT);
    head_within(server.http_builder(), head);
    server
}

// hyper panics the connection task when a timeout is set without a timer.
fn head_within(
    builder: &mut Builder<TokioExecutor>,
    head: Duration,
) -> Http1Builder<'_, TokioExecutor> {
    let mut http1 = builder.http1();
    http1.timer(TokioTimer::new()).header_read_timeout(head);
    http1
}

async fn until_stopped(
    serving: impl Future<Output = io::Result<()>>,
    handle: Handle<Peer>,
    stop: impl Future<Output = ()>,
    grace: Duration,
) -> io::Result<()> {
    tokio::pin!(serving);
    tokio::select! {
        served = &mut serving => return served,
        () = stop => {}
    }
    let stopping = tokio::time::Instant::now();
    handle.graceful_shutdown(Some(grace));
    let served = serving.await;
    if stopping.elapsed() >= grace {
        tracing::warn!(?grace, "closed connections still open at the grace period");
    }
    served
}
