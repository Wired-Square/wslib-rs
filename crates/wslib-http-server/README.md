# wslib-http-server

The listeners under an axum app: plain HTTP, TLS with h1 and h2 by ALPN, a
redirect to the TLS port, and on Unix a local socket, each held to its own bounds and drained once a
stop future completes. The routes are the app's; this crate owns the sockets.

```rust
use wslib_http_server::{Bounds, Https, Listener, Tls};

let provider = Arc::new(rustls::crypto::ring::default_provider());
let config = wslib_http_server::server_config_from_pem_files(provider, &cert, &key)?;
let tls = Tls::new(config);

let https = Https::new(Listener::bind(address, Bounds::SERVING).await?, tls.clone())
    .redirect_from(Listener::bind(redirect, Bounds::REDIRECT).await?);
let port = https.port();
https.serve(app, stop.cancelled_owned()).await?;

// On a certificate install, from anywhere holding a clone:
tls.reload(new_config);
tls.renew();
```

Without TLS, `serve_http(Listener::bind(address, Bounds::SERVING).await?, app, stop)`.
`stop` is any `Future<Output = ()>`: a `CancellationToken`'s
`cancelled_owned()`, or several sources joined by the caller.

The listeners log under the `wslib_http_server` tracing target; an app that
filters by target has to include it.

## What's here

- **No crypto provider.** The crate enables none and never reads the process
  default. The app builds its `ServerConfig` on the provider it chose, with
  `server_config_from_pem` or `server_config_from_pem_files` or by hand.
  Enable exactly one provider in the binary: with two, rustls panics at the
  first handshake.
- **`Listener::bind(address, bounds)`** binds at once, so a taken port fails
  before serving and port 0 resolves; `local_addr` gives the port bound.
  `Listener::from_tcp(tcp, bounds)` holds a listener the caller bound. A bind
  error is the OS's, without context; add your own.
- **`Bounds`**: `connections` held at once, taken before `accept` so the rest
  wait in the kernel's backlog; `head`, the deadline on the TLS handshake, on
  saying which protocol the peer speaks, and on each http/1.1 request head;
  and `grace`, how long open connections get once `stop` completes.
  `Bounds::SERVING` is 16 connections, 10s and 10s; `Bounds::REDIRECT` is 8,
  5s and 10s.
- **`serve_http`** and **`serve_https`**: the router until `stop` completes
  and the listener has drained. Handlers get `ConnectInfo<SocketAddr>`, and
  over TLS `Extension<PeerCertificates>`: the client's chain, leaf first, as
  the config's client verifier passed it, empty when it presented none. h2
  connections are pinged every 20s and hold at most 32 streams.
- **`Tls`**: the config a TLS listener serves. `Tls::new` offers h2 and
  http/1.1 by ALPN when the config names none; a config that names its own
  keeps them. `reload` swaps the config for new connections; clones share it.
  `renew` then drains the connections open on every `serve_https` serving
  it, as a stop would and within the same `grace`, while new ones are
  accepted: h2 peers get a GOAWAY and reconnect on the new config.
  `Tls::from(RustlsConfig)` shares a handle another owner reloads, and its
  ALPN is that owner's to set.
- **`serve_redirect(listener, https_port, stop)`**: a 307 for every request
  to `https://<host>:<port><path and query>`, the port read from the `watch`
  at each request, so it follows a TLS listener that moves. 307 keeps the
  method and body; it is not cached with the port in it. http/1.1 only, and
  each connection is closed after its answer. `redirect_router(https_port)`
  is the same answer as a `Router`, to test in-process.
- **`Https`**: the TLS listener and an optional redirect, served together.
  `port()` is the TLS port bound as a `watch::Receiver<u16>`. Either listener
  failing drains the other.
- **`LocalSocket`** and **`serve_local`**, on Unix: the router over http/1.1
  on a Unix socket, bounded and drained as `serve_http`. Handlers get
  `ConnectInfo<PeerCredentials>` and `Extension<PeerCredentials>`, the
  peer's uid, gid and pid as the kernel recorded them at `connect()`; a
  router also served over TCP takes `Option<Extension<PeerCredentials>>`.
  `LocalSocket::bind(path, mode, bounds)` removes a socket nobody answers
  on, refuses a live one or anything that is not a socket, and puts the socket at `path` with `mode` already set; it is
  unlinked when serving ends, unless something else is at `path` by then.
  `mode` is only the file's permissions: who can connect also turns on the
  socket's group and its directory, which are the app's to arrange.
  `LocalSocket::from_listener` holds a socket the caller bound, and leaves
  its path alone.
