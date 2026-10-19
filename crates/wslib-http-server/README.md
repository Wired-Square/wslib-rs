# wslib-http-server

The listeners under an axum app: plain HTTP, TLS with h1 and h2 by ALPN, and
a redirect to the TLS port, each held to its own bounds and drained on a
`CancellationToken`. The routes are the app's; this crate owns the sockets.

```rust
use wslib_http_server::{Bounds, CancellationToken, Https, Listener, Tls};

let provider = Arc::new(rustls::crypto::ring::default_provider());
let config = wslib_http_server::server_config_from_pem_files(provider, &cert, &key)?;
let tls = Tls::new(config);

let https = Https::new(Listener::bind(address, Bounds::SERVING).await?, tls.clone())
    .redirect_from(Listener::bind(redirect, Bounds::REDIRECT).await?);
let port = https.port();
https.serve(app, stop).await?;

// On a certificate install, from anywhere holding a clone:
tls.reload(new_config);
```

Without TLS, `serve_http(Listener::bind(address, Bounds::SERVING).await?, app, stop)`.

## What's here

- **No crypto provider.** The crate enables none and never reads the process
  default. The app builds its `ServerConfig` on the provider it chose, with
  `server_config_from_pem` or `server_config_from_pem_files` or by hand.
  Enable exactly one provider in the binary: with two, rustls panics at the
  first handshake.
- **`Listener::bind(address, bounds)`** binds at once, so a taken port fails
  before serving and port 0 resolves; `local_addr` gives the port bound.
- **`Bounds`**: `connections` held at once, taken before `accept` so the rest
  wait in the kernel's backlog; `head`, the deadline on the TLS handshake, on
  saying which protocol the peer speaks, and on each http/1.1 request head;
  and `grace`, how long open connections get once the token fires.
  `Bounds::SERVING` is 16 connections, 10s and 10s; `Bounds::REDIRECT` is 8,
  5s and 10s.
- **`serve_http`** and **`serve_https`**: the router until the token fires
  and the listener has drained. Handlers get `ConnectInfo<SocketAddr>`. h2
  connections are pinged every 20s and hold at most 32 streams.
- **`Tls`**: the config a TLS listener serves. `Tls::new` offers h2 and
  http/1.1 by ALPN when the config names none; a config that names its own
  keeps them. `reload` swaps the config for new connections; clones share it.
- **`serve_redirect(listener, https_port, stop)`**: a 307 for every request
  to `https://<host>:<port><path and query>`, the port read from the `watch`
  at each request, so it follows a TLS listener that moves. 307 keeps the
  method and body; it is not cached with the port in it. http/1.1 only, and
  each connection is closed after its answer.
- **`Https`**: the TLS listener and an optional redirect, served together.
  `port()` is the TLS port bound as a `watch::Receiver<u16>`. Either listener
  failing drains the other.
