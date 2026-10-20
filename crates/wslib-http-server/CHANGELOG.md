# Changelog

## 0.1.1

- Accept errors are no longer silent. A peer gone before its accept is
  retried at once; anything else, such as EMFILE, is logged and retried a
  second later, holding the connection's permit, rather than dropped and
  retried every 50ms.

## 0.1.0

- `serve_http`: an axum `Router` over plain HTTP on a `Listener` bound by the
  caller, until a stop future completes; what is open then gets the
  grace period to finish and is closed after it. Handlers get
  `ConnectInfo<SocketAddr>`.
- `serve_https` and `Tls`: TLS from the app's `Arc<rustls::ServerConfig>`,
  h2 and http/1.1 by ALPN unless the config names its own, reloaded in place
  by `Tls::reload`. `server_config_from_pem` and
  `server_config_from_pem_files` build a config on the `CryptoProvider` they
  are given. No provider is enabled and the process default is never read.
  A 204 or 304 carries no `Content-Length`, on h2 as on http/1.1.
- `serve_redirect` and `Https`: a 307 for every request to the same host,
  path and query on the TLS port a `watch` holds, http/1.1 only and closing
  each connection. `Https` serves the TLS listener and, if given one, the
  redirect, drains both on the stop or when either fails, and reports the
  port bound as a `watch::Receiver<u16>`.
- `Bounds` on each `Listener`: a connection cap taken before `accept`, and a
  deadline on the handshake, the protocol decision and each http/1.1 request
  head. `Bounds::SERVING` and `Bounds::REDIRECT` are the defaults; h2
  connections are pinged and capped at 32 streams.
- `Tls::from(RustlsConfig)`: serve a config another owner holds, so its
  `reload_from_config` reaches the listener. Its ALPN is the owner's.
- `redirect_router`: the redirect as a `Router`, for testing in-process.
- `Listener::from_tcp` holds a listener the caller bound; `Listener::bind`
  returns the OS's error without adding context.
- The stop is any `Future<Output = ()>`, so a caller can join several
  sources; a `CancellationToken` passes `cancelled_owned()`.
