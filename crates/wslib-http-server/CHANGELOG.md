# Changelog

## 0.1.0 (unreleased)

- `serve_http`: an axum `Router` over plain HTTP on a `Listener` bound by the
  caller, until a `CancellationToken` fires; what is open then gets the
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
  redirect, drains both on the token or when either fails, and reports the
  port bound as a `watch::Receiver<u16>`.
- `Bounds` on each `Listener`: a connection cap taken before `accept`, and a
  deadline on the handshake, the protocol decision and each http/1.1 request
  head. `Bounds::SERVING` and `Bounds::REDIRECT` are the defaults; h2
  connections are pinged and capped at 32 streams.
