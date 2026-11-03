# Changelog

## 0.1.7

- `Tls::renew`: every `serve_https` serving that `Tls` drains the
  connections open at the time, as a stop would and within the same
  `Bounds::grace`, and keeps accepting new ones. h2 peers get a GOAWAY and
  finish their in-flight requests, so a browser picks up a reloaded
  certificate at once instead of when its connection idles out. A caller
  that never renews sees no change.

## 0.1.6

- libc's floor is 0.2.183, the workspace's.

## 0.1.5

- `serve_local` serves http/1.1 upgrades; the connection was reset right
  after the 101. It still refuses h2, now at the preface. As over TCP, a
  peer gets `Bounds::head` to begin and `head` again for its first request
  head, so about twice `head` in all.

## 0.1.4

- On Unix, `LocalSocket` and `serve_local`: an axum `Router` over http/1.1
  on a Unix socket, held to the same `Bounds` and drained the same way as
  `serve_http`. Handlers get the peer's credentials, read at accept, as
  `ConnectInfo<PeerCredentials>` and as `Extension<PeerCredentials>`, so a
  router also served over TCP can take `Option<Extension<PeerCredentials>>`;
  a peer whose credentials can't be read is closed. `LocalSocket::bind`
  removes a socket nobody answers on, refuses anything else at the path or a
  live server, and links the socket into place with its mode already set; it
  is unlinked when serving ends, unless the path has been replaced since.
  `LocalSocket::from_listener` holds one the caller bound and never unlinks
  it. `PeerCredentials` is re-exported from `wslib-host` (>= 0.1.1), now a
  dependency on Unix.
- A path too long for `sun_path`, as given or once staged beside it, is
  refused as `InvalidInput`, naming the limit and the length, before
  anything needs a Tokio runtime. `libc` (>= 0.2.174)
  is now a dependency on Unix.

## 0.1.3

- Dependency floors raised to match the crates it shares a graph with:
  axum 0.8.7 (was 0.8), rustls 0.23.27 (was 0.23.11), tokio-util 0.7.19 (was
  0.7.5), and for its tests rcgen 0.14.10 (was 0.14). No change to the API.

## 0.1.2

- `PeerCertificates`: the certificates a TLS client presented, as the
  config's client verifier passed them, an extension on each request
  `serve_https` and `Https` serve; empty when it presented none. Needs
  `tokio-rustls` 0.26, already under `axum-server`.

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
