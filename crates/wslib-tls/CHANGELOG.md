# Changelog

## 0.1.0

- `Outbound`: outbound trust over the caller's `CryptoProvider` from a
  `Trust` of OS roots, CA anchors and pins by host; replaced live by
  `set_trust`, with a `watch` generation from `subscribe`; `client_config`
  with resumption off and ALPN left to the caller.
- The OS store read once on a background thread, again until a whole read
  is kept; unpinned handshakes wait up to 30 s for it.
- Typed refusals: `Rejection` inside `rustls::Error::Other`, and `cause` to
  find it or rustls's `CertificateError` through an error's sources.
- `Outbound::inspect`: the presented chain of an `https://` URL or
  `host[:port]`, trusting nothing.
- `testing` feature: an authority, a self-signed pair and a loopback TLS
  peer.
- `Serving`: the pair an app's own listener serves, as an
  `Arc<ServerConfig>` on the caller's provider. `load_or_mint` at a
  `Location`: loaded, minted, or an unusable pair moved aside to
  `*.unusable` and replaced at the app's own location and refused at a named
  one. Written both-or-neither through a `wslib-file-atomic` transaction,
  `0600`, recovered at the next start.
- `Serving::install_pem`: an operator's chain and key checked, examined and
  staged as a `ServerConfig` before the files are written, one install at a
  time; `replaceable` from a startup write probe; `pair` and
  `Location::read_pair` for backups.
- Moved from the chassis's outbound TLS and serving pair.
