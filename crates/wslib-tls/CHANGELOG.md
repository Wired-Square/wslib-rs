# Changelog

## 0.1.1

- `Location::recover()` finishes an interrupted write of the pair, and
  `read_pair()`, `Serving::pair()` and every write (`install_pem`,
  `regenerate`, a mint) run it first, so a `CommitError::Committed` is
  finished before the next write begins. A record naming other files than
  the pair, or not this process's own, is refused; at a named location so
  is one in a directory others may write (Unix) and any record (Windows). A
  `Serving` finishes the record its own failed commit left while it is
  still that file, whatever its directory. Refused or failed, it is
  `ServingError::Recover`. Needs `wslib-file-atomic` 0.1.4.
- `load_or_mint` at a managed location sets an interrupted write it cannot
  finish, or whose record is refused, aside as `.unusable`, record and
  staged files, with a warning, and goes on to load or mint; at a named
  location it is still `ServingError::Recover`.
- An unusable file is moved aside to the first free `<file>.unusable`,
  `.unusable.1`, …, never over an earlier one or a directory there.
- `libc` is a dependency on Unix (>= 0.2.174).

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
- `install_pem` takes the time to examine the certificate at.
- `install_pem` takes the key as a `wslib_secret::Secret`, and `ServingPair`
  carries it as one.
- `Serving::regenerate`: a fresh self-signed pair for given names, written
  under the install lock.
- A restore goes through `install_pem`, the pair's one writer.
- `testing::outbound_with_os_roots`: an `Outbound` over a stub OS store.
- `Trust::anchors` and `Outbound::trust`: the current authorities as DER.
- `Trust::anchor_pem`: one or more authorities from PEM, all or none.
- Moved from the chassis's outbound TLS and serving pair.
