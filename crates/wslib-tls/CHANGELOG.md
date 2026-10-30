# Changelog

## 0.2.5

- libc's floor is 0.2.183, the workspace's.

## 0.2.4

- `Location::discard_pending()`: moves an interrupted write's record aside to
  the first free `.unusable` name, with the files it staged, without following
  or acting on what it names, and answers where it went (`None` when there was
  none). The operator's step past `ServingError::RecordRefused`, whose
  `next_step()` now names it; nothing runs it on its own.

## 0.2.3

- `Serving::with_client_auth_pinned(authorities, KeyFingerprint)`:
  `with_client_auth`, admitting only the client certificate over the pinned
  key, for an authority that signs other clients too. Another key is
  `CertificateError::ApplicationVerificationFailure`.

## 0.2.2

- `Serving::key_fingerprint()`: the served key's `KeyFingerprint`, to pin,
  kept from the last load or write; nothing is read for it.

## 0.2.1

- `Serving::with_client_auth(authorities)`: every client must present a
  certificate one of the authorities signed, checked by rustls's
  `WebPkiClientVerifier` on the caller's provider, in every configuration
  from then on. Each must be `CA:TRUE`; none at all is
  `AnchorError::NoneGiven`.
- `Outbound::client_config_presenting(chain, key)`: `client_config()`,
  presenting a client certificate to a server that asks for one.
- `testing`: `Authority::sign_client(common_name)`, a client's leaf.
- `Trust::pin_key(host, KeyFingerprint)`: trusts any certificate over the
  pinned key, so a self-signed certificate re-minted over the same key keeps
  its pin. `KeyFingerprint` is the SHA-256 of the DER SubjectPublicKeyInfo,
  spelt and parsed as `Fingerprint` is. Another key is
  `Rejection::KeyPinMismatch`, with both.
- `Presented::key_fingerprint`: the key fingerprint `inspect` saw, to pin.

## 0.2.0

- `Serving::pair()` finishes an interrupted write and reads the pair off the
  runtime, through `spawn_blocking`, as a write does.
- A refused record is told from a failed recover by `wslib-file-atomic`'s
  `Refused`, not by its error kind. Needs `wslib-file-atomic` 0.1.5.
- `Location::read_pair_untouched()`: the pair as `read_pair()` reads it,
  writing nothing; `ServingError::Interrupted { record }` while a write's
  record is there, for a backup read while nothing serves.
- Breaking: at a named location `load_or_mint`'s `RecordRefused` and
  `Recover` come back inside `ServingError::Named`, as an unusable pair
  does.
- Breaking: `ServingError::Recover` is `Recover { record, source }`, and says
  to check the record and move it aside by hand, as `RecordRefused` does.
- Breaking: `ServingError::Write` is `Write { path, source }`, for a write
  that replaced nothing; one committed but not finished is
  `ServingError::Unfinished { record, named, source }`, whose message says
  the old pair is still served and what the next write, read or start does.
  Both variants are `#[non_exhaustive]`.
- `ServingError::next_step()`: what follows an `Unfinished` write, on its
  own; at a named location it names the record to move aside if a start
  cannot.
- `Serving::with_alpn(protocols)`: the ALPN `config()`, `watch()`, installs
  and regenerates carry; none by default.
- `Serving::watch()`: a `watch::Receiver` of each configuration a write puts
  in place, sent under the install lock, so in the order written. A listener
  following it reloads after the write returns, not before.
- Breaking: `load_or_mint` takes the names as `impl FnOnce() ->
  Vec<SubjectAltName>`, called only when it mints.

## 0.1.1

- `Location::recover()` finishes an interrupted write of the pair, and
  `read_pair()`, `Serving::pair()` and every write (`install_pem`,
  `regenerate`, a mint) run it first, so a `CommitError::Committed` is
  finished before the next write begins. A record naming other files than
  the pair, or not this process's own, is refused; at a named location so
  is one in a directory others may write (Unix) and any record (Windows). A
  `Serving` finishes the record its own failed commit left while it is
  still that file, whatever its directory. A refused record is
  `ServingError::RecordRefused`, naming it for an operator to check and move
  aside by hand; a recover that fails otherwise is `ServingError::Recover`.
  Needs `wslib-file-atomic` 0.1.4.
- `load_or_mint` at a managed location sets an interrupted write it cannot
  finish, or whose record is refused, aside as `.unusable`, record and
  staged files, with a warning, then loads the pair, or moves it aside and
  mints, as any start does; at a named location it is an error.
- An unusable file is moved aside to the first free `<file>.unusable`,
  `.unusable.1`, …, never over an earlier one or a directory there.
- `Location::record()`: the path of the transaction record a write leaves.
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
