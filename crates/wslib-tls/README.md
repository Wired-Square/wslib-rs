# wslib-tls

What an app trusts when it dials out, over the app's rustls
`CryptoProvider`: the OS's roots, authorities it installed and certificates
pinned by host, replaced live, with typed rejections and a look at what a
host presents before it is pinned. And the pair its own listener serves,
minted, kept and replaced. No provider is enabled here.

```rust
use wslib_tls::{Cause, Outbound, Rejection, Trust};

let mut trust = Trust::os_roots();
trust.anchor(&authority_der)?; // must be CA:TRUE
trust.anchor_pem(&authorities_pem)?; // each one, or none
trust.pin("10.0.50.198", fingerprint);
let outbound = Arc::new(Outbound::new(provider.clone(), trust)?);

let mut config = outbound.client_config();
config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
let client = reqwest::Client::builder().use_preconfigured_tls(config).build()?;

// Later, from the app's own tables; every client built above follows:
outbound.set_trust(next);

// Why a request failed:
match wslib_tls::cause(&error) {
    Some(Cause::Rejected(Rejection::PinMismatch { host, presented, pinned })) => {}
    Some(Cause::Certificate(rustls::CertificateError::UnknownIssuer)) => {}
    _ => {}
}

// The look before a pin:
let presented = outbound.inspect("https://10.0.50.198:8443").await?;
let view = wslib_crypto_x509::inspect(&presented.end_entity)?;
```

## What's here

- **`Trust`**: plain values. `Trust::os_roots()` or `Trust::default()`
  (nothing), `anchor` for an authority's certificate (refused unless it is
  `CA:TRUE`, so a leaf cannot anchor itself), `anchor_pem` for one or more
  in PEM, all anchored or none, `anchors()` to read them back as DER (for
  a Docker daemon's CA file, say), and `pin` for a host and a
  `wslib_crypto::Fingerprint`. Hosts are keyed as `normalise_host` spells
  them: an address in canonical form, a name in lowercase without a
  trailing dot.
- **`Outbound::new(provider, trust)`**: fails only when the provider cannot
  make a TLS client. The OS store is read on a background thread with
  `rustls-native-certs`, and read again on each `set_trust` until a read
  comes back whole and non-empty, then kept. `SSL_CERT_FILE` and
  `SSL_CERT_DIR` replace it.
- **The verifier**: a pinned host is trusted for exactly that certificate,
  its name and expiry unchecked; any other host is checked by webpki
  against the OS roots and the anchors with the provider's algorithms. An
  unpinned handshake waits up to 30 s for the first OS read, handing a
  multi-threaded runtime's worker on while it waits. An authority's own
  dates are not checked.
- **`set_trust`, `trust` and `subscribe`**: every client built from
  `client_config` reads the trust last set at its next handshake, and
  `trust()` hands it back. Pooled connections are
  not reached; drop clients when the `watch` generation changes to make a
  removal bite at once.
- **`client_config()`**: on the caller's provider, session resumption off
  (rustls does not verify a resumed handshake), ALPN left to the caller.
- **`Rejection` and `cause`**: the verifier's own refusals (`PinMismatch`
  with both fingerprints, `OsRootsNotRead`, `NoAuthority`) travel as
  `rustls::Error::Other`; `cause` walks an error's sources, through
  `std::io::Error`, to one of them or to rustls's `CertificateError`.
- **`Outbound::inspect(target)`**: an `https://` URL or `host[:port]`
  (443 by default); connects within 5 s, trusting nothing, and returns the
  presented chain. Offers ALPN `h2` and `http/1.1`. `ProbeError` says
  which part failed.
- **`testing`** (feature): an `Authority` that signs, a `self_signed` pair
  and a loopback `TlsPeer` answering 204, each on the provider passed in;
  `outbound_with_os_roots` for an `Outbound` whose OS store holds the
  roots given, or none, rather than the machine's.

Needs tokio's multi-threaded runtime feature, for `block_in_place`.

## Serving its own listener

The certificate and key an app serves, as an `Arc<ServerConfig>` on the
app's provider with ALPN left empty.

```rust
use wslib_tls::{Location, Serving};

let location = Location::managed(state.join("cert.pem"), state.join("key.pem"));
let names = ["widget-01", "widget-01.local", "127.0.0.1"].map(|n| n.parse().unwrap());
let serving = tokio::task::spawn_blocking(move || {
    Serving::load_or_mint(provider, location, &names, KeyAlgorithm::EcP256)
})
.await??;
let tls = wslib_http_server::Tls::new(serving.config()); // adds h2 and http/1.1

// An operator's pair: refused before a file is touched, or written and handed back.
let installed = serving
    .install_pem(&cert_pem, &key_pem, Some(host), SystemTime::now()) // key_pem: Secret
    .await?;
tls.reload(installed.config);
for warning in &installed.report.warnings { /* expired, host not covered, ... */ }
```

- **`Serving::load_or_mint`**: both files there and loadable, they are
  served; neither, a self-signed pair is minted with `wslib_crypto_x509::mint`
  for the caller's names; one half, or a pair that will not read, parse,
  match or load, is moved aside to the first free `<file>.unusable`,
  `.unusable.1`, … and replaced at a
  `Location::managed` location, and refused with `ServingError::Named` at a
  `Location::named` one. A path that cannot even be looked at is refused at
  either. An interrupted write that cannot be finished, or whose record is
  refused, is set aside the same way at a managed location, record and
  staged files, and is `ServingError::Recover` at a named one. Blocks: it
  reads and writes files, and RSA generation takes seconds.
- **Writing the pair** goes through a `wslib_file_atomic::Transaction`
  recorded beside the key as `<key file>.txn`: both files land or neither,
  `0600`, key first, a symlink at either path replaced rather than
  followed. `Location::recover()` finishes or rolls back an interrupted
  write, and `load_or_mint`, `read_pair()`, `pair()` and every write run it
  first. A record naming other files, or not this process's own, is refused;
  at a named location so is one in a directory others may write, and on
  Windows any record. A `Serving` finishes the record its own failed commit
  left while it is still that file, whatever its directory.
- **`replaceable()`**: whether both directories took a new file when the
  pair was loaded, for a caller about to do something an install failing
  would leave half done.
- **`install_pem(cert, key, host, now)`**: the key a `wslib_secret::Secret`;
  normalises both, refuses anything but
  certificates in the chain, an encrypted key, a key that is not the
  certificate's, or a pair rustls will not serve, and builds the new
  `ServerConfig`, all before the lock and the write. Installs are taken one
  at a time. `Installed` carries the config for `Tls::reload` and the
  `wslib_crypto_x509::Report` for `host` at `now`, whose warnings refuse
  nothing. A restore installs its backup's pair through it too, so the
  files have one writer and `config()` never goes stale.
- **`regenerate(names, algorithm)`**: a fresh self-signed pair for the
  caller's names, minted off the runtime and written under the same lock;
  returns the config for `Tls::reload`.
- **`pair()`** and **`Location::read_pair()`**: the PEM on disk for a
  backup, the certificate file filtered to its `CERTIFICATE` sections and
  the key a `Secret`;
  `pair()` under the install lock, `read_pair()` with nothing serving.

## What isn't

Storing trust (the app keeps its tables and calls `set_trust`), a reqwest
dependency, installing a provider, revocation, and the names a minted
certificate covers (the app's hostname, `.local` and loopback are its own
policy).
