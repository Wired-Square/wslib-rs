# wslib-tls

What an app trusts when it dials out, over the app's rustls
`CryptoProvider`: the OS's roots, authorities it installed and certificates
pinned by host, replaced live, with typed rejections and a look at what a
host presents before it is pinned. No provider is enabled here.

```rust
use wslib_tls::{Cause, Outbound, Rejection, Trust};

let mut trust = Trust::os_roots();
trust.anchor(&authority_der)?; // must be CA:TRUE
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
  `CA:TRUE`, so a leaf cannot anchor itself), and `pin` for a host and a
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
- **`set_trust` and `subscribe`**: every client built from `client_config`
  reads the trust last set at its next handshake. Pooled connections are
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
  and a loopback `TlsPeer` answering 204, each on the provider passed in.

Needs tokio's multi-threaded runtime feature, for `block_in_place`.

## What isn't

Storing trust (the app keeps its tables and calls `set_trust`), a reqwest
dependency, installing a provider, and revocation.
