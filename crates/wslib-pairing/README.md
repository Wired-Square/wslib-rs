# wslib-pairing

Primitives for pairing a client with a daemon that serves a self-signed
certificate. The daemon prints a URI carrying the SHA-256 of its key and a
one-time code; the client dials, checks the key against the pin before it
sends the code, and the daemon checks and spends the code. No network, HTTP
or TLS here, and no rustls: those are the caller's.

```rust
use std::num::NonZeroU32;
use wslib_pairing::{OneTimeCode, PairingUri, Redemption, SpkiSha256};
use wslib_tls::{KeyFingerprint, Location, Serving};

// Daemon, at startup: its key and certificate, minted once and kept.
let serving = Serving::load_or_mint(provider.clone(), location, names, KeyAlgorithm::EcP256)?;
let pair = serving.pair().await?;
let key = KeyFingerprint::of(&wslib_crypto_x509::pem::certificates(&pair.cert_pem)?[0])?;
let pin = SpkiSha256::from(*key.0.as_bytes());

let attempts = NonZeroU32::new(5).unwrap();
let (mut code, plain) = OneTimeCode::issue(state_dir.join("pairing-code"), attempts)?;
let uri = PairingUri::new("example-enrol", "broker.lan", 8443, pin, plain)?;
println!("{}", uri.expose());

// Daemon, when a client offers a code: checked and spent in one call.
match code.redeem(&offered)? {
    Redemption::Accepted => { /* pair */ }
    Redemption::Refused { remaining } => { /* at 0 the code is spent */ }
    Redemption::Spent => { /* issue a new one to pair again */ }
}

// Daemon, once its certificate is signed: a new chain over the same key, so
// the pin printed above still holds.
serving.install_pem(&signed_chain, &pair.key_pem, None, SystemTime::now()).await?;

// Client:
let uri = PairingUri::parse("example-enrol", &pasted)?;
trust.pin_key(uri.host(), KeyFingerprint(uri.pin().to_string().parse()?));
// dial uri.host():uri.port() with that trust, and send uri.code().expose()
// only after the handshake.
```

## What's here

- **`OneTimeCode`**: `issue(path, attempts)` draws 128 bits from the OS
  through `wslib-secret`'s `token` feature and writes a fresh state over
  whatever is at `path`; `open(path)` reads it back (`None` when nothing is
  there). `redeem(&offered)` compares in constant time and spends the code on
  its first right use, or when wrong attempts reach the limit, saving the new
  state before it returns; an error leaves the code refusing in memory too.
  Hold one per file and serialise `redeem` through it.
- **The state file**: owner-only (`0600`, or a protected DACL on Windows),
  replaced whole through `wslib-file-atomic`, holding the code's
  `wslib_secret::TokenHash` (SHA-256, unpadded base64url) and the count,
  never the code. So a restart cannot revive a spent code or reset the count,
  and a leaked state file does not give the code away. The daemon cannot
  print the code again after a restart; it issues a new one.
- **`PairingCode`**: 26 characters of unpadded RFC 4648 base32, read in
  either case; `Debug` redacts it and `expose()` gives it.
- **`PairingUri`**: `<scheme>://host:port#pin=<hex>&code=<code>`. The host is
  a DNS name, an IPv4 address or a bracketed IPv6 address; the pin is a
  `SpkiSha256`; the keys come in either order. Unknown, repeated or missing
  keys, a path, user info or port 0 are refused. `Debug` redacts the code;
  `expose()` writes the URI in full.
- **`SpkiSha256`**: the SHA-256 of the daemon's DER SubjectPublicKeyInfo over
  `[u8; 32]`, read as hex or colon-hex and written as hex, as
  `wslib_crypto::Fingerprint` is. From a `wslib_tls::KeyFingerprint` or a
  `Fingerprint`: `SpkiSha256::from(*key.0.as_bytes())` or
  `SpkiSha256::from(*fingerprint.as_bytes())`. Back, through text, as
  `Fingerprint` has no constructor from bytes:
  `KeyFingerprint(pin.to_string().parse()?)` or
  `pin.to_string().parse::<Fingerprint>()?`.

## What isn't

The pairing exchange itself, the client's dial and pin check, and expiry of
an unused code: the daemon reissues when it wants a fresh one. The daemon's
identity is `wslib_tls::Serving`, which keeps its key while a signed chain
replaces the self-signed one.
