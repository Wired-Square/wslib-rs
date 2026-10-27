# wslib-pairing

Primitives for pairing a client with a daemon that serves a self-signed
certificate. The daemon prints a URI carrying the SHA-256 of its key and a
one-time code; the client dials, checks the key against the pin before it
sends the code, and the daemon checks and spends the code. No network, HTTP
or TLS here, and no rustls: those are the caller's.

```rust
use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::SystemTime;
use wslib_crypto::{Fingerprint, KeyAlgorithm};
use wslib_pairing::{OneTimeCode, PairingUri, Redemption, SpkiSha256};
use wslib_tls::{KeyFingerprint, Serving};

// Daemon, at startup: its key and certificate, minted once and kept.
// `load_or_mint` blocks, as wslib-tls says.
let names = || vec!["broker.lan".parse().unwrap()];
let serving = Serving::load_or_mint(provider, location, names, KeyAlgorithm::EcP256)?;
let pin = SpkiSha256::from(*serving.key_fingerprint().0.as_bytes());

let attempts = NonZeroU32::new(5).unwrap();
let (code, plain) = OneTimeCode::issue(state_dir.join("pairing-code"), attempts)?;
let code = Arc::new(code);
let uri = PairingUri::new("example-enrol", "broker.lan", 8443, pin, plain)?;
println!("{}", uri.expose());

// Daemon, when a client offers a code: checked and spent in one call, which
// blocks on a file lock and fsync.
let redeeming = code.clone();
match tokio::task::spawn_blocking(move || redeeming.redeem(&offered)).await?? {
    Redemption::Accepted => { /* pair */ }
    Redemption::Refused { remaining } => { /* one or more attempts left */ }
    Redemption::Spent(by) => { /* by acceptance or lockout: issue a new one to pair again */ }
    _ => { /* refuse */ }
}

// Daemon, once its certificate is signed: a new chain over the same key, so
// the pin printed above still holds.
let pair = serving.pair().await?;
serving.install_pem(&signed_chain, &pair.key_pem, None, SystemTime::now()).await?;

// Client:
let uri = PairingUri::parse("example-enrol", &pasted)?;
trust.pin_key(uri.host(), KeyFingerprint(Fingerprint::from(*uri.pin().as_bytes())));
// dial uri.host():uri.port() with that trust, and send uri.code().expose()
// only after the handshake.
```

## What's here

- **`OneTimeCode`**: `issue(path, attempts)` draws 128 bits from the OS
  through `wslib-secret`'s `token` feature and writes a fresh state over
  whatever is at `path`; `open(path)` finds it (`None` when nothing is
  there). `redeem(&offered)` compares in constant time and spends the code on
  its first right use, or when wrong attempts reach the limit, saving the new
  state before it returns. The attempt that reaches the limit answers
  `Spent(SpentBy::Lockout)`, as every later one does. A save that fails is
  an error and changes nothing: the attempt is neither counted nor answered.
  `status()` reads the remaining attempts and the limit, or why the code is
  spent, without spending an attempt.
- **The file is the authority**: every call reads it afresh, and `issue`
  and `redeem` hold an exclusive lock on `<path>.lock` from the read to the
  write, so a code issued or an attempt made by another process or handle
  on the same path counts. The lock is a file beside the state rather than
  the state itself, as each save renames a new file over it. `redeem` blocks
  on the lock and on fsync, so an async caller runs it under
  `spawn_blocking`.
- **The state file**: owner-only (`0600`, or a protected DACL on Windows),
  replaced whole through `wslib-file-atomic`, holding the code's
  `wslib_secret::TokenHash` (SHA-256, unpadded base64url) and the count, or
  why it was spent; never the code. So a restart cannot revive a spent code
  or reset the count, and a leaked state file does not give the code away.
  Nor can the daemon print the URI again after a restart; it issues a new
  code and prints a new one. Being owner-only, the state and its lock serve
  only their owner: a tool that issues as root for a daemon running as
  another user drops to that user first.
- **`PairingCode`**: 26 characters of unpadded RFC 4648 base32, read in
  either case; `Debug` redacts it and `expose()` gives it.
- **`PairingUri`**: `<scheme>://host:port#pin=<hex>&code=<code>`. The host is
  a DNS name, an IPv4 address or a bracketed IPv6 address; the pin is a
  `SpkiSha256`; the keys come in either order, and a key it does not know is
  ignored, so a later release can add one. A repeated or missing key, a
  path, user info or port 0 are refused. The host is kept as
  `wslib_tls::normalise_host` keys a pin: an address in canonical form, a
  name in lowercase without its trailing dot. `Debug` redacts the code;
  `expose()` writes the URI in full.
- **`SpkiSha256`**: the SHA-256 of the daemon's DER SubjectPublicKeyInfo over
  `[u8; 32]`, read as hex or colon-hex and written as hex, as
  `wslib_crypto::Fingerprint` is. From a `wslib_tls::KeyFingerprint`, such
  as `Serving::key_fingerprint()` (wslib-tls 0.2.2):
  `SpkiSha256::from(*key.0.as_bytes())`. Back:
  `KeyFingerprint(Fingerprint::from(*pin.as_bytes()))` (wslib-crypto 0.1.2).

## What isn't

The pairing exchange itself, the client's dial and pin check, and expiry of
an unused code: the daemon reissues when it wants a fresh one. The daemon's
identity is `wslib_tls::Serving`, which keeps its key while a signed chain
replaces the self-signed one.
