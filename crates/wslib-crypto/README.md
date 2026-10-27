# wslib-crypto

Keys for X.509 through the app's rustls `CryptoProvider`. This crate
generates P-256, P-384, RSA-2048 and RSA-4096 keys in pure Rust
(RustCrypto) as PKCS#8; the provider loads them, signs, verifies and
supplies randomness. No provider is enabled here, so ring, aws-lc-rs and
rustls-openssl all work.

```rust
use wslib_crypto::{KeyAlgorithm, Signer};

let provider = Arc::new(rustls::crypto::ring::default_provider());
let key = KeyAlgorithm::EcP256.generate()?; // store this PKCS#8
let signer = Signer::new(provider, &key.into())?;
// `signer` is an rcgen 0.14 SigningKey; wslib-crypto-x509 mints with it.
```

## What's here

- **`KeyAlgorithm`**: `EcP256`, `EcP384`, `Rsa2048` and `Rsa4096`, spelt
  `ec-p256` and so on by `Display` and `FromStr`. `of_spki` reads one from a
  public key. Each has one signature scheme: ECDSA with SHA-256 or SHA-384
  by curve, RSA PKCS#1 with SHA-256.
- **`KeyAlgorithm::generate`**: a new key as PKCS#8 DER. **It blocks**: RSA
  takes seconds, and RSA-4096 has taken over eight; use `spawn_blocking` in
  an async app. Unoptimised, it takes far longer, so a workspace whose tests
  generate RSA keys can set `[profile.dev.package.num-bigint-dig]
  opt-level = 3`.
- **`Signer::new(provider, &key)`**: a key loaded through the provider, as
  rcgen's `SigningKey` and `PublicKeyData`. The algorithm is read from the
  key, and the signer offers its one scheme only. The public key is the
  provider's; when the provider gives none, it is computed from a PKCS#8
  key of the four algorithms, and any other key is refused with
  `Error::NoPublicKey`.
- **`key_matches(provider, &key, spki)`**: whether a private key is the
  other half of a certificate's SubjectPublicKeyInfo, as the provider sees it.
- **`key_identifier(spki)`**: RFC 7093 method 1, the first 20 bytes of the
  SHA-256 of the SubjectPublicKeyInfo, for subject and authority key
  identifiers.
- **`random_serial(provider)`**: a 16-byte positive serial from the
  provider's randomness.
- **`random::<N>(provider)`**: `N` bytes from the provider's randomness.
  `random_default::<N>()` takes them from the process's default provider,
  and returns `Error::NoProvider` when none is installed.
- **`Fingerprint`**: the SHA-256 of some DER. `Display` is lowercase hex,
  `colons()` is `AB:CD:…` as browsers show it, and `FromStr` reads either.
  `as_bytes()` and `From<[u8; 32]>` go to and from the digest.

## What isn't

Certificates themselves: see `wslib-crypto-x509`. Ed25519 and other curves,
and signing schemes other than the one per algorithm above (no RSA-PSS).
