# wslib-crypto-jose

The JWS an ACME server (RFC 8555) receives, read and verified. Requests
come in flattened JSON serialisation with a protected header naming the key
by `jwk` or `kid`; the signature is checked through the app's rustls
`CryptoProvider`, and no provider is enabled here.

```rust
use wslib_crypto_jose::{FlattenedJws, KeyRef};

let jws = FlattenedJws::parse(&body)?;
let header = jws.header(); // alg, nonce, url, key
let key = match &header.key {
    KeyRef::Jwk(jwk) => jwk.clone(),               // newAccount, revokeCert
    KeyRef::Kid(url) => account_key(url).await?,   // everything else
};
jws.verify(&key, &provider)?;
let stored = key.to_canonical_json();
let thumbprint = key.thumbprint(); // for key authorisations
```

## What's here

- **`FlattenedJws::parse`**: `protected`, `payload` and `signature`, each
  unpadded base64url; any other member, such as an unprotected `header`, is
  refused (RFC 8555 §6.2). An empty payload is a POST-as-GET.
- **`ProtectedHeader`**: `alg` (ES256, ES384, RS256 or EdDSA; `none`, HMAC
  and the rest are refused), `url`, an optional `nonce`, and exactly one of
  `jwk` or `kid`. A `crit` member is refused; other members are ignored.
  Which requests need a nonce or a `jwk`, and the key change's inner JWS
  rules (§7.3.5), are the caller's.
- **`FlattenedJws::verify`**: the `alg` must suit the key (ES256 with P-256,
  ES384 with P-384, RS256 with RSA of 2048 bits or more, EdDSA with
  Ed25519), then the signature verifies with the provider's
  `signature_verification_algorithms`. A provider without the algorithm is
  `Error::NoVerifier`, not a bad signature.
- **`Jwk`**: a public key, from JSON or through serde; a private member
  (`d`, `p`, `k`, …) is refused, and optional ones (`kid`, `use`, `alg`)
  are ignored. `to_canonical_json` is the RFC 7638 form, the one to store,
  and `thumbprint` its SHA-256. Keys are equal when their canonical forms
  are.

Not here: signing, JWE, compact serialisation, JWT claims, and HS256, so an
external account binding's MAC is the caller's.
