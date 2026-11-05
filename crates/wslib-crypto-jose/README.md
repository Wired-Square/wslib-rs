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
  Which requests need a nonce or a `jwk` is the caller's rule.
- **`FlattenedJws::verify`**: the `alg` must suit the key (ES256 with P-256,
  ES384 with P-384, RS256 with RSA, EdDSA with Ed25519), then the signature
  verifies with the provider's `signature_verification_algorithms`.
  `into_parts` gives up the header and payload.
- **`FlattenedJws::key_change`**: on the outer JWS of a key change (§7.3.5),
  verified with the account's key, checks the inner JWS: a `jwk`, no
  nonce, the outer `url`, its own signature, and an `oldKey` that is the
  account's. It returns the new key and the `account`; whether that is the
  outer `kid`'s account and the new key is unused are the caller's checks.
- **`Error::kind`**: the ACME error type to answer with:
  `BadSignatureAlgorithm` (an unsupported `alg`, or one that does not suit
  the key; `Algorithm::ALL` is the list to offer), `BadPublicKey` (any
  `JwkError`), `ServerConfiguration` when the provider lacks an algorithm
  this crate accepts, and `Malformed` for the rest, a bad signature and a
  key change's wrong `oldKey` among them.
- **`Jwk`**: a public key, from JSON or through serde; a private member
  (`d`, `p`, `k`, …) or RSA under 2048 bits is refused, and optional
  members (`kid`, `use`, `alg`) are ignored. `to_canonical_json` is the
  RFC 7638 form, the one to store, and `thumbprint` its SHA-256. Keys are
  equal when their canonical forms are. `algorithm` is the one `alg` that
  suits it, and `subject_public_key_info` its DER, to compare with a CSR's
  key (§11.1).

Not here: signing, JWE, compact serialisation, JWT claims, and HS256, so an
external account binding's MAC is the caller's.
