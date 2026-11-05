# Changelog

## 0.1.0

- `FlattenedJws::parse`: an ACME request body, refusing an unprotected
  header, more than one signature, padded or non-url base64, a `crit`
  member, and any `alg` but ES256, ES384, RS256 and EdDSA.
- `ProtectedHeader`: `alg`, `nonce`, `url` (required) and the key by
  exactly one of `jwk` or `kid`.
- `FlattenedJws::verify`: the `alg` must suit the key, then the signature
  through the caller's rustls `CryptoProvider`. `into_parts` gives up the
  header and payload.
- `FlattenedJws::key_change`: RFC 8555 §7.3.5's inner JWS checked and its
  `KeyChange` (new key and account) returned.
- `Jwk`: public EC P-256 and P-384, RSA of 2048 bits or more and Ed25519
  keys, private members refused, with `JwkError`; the RFC 7638 canonical
  form and thumbprint, and equality by it; `algorithm` and
  `subject_public_key_info`.
- `Error::kind`: the ACME error type to answer with, as an `ErrorKind`.
  `Algorithm::ALL` lists what a badSignatureAlgorithm answer offers.
