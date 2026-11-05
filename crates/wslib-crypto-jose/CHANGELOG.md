# Changelog

## 0.1.0

- `FlattenedJws::parse`: an ACME request body, refusing an unprotected
  header, more than one signature, padded or non-url base64, a `crit`
  member, and any `alg` but ES256, ES384, RS256 and EdDSA.
- `ProtectedHeader`: `alg`, `nonce`, `url` (required) and the key by
  exactly one of `jwk` or `kid`.
- `FlattenedJws::verify`: the `alg` must suit the key, RSA at 2048 bits or
  more, then the signature through the caller's rustls `CryptoProvider`.
- `Jwk`: public EC P-256 and P-384, RSA and Ed25519 keys, private members
  refused; the RFC 7638 canonical form and thumbprint, and equality by it.
