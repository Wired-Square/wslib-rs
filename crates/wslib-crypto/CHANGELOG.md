# Changelog

## 0.1.0

- `KeyAlgorithm`: P-256, P-384, RSA-2048 and RSA-4096, each with one
  signature scheme; `generate` to PKCS#8 in pure Rust, blocking for RSA;
  `of_spki`; `ec-p256`-style names.
- `Signer`: a key loaded through the caller's rustls `CryptoProvider`,
  implementing rcgen 0.14's `SigningKey`. Its public key is the provider's,
  or computed from PKCS#8 when the provider gives none.
- `key_matches`, `key_identifier` (RFC 7093 method 1), `random_serial` from
  the provider, and the SHA-256 `Fingerprint` in hex or colon form.
