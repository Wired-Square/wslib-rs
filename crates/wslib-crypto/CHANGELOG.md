# Changelog

## 0.1.3

- `to_pkcs8`: a private key as PKCS#8. A SEC1 P-256 or P-384 key is
  converted, and a two-prime PKCS#1 RSA-2048 or RSA-4096 key is wrapped as
  it is; a PKCS#8 key is copied. Another curve or size is
  `Error::Unsupported`, and DER that does not parse is the new
  `Error::Malformed`. No unwiped copy of the key is left behind.

## 0.1.2

- `Fingerprint` from its 32 digest bytes, as `From<[u8; 32]>`.

## 0.1.1

- `random::<N>(provider)` for `N` bytes from the provider's randomness, and
  `random_default::<N>()` from the process's default provider, with the new
  `Error::NoProvider` when none is installed. `random_serial` is built on
  `random`.

## 0.1.0

- `KeyAlgorithm`: P-256, P-384, RSA-2048 and RSA-4096, each with one
  signature scheme; `generate` to PKCS#8 in pure Rust, blocking for RSA;
  `of_spki`; `ec-p256`-style names.
- `Signer`: a key loaded through the caller's rustls `CryptoProvider`,
  implementing rcgen 0.14's `SigningKey`. Its public key is the provider's,
  or computed from PKCS#8 when the provider gives none.
- `key_matches`, `key_identifier` (RFC 7093 method 1), `random_serial` from
  the provider, and the SHA-256 `Fingerprint` in hex or colon form.
