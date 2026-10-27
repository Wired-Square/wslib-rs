# Changelog

## 0.1.0

- `OneTimeCode`: a pairing code drawn from the OS, kept as its
  `wslib_secret::TokenHash` in an owner-only state file, and spent by its
  first right use or when wrong attempts reach the limit. The file is the
  authority: each call rereads it, and `issue` and `redeem` hold a lock
  beside it from read to write, so a code issued by another process counts.
  `redeem` checks and spends in one call; `status` reads the attempts left
  and the limit, or `SpentBy` acceptance or lockout, spending nothing.
- `Redemption` is `#[non_exhaustive]`; the attempt that reaches the limit
  answers `Spent(SpentBy::Lockout)`.
- `PairingCode`: 128 random bits as 26 characters of unpadded base32,
  redacted in `Debug`.
- `PairingUri`: `<scheme>://host:port#pin=<SPKI SHA-256>&code=<code>`
  parsed and formatted, with a DNS name, IPv4 or bracketed IPv6 host, kept
  as `wslib_tls::normalise_host` spells it; an unknown fragment key is
  ignored, a repeated one refused.
- `SpkiSha256`: the pin, the SHA-256 of the daemon's SubjectPublicKeyInfo,
  read as hex or colon-hex and written as hex. No rustls, `wslib-crypto` or
  `wslib-tls` dependency.
