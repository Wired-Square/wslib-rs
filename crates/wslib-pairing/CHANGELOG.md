# Changelog

## 0.1.0

- `OneTimeCode`: a pairing code drawn from the OS, kept as its
  `wslib_secret::TokenHash` in an owner-only state file, and spent by its
  first right use or when wrong attempts reach the limit; `redeem` checks and spends in one
  call, and a restart reads the spent state back.
- `PairingCode`: 128 random bits as 26 characters of unpadded base32,
  redacted in `Debug`.
- `PairingUri`: `<scheme>://host:port#pin=<SPKI SHA-256>&code=<code>`
  parsed and formatted, with a DNS name, IPv4 or bracketed IPv6 host;
  unknown and repeated fragment keys refused.
- `SpkiSha256`: the pin, the SHA-256 of the daemon's SubjectPublicKeyInfo,
  read as hex or colon-hex and written as hex. No rustls, `wslib-crypto` or
  `wslib-tls` dependency.
