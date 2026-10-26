# Changelog

## 0.1.0

- `OneTimeCode`: a pairing code issued from the caller's provider, kept as
  its SHA-256 in an owner-only state file, and spent by its first right use
  or when wrong attempts reach the limit; `redeem` checks and spends in one
  call, and a restart reads the spent state back.
- `PairingCode`: 128 random bits as 26 characters of unpadded base32,
  redacted in `Debug`.
- `PairingUri`: `<scheme>://host:port#pin=<key fingerprint>&code=<code>`
  parsed and formatted, with a DNS name, IPv4 or bracketed IPv6 host;
  unknown and repeated fragment keys refused.
