# Changelog

## 0.1.1

- Recovery codes: `generate_recovery_codes` makes ten of 80 bits, shown as four
  groups of four base32 characters, with the hash to keep of each;
  `recovery_code_hash` hashes a typed code the same way (case, separators and
  the digits 0, 1 and 8 normalised). Moved from the chassis, hashes unchanged.

## 0.1.0

- `Key`: a 160-bit TOTP key, generated, read from and written to unpadded
  base32, and its `otpauth://` URI. HMAC-SHA1, six digits, 30 s steps.
- `Key::accepted_step`: the step a code matched, one step either side of now,
  for the caller to spend once. `Key::code_at` for tests.
- `check_clocks` and `ClockSkew`: the server's clock against the browser's.
  With the default `codes` feature off, they are all that is left, on serde.
- Moved from the chassis's `appliance-auth`, on RustCrypto rather than ring.
