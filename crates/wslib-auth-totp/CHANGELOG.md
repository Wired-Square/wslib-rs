# Changelog

## 0.1.0

- `Key`: a 160-bit TOTP key, generated, read from and written to unpadded
  base32, and its `otpauth://` URI. HMAC-SHA1, six digits, 30 s steps.
- `Key::accepted_step`: the step a code matched, one step either side of now,
  for the caller to spend once. `Key::code_at` for tests.
- `check_clocks` and `ClockSkew`: the server's clock against the browser's.
  With the default `codes` feature off, they are all that is left, on serde.
- Moved from the chassis's `appliance-auth`, on RustCrypto rather than ring.
