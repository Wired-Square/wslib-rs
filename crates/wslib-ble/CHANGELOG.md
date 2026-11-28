# Changelog

## 0.1.0

- `Address`: a Bluetooth address, parsed in either case and printed in upper
  case.
- `Paired`, `Forgotten`, `Refusal`, `PairError` and `ForgetError`: what a
  pairing or a forgetting came to.
- Off Linux, `Pairing::confirm` and `pair` answer `Paired::ByTheSystem` at
  once, and `forget` answers `ForgetError::Unsupported`.
