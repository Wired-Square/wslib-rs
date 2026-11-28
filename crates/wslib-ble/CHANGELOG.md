# Changelog

## 0.1.0

- `Address`: a Bluetooth address, parsed in either case and printed in upper
  case.
- `Paired`, `Forgotten`, `Refusal`, `PairError` and `ForgetError`: what a
  pairing or a forgetting came to.
- Off Linux, `Pairing::confirm` and `pair` answer `Paired::ByTheSystem` at
  once, and `forget` answers `ForgetError::Unsupported`.
- `forget` removes the bond and the record BlueZ holds for a device, through
  `Adapter1.RemoveDevice`; a device BlueZ does not have is
  `Forgotten::NotKnown`. `forget_on` does it over a given connection.
- The `testing` feature adds `testing::FakeBluez`, a scripted BlueZ served
  over a socket pair.
