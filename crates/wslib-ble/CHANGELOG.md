# Changelog

## 0.1.0

- `Address`: a Bluetooth address, parsed in either case and printed in upper
  case.
- `Pairing::confirm` registers a `NoInputNoOutput` BlueZ agent, never the
  default, that answers `RequestAuthorization` for one device only and
  rejects every other method, `RequestConfirmation` included. `close`
  unregisters it; a dropped guard sends nothing and leaves that to its
  connection closing.
- `Pairing::pair` calls `Device1.Pair()` with a limit and answers
  `Paired::New` or `Paired::Existing`; a refusal keeps BlueZ's error name as
  `Refusal`, and a pairing unanswered at the limit is cancelled. A dropped
  call is cancelled by the next `pair` or by `close`.
- `forget` removes the bond and the record BlueZ holds for a device, through
  `Adapter1.RemoveDevice`; a device BlueZ does not have is
  `Forgotten::NotKnown`.
- `PairError` and `ForgetError` keep the `zbus::Error` behind `source()`.
- `Pairing::confirm_on` and `forget_on` do the same over a given connection.
- Off Linux, `Pairing::confirm` and `pair` answer `Paired::ByTheSystem` at
  once, and `forget` answers `ForgetError::Unsupported`.
- The `testing` feature adds `testing::FakeBluez`, a scripted BlueZ served
  over a socket pair.
