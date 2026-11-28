# wslib-ble

Bluetooth LE pairing on a host with no agent, and forgetting a bond. BlueZ
confirms no pairing, not even one that asks the user nothing, while the host
has no pairing agent, which a headless host has not. This crate supplies one
for the length of a connection, for one named device. It does no scanning,
connecting or GATT: the BLE library in use keeps those.

```rust
use std::time::Duration;

use wslib_ble::{Address, Pairing, forget};

let address: Address = "AA:BB:CC:DD:EE:FF".parse()?;
forget("hci0", &address).await?; // a reflashed device has lost its keys
// ... discover the device ...
let pairing = Pairing::confirm("hci0", &address).await?;
// ... connect ...
pairing.pair(Duration::from_secs(30)).await?;
// ... encrypted reads and writes ...
pairing.close().await?;
```

## What's here

- **`Pairing::confirm`** registers an `org.bluez.Agent1` object with
  capability `NoInputNoOutput` on a system-bus connection of its own, and
  returns the guard. It never asks to be the default agent and never sets
  `Trusted`. The adapter must have discovered the device first:
  `PairError::UnknownDevice` otherwise.
- **`Pairing::pair`** calls `Device1.Pair()` with the caller's limit and
  answers `Paired::New` or `Paired::Existing`. A refusal keeps BlueZ's error
  name as `Refusal` and its text. A pairing unanswered at the limit, or whose
  call is dropped, gets a `CancelPairing`.
- **Dropping the guard** unregisters the agent on the Tokio runtime it is
  dropped in, without waiting, and outside a runtime leaves it to the
  connection closing. **`close`** waits and reports.
- **`forget`** is `Adapter1.RemoveDevice`. A device BlueZ has no record of is
  `Forgotten::NotKnown`. BlueZ drops the device object too, so the device
  must be discovered again.
- **`Address`** parses `AA:BB:CC:DD:EE:FF` in either case and prints upper
  case.
- Nothing is logged. Every failure is a `PairError` or `ForgetError`, with
  the `zbus::Error` behind `source()` where the bus gave one.

## The order, and what the agent does not guard

`confirm`, then connect and `pair`, then any encrypted operation, then drop.
An encrypted read or write tried before the pairing can go unanswered until
its caller's own limit.

Measured on BlueZ 5.85: a `Pair()` bonds without asking the agent, yet fails
with `AuthenticationFailed` when no agent exists; a pairing started by an
encrypted read asks the agent through `RequestAuthorization`, whichever
connection the read came from. So the agent authorises that request, and
`RequestConfirmation`, for its one device only, and rejects every method that
needs a PIN or a passkey. It cannot stop another local process pairing
another Just Works device with a `Pair()` of its own while the guard lives:
hold the guard only around the pairing.

Not tested: a host where another process already has an agent, a pairing the
peripheral asks for, and any BlueZ but 5.85.

## Off Linux

The operating system pairs by itself. `Pairing::confirm` and `pair` answer
`Paired::ByTheSystem` at once, and the crate has no dependency. `forget`
answers `ForgetError::Unsupported`, since no call removes a bond.

## Testing

The `testing` feature adds `testing::FakeBluez`, a scripted BlueZ over a
socket pair that behaves as measured above, and it makes
`Pairing::confirm_on` and `forget_on`, which take a `zbus::Connection`,
available on any Unix.

```toml
wslib-ble = { version = "0.1", registry = "wired-square" }
```
