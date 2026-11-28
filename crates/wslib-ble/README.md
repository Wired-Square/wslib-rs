# wslib-ble

Bluetooth LE pairing on a host with no agent, and forgetting a bond. It does
no scanning, connecting or GATT: the BLE library in use keeps those.

```rust
use std::time::Duration;

use wslib_ble::{Address, Pairing};

let address: Address = "AA:BB:CC:DD:EE:FF".parse()?;
let pairing = Pairing::confirm("hci0", &address).await?;
pairing.pair(Duration::from_secs(30)).await?;
pairing.close().await?;
```

Off Linux the operating system pairs by itself: `Pairing::confirm` and `pair`
answer `Paired::ByTheSystem` at once and the crate has no dependency.
`forget` answers `ForgetError::Unsupported` there, since no call removes a
bond.

```toml
wslib-ble = { version = "0.1", registry = "wired-square" }
```
