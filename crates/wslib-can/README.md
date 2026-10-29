# wslib-can

CAN, sans-io: `CanFrame` as it is on the bus, its flags byte, the data length
code table, the kernel's bit timing search, what a SocketCAN error frame says,
and the candump and SavvyCAN text formats. With `task`, the one task shape
every CAN transport runs. [`docs/`](docs/) specifies both text formats.

```rust
use wslib_can::{CanFrame, Direction, candump, payload_dlc};

let frame = CanFrame::data(0, 0x123, false, true, true, vec![0; 12]);
assert_eq!(frame.dlc(), 9);
assert_eq!(payload_dlc(20, false), 8);
let mut log = String::new();
candump::encode_line_into(&mut log, 1_700_000_000_000_000, "can0", &frame, Some(Direction::Rx));
```

The wire carries a data length code and a store keeps a length; above 8 bytes
on CAN FD the two differ, and `dlc_to_len`, `len_to_dlc` and `payload_dlc` are
the one place that holds it.

## Features

None is on by default.

- `task`: `open`, which runs a transport's `Device` on a tokio task: it emits
  `CanEvent`s, stamps reads by the device's clock mapped onto the wall clock,
  serves sends through `CanWriter` between reads, and reopens a lost device
  after a wait that doubles from `reopen` up to `reopen_max`.
- `tcp`: `CanError::Connect`, carrying wslib-tcp's `TransportError`.
