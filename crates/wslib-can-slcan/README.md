# wslib-can-slcan

SLCAN, the Lawicel serial line CAN protocol most USB-CAN adapters speak, with
the CAN FD frames and data rates the Elmue CANable 2.5 firmware adds. The codec
is sans-io and the default; [`docs/slcan.md`](docs/slcan.md) specifies the
protocol.

```rust
use wslib_can_slcan::{Line, LineDecoder};

for line in LineDecoder::new().feed(&bytes_from_the_device) {
    if let Line::Frame(frame) = line { /* … */ }
}
```

## Features

None is on by default.

- `transport`: `open`, `probe` and `check_rates`, a wslib-can task on an SLCAN
  adapter over a serial port, opened read-write and exclusive through
  wslib-serial. Each frame takes its read's time, as the protocol carries
  none. Builds nothing on iOS.
