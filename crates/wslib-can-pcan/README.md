# wslib-can-pcan

PEAK-System's USB CAN adapters: the classic PCAN-USB, in `pcan_usb`, and the
CAN FD family (PCAN-USB FD, PCAN-Chip USB, PCAN-USB Pro FD and PCAN-USB X6), in
`pcan_usb_fd`. The codecs are sans-io and the default;
[`docs/pcan_usb.md`](docs/pcan_usb.md) and
[`docs/pcan_usb_fd.md`](docs/pcan_usb_fd.md) specify the protocols. The FD
family's is read from the kernel driver: no device of it has met this code.

```rust
use wslib_can_pcan::pcan_usb::{Record, decode_message};

for record in decode_message(&bulk_in_message) {
    if let Record::Frame { frame, ticks } = record { /* … */ }
}
```

## Features

None is on by default.

- `transport`: on macOS and Windows, `devices`, `open` and `probe`, a wslib-can
  task on one channel of either family over nusb, stamped by the device's
  clock. On Windows an adapter bound to PEAK's own driver, which nusb can't
  open, goes through the `PCANBasic.dll` that driver installs, loaded at open;
  classic CAN only. On Linux the kernel's `peak_usb` driver makes each adapter
  a SocketCAN interface, and `transport` builds nothing.
