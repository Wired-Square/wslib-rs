# wslib-can-gsusb

gs_usb, the USB protocol candleLight firmware speaks: CANable, CANable Pro and
the Geschwister Schneider adapters. The codec is sans-io and the default;
[`docs/gs_usb.md`](docs/gs_usb.md) specifies the protocol.

```rust
use wslib_can_gsusb::{HostFrame, encode_host_frame, parse_host_frame};

let frame = HostFrame::transmit(0x123, false, false, false, false, 0, vec![1, 2, 3]);
assert_eq!(parse_host_frame(&encode_host_frame(&frame)), Some(frame));
```

## Features

None is on by default.

- `transport`: on macOS and Windows, `devices`, `open` and `probe`, a wslib-can
  task on one channel of a gs_usb adapter over nusb, stamped by the device's
  clock where it has one. On Linux the kernel's `gs_usb` driver binds the
  adapter, so there `devices` lists the SocketCAN interface each channel
  became, from sysfs.
