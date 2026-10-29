# wslib-can-socketcan

SocketCAN's `can_frame` and `canfd_frame` layouts and the flags packed beside
an id, by default; a kernel ABI rather than a wire format, so the id is
native-endian. With `transport`, on Linux, a wslib-can task over a raw socket.

```rust
use wslib_can_socketcan::{Frame, encode_frame, parse_frame};

let frame = Frame::new(0x123, false, false, false, false, vec![1, 2, 3]);
assert_eq!(parse_frame(&encode_frame(&frame)), Some(frame));
```

## Features

- `transport`: `open`, a CAN task on one interface, reopened by name after a
  loss, each read stamped with the kernel's receive time and the socket's own
  sends marked `Tx`; and `bitrates`, an interface's configured rates over
  netlink. Linux only; elsewhere it builds nothing.
