# wslib-can-gvret

GVRET, both ends: the host end a client speaks to an adapter, and the device
end a capture tool speaks to look like one. The codec is sans-io and the
default.

```rust
use wslib_can_gvret::{DeviceDecoder, DeviceMessage, SYNC, encode_transmit};

let mut wire = SYNC.to_vec();
wire.extend(encode_transmit(0x123, false, 0, &[1, 2, 3]));
for message in DeviceDecoder::new().feed(&bytes_from_the_device) {
    if let DeviceMessage::Frame { arb_id, data, .. } = message { /* … */ }
}
```

The byte after a frame's payload is a checksum every participant guesses
differently. This crate speaks the dialect the field speaks, which is not the
spec; the codec's module header records it. Changing it is a protocol change,
not a refactor.

## Features

None is on by default.

- `transport`: `open` and `probe`, a wslib-can task on a GVRET device over
  TCP, with a keepalive that drops a device once it stops answering.
- `serial`: `Link::Serial`, the same device on a serial port, opened
  read-write and exclusive through wslib-serial.
