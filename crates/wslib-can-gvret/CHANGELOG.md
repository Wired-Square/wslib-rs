# Changelog

## 0.2.0

- On wslib-serial 0.2, whose `LineSettings` is `Link::Serial`'s `line`.
- `serial`: a serial port's refusal other than an open, a close, a read or a
  write, such as settings it can't take, now arrives as wslib-can's
  `CanError::Serial` carrying the `SerialError`, not `CanError::Config` and
  its text. wslib-can's floor is 0.1.4.
- A serial open that panics on the blocking pool is `CanError::Panicked`:
  `open` and `probe` return it, and a reopen's is the task's
  `Disconnected`, after which the task tries again. An open the runtime
  cancels before it runs is `CanError::Open` with `Interrupted`.

## 0.1.1

- `docs/gvret.md` specifies the GVRET protocol. No code change.

## 0.1.0

- The GVRET codec, both ends: `Decoder` and the reply encoders for the device,
  `DeviceDecoder` and `encode_transmit` for the host, in the trailing-byte
  dialect the field speaks.
- `transport`: `open` and `probe` over TCP, through wslib-tcp.
- `serial`: `Link::Serial`, through wslib-serial.
