# Changelog

## 0.2.0

- On wslib-serial 0.2, whose `LineSettings` is `Link::Serial`'s `line`.
- `serial`: a serial port's refusal other than an open, a close or a read,
  such as settings it can't take, is wslib-can's `CanError::Serial` carrying
  the `SerialError`, in place of `CanError::Config` and its text. wslib-can's
  floor is 0.1.4.
- A blocking open's panic resumes on the caller, as an inline open would, in
  place of a `CanError::Read` holding its text. An open the runtime cancels
  before it runs fails as `CanError::Open` with `Interrupted`.

## 0.1.1

- `docs/gvret.md` specifies the GVRET protocol. No code change.

## 0.1.0

- The GVRET codec, both ends: `Decoder` and the reply encoders for the device,
  `DeviceDecoder` and `encode_transmit` for the host, in the trailing-byte
  dialect the field speaks.
- `transport`: `open` and `probe` over TCP, through wslib-tcp.
- `serial`: `Link::Serial`, through wslib-serial.
