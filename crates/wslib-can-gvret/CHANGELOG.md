# Changelog

## 0.2.0

- On wslib-can 0.2, and on wslib-serial 0.2, whose `LineSettings` is
  `Link::Serial`'s `line`.
- `serial`: a serial port's refusal other than an open, a close, a read or a
  write, such as settings it can't take, is wslib-can's `CanError::Serial`
  carrying the `SerialError`, in place of `CanError::Config` and its text.
- `serial` builds nothing on iOS, so there gvret needs no wslib-serial.
- A serial open that panics on the blocking pool is `CanError::Panicked`:
  `open` and `probe` return it, and a reopen's is the task's
  `Disconnected`, after which the task tries again. An open the runtime
  cancels before it runs is `CanError::Cancelled`, and a port's
  `SerialError::Cancelled` is that or `WriteFailed::Cancelled`.
- A send answers with a `WriteFailed`: `Io` for the socket's or port's
  `io::Error`, `Panicked` for a serial write that panicked, and `Serial`
  for any other `SerialError`. A handshake's write that fails is
  `CanError::Write`, in place of `CanError::Read`.
- A write of pending output, such as a keepalive ask, before a read that
  fails is that read's `CanError::Write`. It was dropped, and a serial one
  that panicked left the read saying `Closed`.

## 0.1.1

- `docs/gvret.md` specifies the GVRET protocol. No code change.

## 0.1.0

- The GVRET codec, both ends: `Decoder` and the reply encoders for the device,
  `DeviceDecoder` and `encode_transmit` for the host, in the trailing-byte
  dialect the field speaks.
- `transport`: `open` and `probe` over TCP, through wslib-tcp.
- `serial`: `Link::Serial`, through wslib-serial.
