# Changelog

## 0.2.0

- On wslib-can 0.2, and on wslib-serial 0.2, whose `LineSettings` is
  `SlcanOptions::line`.
- `transport`: a serial port's refusal other than an open, a close, a read
  or a write, such as settings it can't take, is wslib-can's
  `CanError::Serial` carrying the `SerialError`, in place of
  `CanError::Config` and its text.
- An open that panics on the blocking pool is `CanError::Panicked`: `open`
  and `probe` return it, and a reopen's is the task's `Disconnected`, after
  which the task tries again. An open the runtime cancels before it runs is
  `CanError::Cancelled`, and a port's `SerialError::Cancelled` is that or
  `WriteFailed::Cancelled`.
- A send answers with a `WriteFailed`: `Io` for the port's `io::Error`,
  `Panicked` for a write that panicked, and `Serial` for any other
  `SerialError`. A write the runtime cancels before it runs is
  `WriteFailed::Cancelled`. A probe's write that fails is `CanError::Write`, in place
  of `CanError::Read`.
- The transport needs no wslib-serial on iOS, which it doesn't build for.

## 0.1.0

- The SLCAN codec: `LineDecoder`, `parse_frame` and `encode_frame_into`, the
  command and bitrate tables, and `parse_version`, which tells the Elmue CAN FD
  firmware from the standard.
- `transport`: `open`, `probe` and `check_rates` over a serial port, through
  wslib-serial.
