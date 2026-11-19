# Changelog

## 0.2.0

- On wslib-serial 0.2, whose `LineSettings` is `SlcanOptions::line`.
- `transport`: a serial port's refusal other than an open, a close, a read
  or a write, such as settings it can't take, now arrives as wslib-can's
  `CanError::Serial` carrying the `SerialError`, not `CanError::Config` and
  its text. wslib-can's floor is 0.1.4.
- An open that panics on the blocking pool is `CanError::Panicked`: `open`
  and `probe` return it, and a reopen's is the task's `Disconnected`, after
  which the task tries again. A write that panics answers its send with an
  `io::Error` holding `CanError::Panicked`. An open the runtime cancels
  before it runs is `CanError::Open` with `Interrupted`, and a write
  `Interrupted`.
- The transport needs no wslib-serial on iOS, which it doesn't build for.

## 0.1.0

- The SLCAN codec: `LineDecoder`, `parse_frame` and `encode_frame_into`, the
  command and bitrate tables, and `parse_version`, which tells the Elmue CAN FD
  firmware from the standard.
- `transport`: `open`, `probe` and `check_rates` over a serial port, through
  wslib-serial.
