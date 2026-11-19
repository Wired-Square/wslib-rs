# Changelog

## 0.2.0

- On wslib-serial 0.2, whose `LineSettings` is `SlcanOptions::line`.
- `transport`: a serial port's refusal other than an open, a close or a
  read, such as settings it can't take, is wslib-can's `CanError::Serial`
  carrying the `SerialError`, in place of `CanError::Config` and its text.
  wslib-can's floor is 0.1.4.
- A blocking call's panic resumes on the caller, as an inline call would, in
  place of an error holding its text. A call the runtime cancels before it
  runs fails as `Interrupted`.

## 0.1.0

- The SLCAN codec: `LineDecoder`, `parse_frame` and `encode_frame_into`, the
  command and bitrate tables, and `parse_version`, which tells the Elmue CAN FD
  firmware from the standard.
- `transport`: `open`, `probe` and `check_rates` over a serial port, through
  wslib-serial.
