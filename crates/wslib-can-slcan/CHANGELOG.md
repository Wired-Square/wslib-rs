# Changelog

## 0.1.0

- The SLCAN codec: `LineDecoder`, `parse_frame` and `encode_frame_into`, the
  command and bitrate tables, and `parse_version`, which tells the Elmue CAN FD
  firmware from the standard.
- `transport`: `open`, `probe` and `check_rates` over a serial port, through
  wslib-serial.
