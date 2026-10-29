# Changelog

## 0.1.0

- `LineSettings` and `Parity`: a line's rate and character framing, parsed
  with 8N1's defaults and validated, and `wire_time`, the start, data, parity
  and stop bits of a run of bytes.
- `slip`: SLIP (RFC 1055) both ways, with a decoder that can cap a frame, and
  `DelimiterFramer`; both report each frame's end offset.
- `task`: `open`, a port read by a tokio task that reopens it after a wait
  doubling from `reopen` to `reopen_max`, and can wait for a port that isn't
  there yet. Read-only on Unix is `O_RDONLY` with raw termios, through libc.
- `ports`: the ports the OS lists, with their USB identity.
- `write`: read-write ports, `SerialWriter` and `SerialPort`.
