# Changelog

## 0.1.0

- `Frame`, `parse_frame`, `encode_frame` and the id flags: SocketCAN's classic
  and FD layouts.
- `transport`: on Linux, `open` and `bitrates`, with reads stamped by
  `SO_TIMESTAMPNS` through the crate's own `recvmsg`.
