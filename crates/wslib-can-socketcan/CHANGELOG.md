# Changelog

## 0.2.0

- `transport`: `bitrates` fails with `BitratesError`, in place of an
  `io::Error`: `Interface` for a name no interface has, with its
  `io::Error`, and `Netlink` with socketcan's error as its source, not its
  text.

## 0.1.1

- `docs/socketcan.md` gives the SocketCAN frame layouts. No code change.

## 0.1.0

- `Frame`, `parse_frame`, `encode_frame` and the id flags: SocketCAN's classic
  and FD layouts.
- `transport`: on Linux, `open` and `bitrates`, with reads stamped by
  `SO_TIMESTAMPNS` through the crate's own `recvmsg`.
