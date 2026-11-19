# Changelog

## 0.2.0

- `From<LineSettingsError> for String` is gone, so `?` keeps a
  `LineSettingsError` typed.
- `SerialError::Open` and `Read` name only their own layer. The `io::Error`
  comes only through `source()`, which `Read` now returns too.
- A port read on the blocking pool (on Windows, and with `write`) resumes a
  blocking call's panic on the caller, as an inline call would, in place of
  an `io::Error` holding its text. A call the runtime cancels before it runs
  fails as `Interrupted`.

## 0.1.3

- `SerialWriter::set_dtr` and `set_rts`, and the same on `SerialPort`: a
  control line set between reads, in turn with writes, as a reset pulse
  needs.
- Closing a read-write port discards output the device never took, so Linux
  doesn't hold the close for its `closing_wait`.
- A write returns once its bytes are queued, not when they are sent, so a
  device halted by flow control can't hold a close behind it.

## 0.1.2

- thiserror's floor is 2.0.20.

## 0.1.1

- `SerialPort::try_clone`: a second handle on an idle port, for a write
  that can't wait for a read in flight.

## 0.1.0

- `LineSettings` and `Parity`: a line's rate and character framing, parsed
  with 8N1's defaults and validated; `bits_per_char`, a character's start,
  data, parity and stop bits; and `wire_time`, a run of bytes at the rate.
- `slip`: SLIP (RFC 1055) both ways, with a decoder that can cap a frame, and
  `DelimiterFramer`; both report each frame's end offset.
- `task`: `open`, a port read by a tokio task that reopens it after a wait
  doubling from `reopen` to `reopen_max`, and can wait for a port that isn't
  there yet. Read-only on Unix is `O_RDONLY` with raw termios, through libc.
- `ports`: the ports the OS lists, with their USB identity.
- `write`: read-write ports, `SerialWriter` and `SerialPort`.
