# Changelog

## 0.2.0

- `From<LineSettingsError> for String` is gone, so `?` keeps a
  `LineSettingsError` typed.
- `SerialError::Open` and `Read` name only their own layer. The `io::Error`
  comes only through `source()`, which `Read` now returns too.
- `SerialPort::write`, `set_dtr` and `set_rts`, and `SerialWriter`'s, answer
  with a `SerialError` in place of an `io::Error`: `Write` holds the
  `io::Error` of a write, or of a DTR or RTS change, that failed.
- `SerialError::Panicked`: a blocking call on the port panicked, on Windows
  or with `write`, in a read, a write or a DTR or RTS change. A read's is
  the task's `Disconnected`, and the task reopens as after any loss. A
  write's or a control line's is that call's answer. A write that waits for
  a read that panicked is `Write` with `NotConnected`, the next read
  reporting the read's `Panicked`.
- `SerialError::Cancelled`: the runtime cancelled a blocking call on the
  port before it ran.

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
