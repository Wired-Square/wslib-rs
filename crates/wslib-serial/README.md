# wslib-serial

A serial line: its settings and the wire time of its bytes, the SLIP (RFC 1055)
and delimiter framers, and a port read by a task that reopens the line when it
goes away. The settings and framers need no feature and do no I/O.

```rust
use wslib_serial::{LineSettings, SerialEvent, SerialOptions};

let line = LineSettings::parse(9600, None, None, Some("even"))?; // 9600 8E1
let mut task = wslib_serial::open("/dev/ttyUSB0", line, SerialOptions::default())?;
while let Some(event) = task.next_event().await {
    if let SerialEvent::Read { bytes, at } = event {
        // each read's bytes, unframed, and when the read returned
    }
}
```

The framers count where each frame ended in their input, as wslib-modbus's
RTU stream does, so a caller can back-date all three by the line's wire time.

## Features

None is on by default.

- `task`: `open`, a tokio task owning the port. Read-only on Unix opens the
  path `O_RDONLY` with raw termios and `TIOCEXCL`, so no write path exists; it
  needs neither serialport nor libudev. A loss is reopened after a wait that
  doubles from `reopen` up to `reopen_max`.
- `ports`: `ports`, the ports the OS lists, with their USB identity, through
  serialport.
- `write`: `Access::ReadWrite`, `SerialWriter`, whose writes the task serves
  between reads, and `SerialPort`, a read-write port for a protocol that
  drives the line itself. Off by default; without it no write path is
  compiled.

serialport always builds on Windows, where the task reads every port through
it.
