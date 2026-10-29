# wslib-modbus

Modbus for a device on the other end of a link: the wire facts, a register map
written as TOML and decoded and encoded against it, poll schedules on a clock
the caller owns, a register sweep for a device with no map, and a Modbus TCP
client, poller and poll task. The pure parts need no feature and do no I/O.

```toml
[meta.modbus]
device_address = 1
register_base = 0          # 0: protocol addresses; 1: traditional 3xxxx/4xxxx
default_interval = 5000    # ms
default_byte_order = "big"
default_word_order = "little"

[frame.modbus.battery_status]   # one read of a register block
register_number = 13019
register_type = "input"          # input | holding | coil | discrete
length = 9                       # registers
tx.interval_ms = 10000
signals = [                      # bit fields of the block
  { name = "Battery_SoC", start_bit = 48, bit_length = 16, factor = 0.1, unit = "%" },
]
```

```rust
use wslib_modbus::{ModbusManifest, decode_frame};

let manifest = ModbusManifest::parse(&text)?;
let frame = &manifest.frames[0];
for signal in decode_frame(frame, &registers, &manifest.meta) {
    println!("{} = {} {}", signal.name, signal.value, signal.unit.unwrap_or_default());
}
```

A signal's `byte_order` and `word_order` fall back to `[meta.modbus]`'s
defaults, so a device that stores 32-bit values low word first needs saying so
once. A write encodes in the same orders, so it decodes back to its value; a
signal of no bits, a numeric one over 64 bits, or one past the bank's 65 536
addresses is skipped at parse, and `validate` reports it. Scaling is
exact (`3374 × 0.1` is `337.4`). A coil or discrete frame has one order, eight
to a byte and least significant bit first.

`validate` reports what is wrong in a catalogue's `[meta]` and
`[frame.modbus]` sections as field paths and messages; it reads no other
section.

## Features

None is on by default.

- `tcp`: `ModbusTcp`, which connects lazily, resolves its endpoint on every
  connect and drops the socket on any transport error, and `Poller`, which
  reads what is due over a connection it borrows. Neither retries nor backs
  off. Builds on macOS, iOS, Linux and Windows.
- `task`: `spawn`, a task on the ambient tokio runtime owning a connection and
  a poller, reconnecting with capped exponential backoff.
- `write`: `ModbusTcp`'s writes and, with `task`, `PollTask::writer`. Without
  it no write path is compiled in; Cargo unions features across a build, so
  check with `cargo tree -e features -i wslib-modbus`.
- `testing`: `testing::device`, a fake Modbus TCP device on loopback that
  answers each request with a closure.
- `ts`: `ts_rs::TS` (ts-rs 12) on every serde type. `Finding` exports as
  `ValidationError`. Nothing here writes a `.ts` file.

No tokio-modbus type appears in the API.
