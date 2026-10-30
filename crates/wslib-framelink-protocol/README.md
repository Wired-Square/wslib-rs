# wslib-framelink-protocol

The FrameLink protocol with no I/O: the frame, every message's payload, the
signal vocabulary and its identity tuple, and a device's BLE manufacturer
data. It speaks protocol version 4 only.
[`docs/framelink.md`](docs/framelink.md) specifies the wire.

```rust
use wslib_framelink_protocol::{frame, types};

let wire = frame::build_frame(types::MSG_PING, types::FLAG_ACK_REQ, 1, &[]);
let reply = frame::parse_frame(&wire[1..wire.len() - 1])?;
```

- `frame`: a 5-byte header and the payload, COBS-stuffed between `0x00`s.
  A block is unstuffed before its version is read.
- `types`: message types, flags, NACK codes, and the closed vocabularies of
  interface types, peripheral kinds, roles, quantities, aspects and metadata
  ids, with their names and board-TOML slugs. `INTERFACE_NAMES` and
  `frame_def::VALUE_TYPE_NAMES` list theirs for enumerating.
- `dsig`: device signals. A signal is identified by `SignalKey`
  (`target_type`, `target_index`, `role`, `quantity`, `aspect`, `channel`)
  and its writable flag; `signal_id` is a handle the device renumbers.
  `format_signal_key` and `parse_signal_key` are the board TOML's slug for a
  key, `semantic_signal_name` a display name derived from it.
- `capabilities`, `stream`, `frame_def`, `bridge`, `xform`, `generator`,
  `counter`, `persist`, `file_xfer`, `board_def`, `can_id`: each message's
  builders and parsers.
- `manufacturer_data`: the six bytes a device advertises over BLE.

`PROTOCOL_VERSION`, `RULE_FORMAT` and `SCHEMA_VERSION_MAX` are the formats
this crate speaks; changing one is a breaking release.

The off-by-default `ts` feature derives `ts_rs::TS` (ts-rs 12) on every type
that serialises; `cargo test --features ts` pins their declarations.

```toml
wslib-framelink-protocol = { version = "0.1", registry = "wired-square" }
```
