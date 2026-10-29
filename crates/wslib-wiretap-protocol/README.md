# wslib-wiretap-protocol

The vocabulary captures share, with no I/O and no storage:

- `Protocol`, a protocol as an archive stores it. Serde spells it as a query
  does (`can`, `modbus`, `serial`, also reading `modbus_rtu`); `as_str`,
  `Display` and `FromStr` use the stored tag (`modbus_rtu`, also reading
  `modbus`). `MODBUS_RTU_PROTOCOL` is that tag.
- `FrameKey`, a frame id with whether it is extended, and `format_frame_id`,
  its display form.
- `ProtocolFrames` and `FrameSelection`: frames selected by `(protocol,
  frame_id)` or by whole protocol, normalised so that empty selects
  everything.
- `PayloadQuery` and `Sampling`: which of one frame's payloads to read, the
  newest contiguous run or spread across the recording.
- `InventoryRow`, one frame identity with its count, first and last
  timestamps and longest length.

The off-by-default `ts` feature derives `ts_rs::TS` (ts-rs 12) on
`Protocol` (as `ArchiveProtocol`), `FrameKey`, `ProtocolFrames` and
`InventoryRow`; `cargo test --features ts` pins their declarations.

```toml
wslib-wiretap-protocol = { version = "0.1", registry = "wired-square" }
```
