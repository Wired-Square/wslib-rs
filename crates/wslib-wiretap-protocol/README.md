# wslib-wiretap-protocol

The vocabulary captures share, and the wire protocols they travel by, with no
I/O and no storage:

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
- `ingest`: the binary ingest protocol, both ends: framing, the handshake,
  batches of CAN, Modbus and raw serial records, the catalogue pull and
  status, and `ServerSession`, the server's end as a sans-io state machine.
  `encode_batch_from` fits and encodes one `BATCH` from the front of a list,
  so its base and count can't disagree; `RawTap` cuts a serial line's reads
  into raw serial records, each stamped when its last byte arrived, from the
  line rate and bits per character it is given.
- `import`: the HTTP capture-import body, both ends: a versioned header, then
  CAN records with the ingest CAN record's words.
- `testpattern`: two endpoints proving a CAN link carries what it claims to,
  including a sweep across every data length code. `Responder` is the reply
  side as a sans-io state machine.

The wire is a contract with ends this crate doesn't build: the ingest, import
and Test Pattern tests pin their bytes.

The off-by-default `ts` feature derives `ts_rs::TS` (ts-rs 12) on
`Protocol` (as `ArchiveProtocol`), `FrameKey`, `ProtocolFrames` and
`InventoryRow`; `cargo test --features ts` pins their declarations.

```toml
wslib-wiretap-protocol = { version = "0.2", registry = "wired-square" }
```
