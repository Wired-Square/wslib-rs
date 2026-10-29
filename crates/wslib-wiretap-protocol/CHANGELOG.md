# Changelog

## 0.1.0

- `Protocol`, serialised `can`, `modbus`, `serial` (TS `ArchiveProtocol`) and
  stored as `can`, `modbus_rtu`, `serial` (`as_str`, `Display`), reading either
  spelling; and `MODBUS_RTU_PROTOCOL`.
- `FrameKey`, `format_frame_id`, `ProtocolFrames`, `FrameSelection`,
  `PayloadQuery`, `Sampling` and `InventoryRow`, with the serde shapes and TS
  declarations they had before the move.
