# Changelog

## 0.2.0

- `ingest`, the binary ingest protocol, both ends, and `ServerSession`, its
  server end as a sans-io state machine. The wire is unchanged; the Rust names
  say catalogue (`MSG_CATALOGUE_GET`, `CatalogueGet`,
  `ServerSession::answer_catalogue` and the rest), and its CRC-32 is
  wslib-checksum's.
- `ingest::encode_batch_from`: as many records from the front of a list as fit
  one `BATCH`, encoded, and how many that is; byte for byte the three calls it
  wraps.
- `ingest::RawTap`: a serial line's reads as raw serial records, each stamped
  when its last byte arrived, never before the epoch, and numbered by read from
  the line's open. `RawTap::new(baud, bits_per_char)` takes the line rate and
  the bits per character, start, parity and stop included, as exact integers.
- `Hello`'s `Debug` prints the token's length, not the token.
- `import`, the HTTP capture-import body, and `testpattern`, the CAN link
  check, both ends of each.
- Depends on wslib-can and wslib-checksum, each without features.

## 0.1.0

- `Protocol`, serialised `can`, `modbus`, `serial` (TS `ArchiveProtocol`) and
  stored as `can`, `modbus_rtu`, `serial` (`as_str`, `Display`), reading either
  spelling; and `MODBUS_RTU_PROTOCOL`.
- `FrameKey`, `format_frame_id`, `ProtocolFrames`, `FrameSelection`,
  `PayloadQuery`, `Sampling` and `InventoryRow`, with the serde shapes and TS
  declarations they had before the move.
