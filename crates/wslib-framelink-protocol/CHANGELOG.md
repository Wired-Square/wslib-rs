# Changelog

## 0.2.0

- A frame definition's signal is 17 bytes on the wire, as the device has
  it: `FrameSignalDef` gains `quantity` (a `types::QTY_*`, or'd with
  `QTY_PER_SECOND` for a rate) after `value_type`. 0.1's 16-byte signals
  were NACKed by FRAME_DEF_ADD and misread FRAME_DEF_RESP.
- `frame_def::build_frame_def_add` returns `Result`: it refuses a signal
  whose `bit_length` is outside 1 to `SIGNAL_MAX_BITS` (64), as
  `Error::SignalBits`, and more signals than `MAX_SIGNALS` (255) fit in the
  count byte, as `Error::TooManySignals`, rather than truncating the count.
  It also refuses `RESERVED_IDS`, the signal store's `FRAME_DEF_ID_USER` and
  `FRAME_DEF_ID_DEVICE`, as `Error::ReservedFrameDefId`;
  `frame_def::next_available_id` skips them.

## 0.1.0

- The FrameLink protocol, version 4 only, moved in with its wire unchanged:
  `frame` (the 5-byte header, COBS from wslib-framing), and every message's
  payload in `types`, `dsig`, `capabilities`, `stream`, `frame_def`,
  `bridge`, `xform`, `generator`, `counter`, `persist`, `file_xfer`,
  `board_def` and `can_id`, with BLE `manufacturer_data`.
- `frame::parse_unstuffed`, the parser `parse_frame` runs after unstuffing,
  for a frame a stream decoder has already released.
- `PROTOCOL_VERSION` (4), `RULE_FORMAT` (2) and `SCHEMA_VERSION_MAX` (1) at
  the root, pinned by a test; changing one is a breaking release.
- `dsig::format_signal_key` and `parse_signal_key`, the board TOML's slug for
  a `SignalKey`, which now serialises.
- `types::INTERFACE_NAMES` and `frame_def::VALUE_TYPE_NAMES`, the tables
  behind `interface_name` and `value_type_name`.
- `file_xfer::file_crc32` is wslib-checksum's `crc32`.
- One `Error` for every parser, the signal key's and the manufacturer data's
  included; each message reads as it did.
- `stream::FrameMetadata` and `StreamFrame` serialise, `FrameMetadata` tagged
  by `kind` as `FrameHeader` is.
- `ts`: `ts_rs::TS` (ts-rs 12) on every serialised type.
- Wire enums are `#[non_exhaustive]`.
- `frame_def::CAN_FLAG_EXTENDED`, `CAN_FLAG_FD`, `CAN_FLAG_BRS` and
  `CAN_FLAG_RTR`, the firmware's CAN frame-def flag bits, pinned by a test.
