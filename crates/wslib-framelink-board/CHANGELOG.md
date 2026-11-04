# Changelog

## 0.3.3

- `mcu-flash` takes wslib-mcu-flash 0.1 to 0.3; `UsbAccess` is the same in
  all three.

## 0.3.2

- `EditableBoardDef::put_frame_def` takes a device's frame definition and
  inserts it, or replaces the header and signals of the one already there.
  It keeps the definition's name and description. A signal keeps the slug,
  name and unit of the old signal whose slug parses as its id, or else of an
  unmatched old signal with a non-numeric slug at the same bits, each old
  signal at most once; `names` overrides signal names by id.
- `EditableBoardDef::retain_active` drops the frame definitions, generators
  and transformers the device does not hold.
- `sync_frame_defs` names every value type and byte order as the protocol
  does: an array signal is `array`, no longer `unsigned`. It shares
  `put_frame_def`'s mapping from a device definition to the board TOML.
- A CAN frame definition's `match_any` flag is written to the board TOML,
  where it was dropped, and a flag bit with no label is written as hex such
  as `"0x20"`.

## 0.3.1

- `mcu-flash` accepts wslib-mcu-flash 0.1 or 0.2; `UsbAccess` is the same in
  both.

## 0.3.0

- A frame definition's signal keeps its `quantity` through the board TOML.
  `FrameSignalDefToml`, `FrameSignalDisplayInfo` and `EditableFrameSignal`
  gain `quantity` (a `types::QTY_*`). The TOML holds it as `quantity`, a
  quantity slug such as `"temperature"` or `"temperature_per_s"`, or as a
  `0x` hex string such as `"0x16"` for a quantity this crate has no slug
  for; raw is left out, and anything else fails the load. `sync_frame_defs`
  and the editable writer write it, and `toml_schema::quantity_to_toml`
  gives the slug or hex.

## 0.2.0

- On wslib-framelink-protocol 0.2: an indicator trigger's frame definition
  carries the 17-byte signal the device expects, with `quantity` raw.

## 0.1.0

- FrameLink board definitions moved in, their TOML and JSON unchanged: the
  schema, `parse_board_def` and `load_board_def`, `editable`, `display`,
  `resolve`, `scaffold`, `sync`, `compress`, `selectable`'s
  `categorise_signals`, LED discovery and indicator triggers, and the
  embedded boards.
- The signal-key slug is wslib-framelink-protocol's `dsig::format_signal_key`
  and `parse_signal_key`.
- One `Error`, `resolve`'s included; `toml_schema::parse_hex_key` returns
  the `ParseIntError`.
- `IndicatorConfig::colour` and `display::ColourPreset` and
  `COLOUR_PRESETS`; `colour` still serialises as `color`.
- TOML is read and written by toml_edit alone.
- `sync` labels CAN frame-def flags as the firmware defines them:
  `extended`, `fd`, `brs` and `rtr` (0x02 was written as `rtr` and 0x04 as
  `fd`).
- `UsbAccess` converts into wslib-mcu-flash's `endpoint::UsbAccess` with the
  `mcu-flash` feature.
