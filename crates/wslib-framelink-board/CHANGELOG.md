# Changelog

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
