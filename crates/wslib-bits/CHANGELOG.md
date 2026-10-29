# Changelog

## 0.1.0

- `extract_bits` and `extract_field`: a bit field by position, byte order and
  sign, and in a bank's ordering (`BitOrder`), word swap included. Exact to 64
  bits; a field over 128 bits reads as NaN.
- `apply_word_swap`, `format_hex`, `decode_text` and `format_unix_time`.
- `scale` and `format_decimal` behind the `decimal` feature: `raw × factor +
  offset` in exact `Decimal`.
- `PayloadField` and `ScaledField`, a field cut from a payload without a
  schema.
- `frame_id`: a frame id read out of a framed message, and the ids a CAN mask
  accepts.
- `groups`: a payload cut into byte or bit-width groups, each read four ways.
- `hex`: a typed hex byte string, strict or lenient.
- `register`: a Modbus register as hex, u16, s16 and text; two as u32, s32
  and f32.
- `SignalFormat`, a signal's format, and behind the `display` feature
  `DisplayHint`, its display value.
- `ts`: `ts_rs::TS` on every serde type, under ts-rs 12.
