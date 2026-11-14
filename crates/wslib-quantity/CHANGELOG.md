# Changelog

## 0.2.0

- `Dimension::Time` and `Unit::{Millisecond, Second, Minute, Hour, Day}`,
  parsed from `ms`, `s`, `min`, `h` and `d` in exact case (`S`, `H`, `MS`,
  `Min`, `D` and `m` stay `Other`) and from `millisecond(s)`, `sec(s)`,
  `second(s)`, `mins`, `minute(s)`, `hr(s)`, `hour(s)` and `day(s)` in any
  case. They convert exactly between each other.
- Auto-scaling moves a duration between ms, s, min and h. A value in `d`, or
  in any unit off its dimension's scale, is left as it is.
- Behaviour change: a value in `s`, `min` or `h` now auto-scales, where 0.1.0
  passed it through as `Other`.
- `Unit` and `Dimension` are `#[non_exhaustive]`.

## 0.1.0

- `Unit`: Home Assistant's spellings and the unambiguous tolerant forms of
  them, parsed infallibly, with an `Other` that keeps the original string.
- `Quantity`: a `Decimal` value and its unit, parsed from a state string,
  converted exactly within a dimension (temperature offsets included) and
  auto-scaled to the largest prefix that keeps it at or above 1.
- `Precision` and `format_decimal`: exact, fixed, at-most and magnitude
  places, rounded half away from zero, never `-0`.
