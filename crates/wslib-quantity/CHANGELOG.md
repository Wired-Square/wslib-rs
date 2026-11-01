# Changelog

## 0.1.0

- `Unit`: Home Assistant's spellings and the unambiguous tolerant forms of
  them, parsed infallibly, with an `Other` that keeps the original string.
- `Quantity`: a `Decimal` value and its unit, parsed from a state string,
  converted exactly within a dimension (temperature offsets included) and
  auto-scaled to the largest prefix that keeps it at or above 1.
- `Precision` and `format_decimal`: exact, fixed, at-most and magnitude
  places, rounded half away from zero, never `-0`.
