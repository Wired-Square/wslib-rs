# wslib-quantity

A measured value and its unit, in `rust_decimal`: units parsed from Home
Assistant's spellings and their unambiguous variants, exact conversion within
a dimension, auto-scaling, and display precision. No I/O, so it builds for
wasm.

```rust
use wslib_quantity::{Precision, Quantity};

let power = Quantity::parse("1234", Some("W")).unwrap();
assert_eq!(power.auto_scaled().display(Precision::Fixed(2)), "1.23 kW");
```

`Unit::parse` never fails: a spelling it can't place unambiguously, such as
`deg` or `mw`, is `Unit::Other`, which displays as written and converts to
nothing. Rounding is half away from zero on the decimal, and a zero never
prints as `-0`.

## Precision

| Precision    | Places                                       | `27.4710502624512` |
| ------------ | -------------------------------------------- | ------------------ |
| `Exact`      | every digit, trailing zeros dropped          | `27.4710502624512` |
| `Fixed(n)`   | exactly `n`, padded                          | `27.47` at 2       |
| `AtMost(n)`  | up to `n`, trailing zeros dropped            | `27.471` at 3      |
| `Magnitude`  | by the unrounded \|v\|, padded (below)       | `27.471`           |

`Precision::ha` is Home Assistant's rule: `Fixed` at an entity's
`display_precision`, else `AtMost(3)`.

| \|v\| (unrounded) | Magnitude places |
| ----------------- | ---------------- |
| ≥ 10 000          | 0                |
| ≥ 1 000           | 1                |
| ≥ 100             | 2                |
| below 100         | 3                |

`tests/vectors/magnitude.json` pins `Magnitude` case by case, for ports to
test against.

## Auto-scaling

| Unit                     | Scales to                                        |
| ------------------------ | ------------------------------------------------ |
| W, Wh, VA, var, A, V, Ah | the largest prefix keeping \|v\| ≥ 1, else the smallest |
| c/kWh, $/kWh             | $/kWh when \|$\| > 1, else c/kWh                 |
| ms, s, min, h            | the largest of them keeping \|v\| ≥ 1, else ms   |
| temperature, %, Hz, d, other | unchanged                                    |

A zero power, energy, current, voltage, charge or duration stays in its unit; a zero price is c/kWh.

## Resolution

`display_at` rounds to the nearest step, half away from zero, auto-scales,
and shows at most the places down to the step's first significant figure in
the unit shown: ⌈−log₁₀ step⌉, from 0 to 28. A step that is not a power of
ten is shown to its first significant figure, so `21.25` at `0.25` shows
`21.3`.

| Value            | Resolution  | `display_at`  |
| ---------------- | ----------- | ------------- |
| `6408 W`         | `1 W`       | `6.408 kW`    |
| `12994 W`        | `10 W`      | `12.99 kW`    |
| `21.46 °C`       | `0.5 °C`    | `21.5 °C`     |
| `68044 ms`       | `1 s`       | `1.13 min`    |
| `3598 s`         | `7 s`       | `1 h`         |
| `400 ms`         | `1000 ms`   | `0 s`         |
| `121.0956 c/kWh` | `0.1 c/kWh` | `1.211 $/kWh` |

A rounding that reaches the next unit carries into it, and a rounded zero
shows in the unit one step scales to. A step converts by ratio only, so a
temperature step must share the value's scale. A zero step shows every digit.
