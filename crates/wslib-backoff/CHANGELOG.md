# Changelog

## 0.1.2

- Dependency floor raised to match the crates it shares a graph with:
  tokio 1.47 (was 1.2). No change to the API.

## 0.1.1

- Dependency floor raised to what the crate's tests build against: tokio 1.2.

## 0.1.0

- `Backoff`: delays growing by a multiplier from an initial value to a cap,
  1 s to 30 s doubling by default, with optional jitter and a reset on
  success.
- `retry` and `reconnect` behind the `tokio` feature: loops that run an
  attempt, wait by the backoff after a failure and reset it on success.
