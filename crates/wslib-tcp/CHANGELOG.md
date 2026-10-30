# Changelog

## 0.1.1

- thiserror's floor is 2.0.20.

## 0.1.0

- `connect`: a TCP stream to `host:port`, resolved on every call, each
  address tried in turn on an equal share of what remains of one budget.
- `resolve`, within a timeout, and `tcp_endpoint`, which brackets an IPv6
  literal.
- `TransportError` (non-exhaustive, with `duplicate`) and `ResolveError`, each
  message one short line. A budget too large for the clock counts as about 30
  years.
