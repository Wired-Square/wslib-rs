# Changelog

## 0.1.1

- The `tokio` feature's floor is tokio 1.47, the rest of the workspace's, so a
  crate on both builds at its dependency floors.

## 0.1.0

- `ready`, `status`, `stopping` and `watchdog` send `READY=1`, `STATUS=`,
  `STOPPING=1` and `WATCHDOG=1` to `$NOTIFY_SOCKET`; `notify` sends any
  fields in one datagram. A path or, on Linux, an abstract `@` name. No
  libsystemd. A no-op when the variable is unset, and off Unix.
- `extend_timeout` sends `EXTEND_TIMEOUT_USEC=` for a slow start or stop.
- `watchdog_interval` reads `WATCHDOG_USEC`, honouring `WATCHDOG_PID`.
- `feed_watchdog` behind the `tokio` feature: pings at half the interval until
  a stop future completes. A full socket skips one ping rather than ending it.
  tokio is taken without default features.
