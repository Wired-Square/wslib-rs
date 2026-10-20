# Changelog

## 0.1.0

- `ready`, `status`, `stopping` and `watchdog` send `READY=1`, `STATUS=`,
  `STOPPING=1` and `WATCHDOG=1` to `$NOTIFY_SOCKET`; `notify` sends any
  fields in one datagram. A path or, on Linux, an abstract `@` name. No
  libsystemd. A no-op when the variable is unset, and off Unix.
- `watchdog_interval` reads `WATCHDOG_USEC`, honouring `WATCHDOG_PID`.
- `feed_watchdog` behind the `tokio` feature: pings at half the interval until
  a stop future completes.
