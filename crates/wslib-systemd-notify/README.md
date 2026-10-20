# wslib-systemd-notify

Tells systemd a service is ready, stopping or still alive: the sd_notify
protocol, a datagram to the socket in `$NOTIFY_SOCKET`, written directly, so
a static musl build needs no libsystemd.

```rust
wslib_systemd_notify::ready()?;
wslib_systemd_notify::status("serving on :443")?;

// With the `tokio` feature; the runtime drops it when the process ends:
tokio::spawn(wslib_systemd_notify::feed_watchdog(std::future::pending()));

// On shutdown:
wslib_systemd_notify::stopping()?;
```

## What's here

- **`ready`, `status`, `stopping`, `watchdog`**: send `READY=1`, `STATUS=…`,
  `STOPPING=1` and `WATCHDOG=1`. **`extend_timeout`** sends
  `EXTEND_TIMEOUT_USEC=`, asking for that much more time from now for a slow
  start or stop. **`notify`** sends any `KEY=value` fields in one datagram.
  A newline in a value, or a key that is empty or holds `=`, is
  refused as `InvalidInput` rather than sent as an extra line. The whole
  datagram is refused, so a bad `STATUS` sent with `READY=1` in one `notify`
  holds back the `READY` too.
- Every call is a successful no-op when `$NOTIFY_SOCKET` is unset or empty, so
  the same binary runs outside systemd, and on targets other than Unix. The
  socket is an absolute path, or on Linux an abstract name written `@name`.
  The variable is read on every call and never unset.
- **`watchdog_interval`**: `WATCHDOG_USEC` as a `Duration`, or `None` when it
  is unset or invalid or `WATCHDOG_PID` names another process.
- **`feed_watchdog(stop)`** (feature `tokio`): sends `WATCHDOG=1` at once and
  then at half the interval until `stop` completes. A full socket skips that
  ping; any other failed send ends it with the error. Without a watchdog
  interval it sends nothing and only waits for `stop`, so it can be spawned
  or joined unconditionally.

  Don't stop it when shutdown starts: a long drain or flush still needs
  pings. Pass a future that completes when the process is really done, or
  `std::future::pending()` and let the runtime drop the task.

  A ping from its own task proves the runtime is alive, not that the service
  answers: a frozen process trips the watchdog, a deadlocked handler on a live
  runtime doesn't. Ping from the work itself if that matters.

## The unit file

```ini
[Service]
Type=notify
WatchdogSec=30
NotifyAccess=main
```

`Type=notify` holds the unit in "activating" until `READY=1`, so units ordered
after it start once it is actually serving. `WatchdogSec=` sets
`WATCHDOG_USEC` and restarts the service (with `Restart=on-watchdog` or
`always`) when no ping arrives within it. `NotifyAccess=main`, the default
for `Type=notify`, accepts messages only from the main process; use `all` if
a child sends them.

The watchdog's default signal is `SIGABRT`, which dumps core; `WatchdogSignal=`
changes it. With systemd-coredump, that core is the process's memory on disk,
secrets included; set `WatchdogSignal=SIGTERM` or `LimitCORE=0` if that
matters.

## Re-exec

`STOPPING=1` tells systemd the process is going away. A service that then
re-execs itself on the same PID is SIGKILLed at `TimeoutStopSec=`. Under
`Type=notify`, send `notify(&[("RELOADING", "1")])` before the exec and
`ready()` once the new image is up. `Type=notify-reload` also wants
`MONOTONIC_USEC=` with the reload, a clock std can't read, so this crate
doesn't offer it.
