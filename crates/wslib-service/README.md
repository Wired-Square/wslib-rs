# wslib-service

A background service from one call, under launchd, systemd or the Windows
service control manager, and the checks its own state directory and log file
need.

```rust
use std::process::ExitCode;
use std::time::Duration;

fn main() -> ExitCode {
    wslib_service::Daemon::new("widgets")
        .grace(Duration::from_secs(15))
        .run(|stop| async move { serve(stop).await })
        .map_or_else(ExitCode::from, |()| ExitCode::SUCCESS)
}
```

## What's here

- **`Daemon::run(main)`** runs `main` on a multi-thread Tokio runtime of its
  own, the one `#[tokio::main]` builds, so call it from a plain `fn main`. It
  hands `main` a `Stop` and returns what `main` returned. **Ending once
  stopped is `Ok`; ending unasked, an error or a panic, or overrunning the
  grace is a `Failure`**, so the service manager restarts it. `Failure`
  converts to a failing `ExitCode`. The runtime is torn down, at most 1 s,
  before `run` returns, so a process can re-execute itself after.
- **The first poll of `Stop` means ready**, on every platform: running to the
  service control manager, `READY=1` to systemd. Poll it only once serving,
  or take `stop.ready()` and call `Ready::send(Some("status"))` yourself,
  which sends `READY=1` and `STATUS=` in one datagram, once; `Ready::status`
  updates `STATUS=` after. Take `stop.ready()` before handing the `Stop` down
  to a library: taking it later cannot undo a ready the first poll sent. `Stop::manager()` says which `Manager` ran it, and
  ready logs one `info` line naming it.
- **How it stops is the manager's.** Under the service control manager, a
  stop, preshutdown or shutdown control, logged by name, with checkpoints
  while starting and stopping. On Windows outside it, Ctrl-C in the console.
  Under systemd (`$NOTIFY_SOCKET` on Linux), `SIGTERM`, answered with
  `STOPPING=1` and `EXTEND_TIMEOUT_USEC` in one datagram, so a test expecting
  a bare `STOPPING=1` needs updating. systemd is Linux-only here: unlike
  `wslib-systemd-notify`, which sends on any unix with `$NOTIFY_SOCKET`, `run`
  tells nothing off Linux. Elsewhere, as under launchd, `SIGTERM` or
  `SIGINT`. The signal is logged at `info`.
- **`Stop::token()`** is cancelled at the stop. Cancelling it yourself is a
  stop of your own: a success, under the same grace, reported as stopping to
  the service control manager and as nothing to systemd, so a process that
  re-executes itself keeps its unit.
- **`grace`**, 15 s unless set, bounds everything `main` does after a stop of
  either kind; past it `main` is dropped and `run` returns
  `Failure::Overran`. Keep any drain timeout of your own inside it. The
  service control manager's preshutdown timeout is raised to it plus 5 s,
  and systemd is sent `EXTEND_TIMEOUT_USEC` of the same.
- **The systemd watchdog** is fed from a task of its own from the start of
  `run` until `main` returns, so it shows the runtime is alive, not that the
  service serves. `$NOTIFY_SOCKET` and `$WATCHDOG_USEC` are left set.
- **An error, a panic, ending unasked or overrunning is logged** through
  `tracing`, or to stderr before a subscriber is installed; an error with
  `{:#}`, so an anyhow chain is whole. On Windows an error or a panic also
  goes to the Application event log under the service's name, registered as
  its event source on first start. While `main` runs the panic hook logs where
  a panic happened; the previous hook is restored once it returns. It is
  replaced, not chained, so install a hook of your own inside `main`.
- **Under the service control manager, a failure is a service-specific exit
  code of 1.** The installer sets what follows: `sc failure <name> reset=
  86400 actions= restart/5000` and `sc failureflag <name> 1`. A start that
  finds no failure actions logs a warning.
- **Feature `testing`**: `testing::stop()` gives a `Stop` under
  `Manager::Detached` and a `Recorder`, for a consumer's tests in any Tokio
  runtime, without `Daemon::run`. `Recorder::stop()` is the manager's stop;
  `Recorder::ready().await` resolves once ready is sent, with its status;
  `Recorder::told()` says whether ready was sent and with what status, the
  statuses sent alone, and whether the service stopped itself.
- **`private_directory(dir)`** refuses a state directory anyone else could
  use: on unix one not owned by this user, a link, group-writable, open to
  others, or with an extended ACL on macOS; on Windows one whose owner or DACL
  admits anyone but this user, SYSTEM and Administrators, or whose parent lets
  them delete from it or resecure it. The `Held` it returns keeps both open on
  Windows, so neither can be renamed.
- **`LogFile::open(path)`** is the log where nothing keeps a daemon's output:
  `0640` whatever the umask (owner, SYSTEM and Administrators on Windows), never
  a link or a FIFO, reopened after newsyslog moves it, and on Windows rotated
  to `.1` at 10 MiB. `Arc<LogFile>` is a `MakeWriter`, so
  `wslib_telemetry::Telemetry::writer` takes it. `LogFile::builder()` sets how
  often it checks its path and the size it rotates at.
- **`Refused`** is every check's error, displayed as `refusing <path>:
  <because>`; `Refused::new` builds one for a path of your own. On unix,
  `no_extended_acl(path)` is the macOS ACL check on its own, `Ok` elsewhere.
- **`Layout::macos`, `windows`, `systemd` and `for_this_os`** name where the
  state directory and log go on each: `/Library/Application Support` and
  `/Library/Logs`, `%ProgramData%`, or systemd's `$STATE_DIRECTORY` and
  `$LOGS_DIRECTORY`, with no log file since journald keeps the output.

## A command instead of the service

A CLI verb that runs and exits, such as `widgets check-config`, is handled
before `Daemon::run`, on a runtime of its own from
`tokio::runtime::Builder::new_multi_thread().enable_all().build()`: `run`
counts an `Ok` without a stop as `Failure::Unasked`.

## Moving from the chassis's `run_as_service`

An error after the stop, or overrunning the grace, is now a `Failure`, and a
service-specific exit code of 1 under the service control manager. The old
wrapper counted any end after a stop as success.

## Running under

- **systemd**: `Type=notify`, `WatchdogSec=` if you want the watchdog,
  `TimeoutStopSec=` at least the grace plus 5 s, `Restart=on-failure`.

  ```ini
  [Service]
  Type=notify
  ExecStart=/usr/bin/widgets
  WatchdogSec=30
  TimeoutStopSec=20
  Restart=on-failure
  ```

- **launchd**: `ExitTimeOut` at least the grace (20 s by default), and
  `KeepAlive` so a failure is restarted.
- **The service control manager**: `sc failure <name> reset= 86400 actions=
  restart/5000` and `sc failureflag <name> 1`.
- **A container or a Home Assistant add-on**: `SIGTERM` is the stop, and the
  `SIGKILL` follows 10 s later by default, so keep the grace under 10 s. Log
  to stdout, where the container's log is.

## Not covered

- Installing, registering or removing the service: the installer's, as are
  the directories `Layout` names.
- A Windows console's close, logoff and shutdown events; only Ctrl-C stops it
  there.
