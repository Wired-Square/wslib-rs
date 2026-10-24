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
  own and hands it a `Stop`. **Ending once asked to stop is success, however
  `main` ended; ending unasked, by returning or panicking, is a failure**, so
  the service manager restarts it. `Failure` says how, and converts to a
  failing `ExitCode`.
- **The first poll of `Stop` means ready**, on every platform: running to the
  service control manager, `READY=1` to systemd. Poll it only once serving.
  `Stop::manager()` says which `Manager` ran it, and the first poll logs one
  `info` line naming it.
- **How it stops is the manager's.** Under the service control manager, a
  stop, preshutdown or shutdown control, with checkpoints while starting and
  stopping. On Windows outside it, Ctrl-C in the console. Under systemd
  (`$NOTIFY_SOCKET` on Linux), `SIGTERM`, answered with `STOPPING=1`, and the
  watchdog fed while `main` runs. Elsewhere, as under launchd, `SIGTERM` or
  `SIGINT`, logged at `info`.
- **`grace`**, 15 s unless set, is how long `main` takes to end once stopped.
  The service control manager's preshutdown timeout is raised to it plus 5 s,
  and systemd is sent `EXTEND_TIMEOUT_USEC` of the same. launchd's
  `ExitTimeOut` is the plist's, 20 s by default.
- **An error, a panic or ending unasked is logged** through `tracing`, or to
  stderr before a subscriber is installed. On Windows an error or a panic also
  goes to the Application event log under the service's name, registered as
  its event source on first start. While `main` runs the panic hook logs where
  a panic happened; the previous hook is restored once it returns.
- **Under the service control manager, a failure is a service-specific exit
  code of 1.** The installer sets what follows: `sc failure <name> reset=
  86400 actions= restart/5000` and `sc failureflag <name> 1`. A start that
  finds no failure actions logs a warning.
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
  <because>`.
- **`Layout::macos`, `windows`, `systemd` and `for_this_os`** name where the
  state directory and log go on each: `/Library/Application Support` and
  `/Library/Logs`, `%ProgramData%`, or systemd's `$STATE_DIRECTORY` and
  `$LOGS_DIRECTORY`, with no log file since journald keeps the output.

## Not covered

- Installing, registering or removing the service: the installer's, as are
  the directories `Layout` names.
- Enforcing `grace`: a `main` that does not end is the service manager's to
  kill.
- A Windows console's close, logoff and shutdown events; only Ctrl-C stops it
  there.
