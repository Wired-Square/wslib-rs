# Changelog

## 0.1.0

- `Daemon::new(name).grace(..).run(main)`: `main` on a runtime of its own,
  under the Windows service control manager, in a Windows console, under
  systemd or stopped by `SIGTERM` and `SIGINT`, handed a `Stop`, and its value
  returned. Ready is the `Stop`'s first poll, or `Ready::send` once
  `Stop::ready` is taken, with `STATUS=` in the same datagram. `Stop::token`
  is cancelled at the stop, and cancelling it is a stop of the app's own, which
  sends systemd nothing. Ending once stopped is success; ending unasked, in
  error, in a panic or past the grace is a `Failure`, logged, with the panic
  hook replaced while `main` runs and the runtime torn down within 1 s.
  Taken from the chassis's `appliance-service` and made generic.
- `private_directory`, `LogFile` and `Layout`: the state directory checked,
  the log file opened, rotated and reopened, and each platform's paths for
  them. Every refusal is a `Refused`, displayed as `refusing <path>: <because>`
  and built with `Refused::new` for a path of the product's own; on unix,
  `no_extended_acl` is the macOS ACL check alone.
- Each stop logs one `info` line with the grace: the signal, the service
  control manager's control, or a stop by the service itself.
- Feature `testing`: `testing::stop()`, a `Stop` under `Manager::Detached` and
  the `Recorder` that stops it and keeps what it was told, for a consumer's
  tests.
