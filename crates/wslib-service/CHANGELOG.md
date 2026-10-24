# Changelog

## 0.1.0

- `Daemon::new(name).grace(..).run(main)`: `main` on a runtime of its own,
  under the Windows service control manager, in a Windows console, under
  systemd or stopped by `SIGTERM` and `SIGINT`, and handed a `Stop` whose first
  poll means ready. Ending once asked is success and ending unasked a
  `Failure`, logged, with the panic hook replaced while `main` runs. Taken
  from the chassis's `appliance-service` and made generic.
- `private_directory`, `LogFile` and `Layout`: the state directory checked,
  the log file opened, rotated and reopened, and each platform's paths for
  them. Every refusal is a `Refused`, displayed as `refusing <path>: <because>`.
