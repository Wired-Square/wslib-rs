# Changelog

## 0.1.0

- `hostname`, `uptime`, `boot_id`, `kernel_release` and `os_name`: read from
  `/proc` and `/etc` on Linux, libc and sysctl on macOS, Win32 and the
  registry on Windows; `None` where the host can't answer. `HOSTNAME_SOURCE`
  names where `hostname` reads.
- `machine_id(app)`: systemd's app-specific id, keyed by `/etc/machine-id` or
  a Mac's `IOPlatformUUID`. `None` on Windows.
