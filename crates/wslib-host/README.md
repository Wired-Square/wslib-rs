# wslib-host

What a host says about itself, read from the kernel and `/etc` rather than
asked of a command or a bus: its name, uptime, boot id, kernel release, OS
name, and a stable machine id per app.

```rust
use uuid::Uuid;

const MY_APP: Uuid = Uuid::from_u128(0x6e882fe4_9003_4dc4_9739_89aa7425c9b9);

let name = wslib_host::hostname();
let up = wslib_host::uptime();
let id = wslib_host::machine_id(MY_APP);
```

## What's here

Every reader returns `None` rather than an error when the host can't answer;
`HOSTNAME_SOURCE` names where `hostname` reads, for the log line. The crate
logs nothing itself.

| Reader           | Linux                               | macOS                         | Windows                           |
| ---------------- | ----------------------------------- | ----------------------------- | --------------------------------- |
| `hostname`       | `/proc/sys/kernel/hostname`         | `gethostname`, first label    | DNS host name, no domain          |
| `uptime`         | `/proc/uptime` (`CLOCK_BOOTTIME`)   | `CLOCK_MONOTONIC`             | `GetTickCount64`                  |
| `boot_id`        | `/proc/sys/kernel/random/boot_id`   | `None`                        | `None`                            |
| `kernel_release` | `/proc/sys/kernel/osrelease`        | `kern.osrelease`              | e.g. `10.0.26200.9457`            |
| `os_name`        | `PRETTY_NAME` from `/etc/os-release`| e.g. `macOS 26.6.2`           | e.g. `Windows 11 Pro 25H2`        |
| `machine_id`     | from `/etc/machine-id`              | from `IOPlatformUUID`         | `None`                            |

- **`hostname`** is the running name, not `/etc/hostname`. Under a unit's
  `ProtectHostname=yes` it is the name when the service started.
- **`uptime`** counts sleep and doesn't jump when the wall clock is set.
- **`os_name`** on Windows names Windows 11 for builds from 22000, which the
  registry's `ProductName` still calls Windows 10.
- **`peer_credentials(socket)`** (Unix) is a Unix socket peer's effective
  uid and gid at `connect()`, and its pid on Linux and macOS.
  **`account_name(uid)`** looks the uid up in the passwd database; it blocks,
  as a directory service may answer it.
- **`Sid`** (Windows) is an account's SID by name or from its text, with the
  `Account` it names. `current_user`, `process_user(pid)` and
  `pipe_client_user(pipe)` read a process token's user, `owner(handle)` a
  kernel object's owner, and `service_account(service)` the
  `NT SERVICE\<service>` SID, `None` for a service that is not installed.
- **`machine_id(app)`** is systemd's `sd_id128_get_app_specific`: an
  HMAC-SHA256 of `app` keyed by the machine id, as a v4 UUID. It survives a
  rename and tells another app nothing about the machine id or its own id. On
  Linux it equals `systemd-id128 machine-id --app-specific=<app> -u`; on
  macOS the `IOPlatformUUID` stands in for the machine id. An uninitialised
  or all-zero machine id gives `None`.
