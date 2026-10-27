# Changelog

## 0.1.3

- On Windows, `owner` returns `NotFound` for an object with no owner, where
  it read through a null SID. `Sid::of_account` and `Sid::account` return a
  failed sizing lookup's own error, such as `ERROR_NONE_MAPPED`, instead of
  retrying with empty buffers.
- On Unix, `PeerCredentials::new(uid, gid, pid)`, for a test that hands a
  handler credentials without a socket.

## 0.1.2

- Dependency floor raised to match the crates it shares a graph with:
  sha2 0.10.9 (was 0.10.1). No change to the API.

## 0.1.1

- On Unix, `peer_credentials(socket)`: the uid, gid and, on Linux and macOS,
  pid of a Unix socket's peer, std's or tokio's. `account_name(uid)`: the
  account's name from the passwd database, `None` for a uid with no entry.
  `libc` is now a dependency on every Unix (>= 0.2.174).
- On Windows, `Sid`: of an account by name (`Sid::of_account`), parsed from
  its `S-1-…` text, or from a `PSID`, with the `Account` it names. Beside it,
  `current_user`, `process_user(pid)`, `pipe_client_user(pipe)`,
  `owner(handle)` of a kernel object, and `service_account(service)`, the
  `NT SERVICE\<service>` SID, `None` for a service not installed.

## 0.1.0

- `hostname`, `uptime`, `boot_id`, `kernel_release` and `os_name`: read from
  `/proc` and `/etc` on Linux, libc and sysctl on macOS, Win32 and the
  registry on Windows; `None` where the host can't answer. `HOSTNAME_SOURCE`
  names where `hostname` reads.
- `machine_id(app)`: systemd's app-specific id, keyed by `/etc/machine-id` or
  a Mac's `IOPlatformUUID`. `None` on Windows.
