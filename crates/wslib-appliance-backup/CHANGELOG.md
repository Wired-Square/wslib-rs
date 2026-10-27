# Changelog

## 0.1.1

Moved from `appliance-backup` 0.17.1 in wslib-appliance-rs; what differs:

- The bundle format, its `appliance-backup` tag and the console's
  `appliance-app-sections` are unchanged: a file either version wrote opens
  in the other.
- Audit rows and log lines carry the `wslib_appliance_backup` target (was
  `appliance_backup`). The line a scheduled write logs when it puts the
  backups directory back at `0700` is this crate's (was `appliance_core`'s).
- A take's or download's filename is escaped as an RFC 9110 quoted string
  by `wslib-http-scaffold`'s `attachment`, where 0.17.1 sent a `\` or `"` in
  the product's name as it was.
- `ApplianceState`, `Mount` and the other `wslib-appliance-core` items in
  this crate's signatures carry that crate's changes; see its changelog.
