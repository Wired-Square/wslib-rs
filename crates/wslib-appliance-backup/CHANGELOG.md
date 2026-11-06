# Changelog

## 0.2.1

- Pins `wslib-appliance-core` at 0.1.4.

## 0.2.0

- Breaking: `Sections::restore` takes `chosen: &Chosen`, was the chosen
  section names; an implementer reads `chosen.app` where it read `chosen`,
  and may honour `chosen.items` through `Chosen::restores_item`.
- `Sections::items(from)`: the items within each section a restore may
  choose among, empty by default. Inspect, at both routes and the console's
  hook, reports them for the sections the bundle carries and `names` answers.
- A restore hands `restore` the chosen items of the sections it applies.
  Every restore route, first-run and the console's hook included, refuses an
  item outside a chosen section, more than 512 items, an item not named as an
  app is, or one its section does not list; the session and local routes
  refuse the first three before the proof.
- Raises `wslib-appliance-types` to 0.1.7.

## 0.1.3

- Pins `wslib-appliance-core` 0.1.3.

## 0.1.2

- Pins `wslib-appliance-core` 0.1.2.

## 0.1.1

- Pins `wslib-appliance-core` 0.1.1.
- The derived key, argon2's memory, and the plaintext and compressed
  buffers this crate allocates, every one they outgrow included, are wiped
  when dropped. State inside the compression library, and the strings of an
  opened snapshot, are not. `zeroize` (>= 1.8.1) is now a dependency.

## 0.1.0

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
