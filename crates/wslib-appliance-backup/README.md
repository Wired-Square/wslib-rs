# wslib-appliance-backup

An appliance's backups on any of the family's backends: a sealed file, what
goes in it, the routes that take and restore one, and the schedule that
writes them.

- **`Sections`** is what a product implements once, whichever backend it
  runs on: the named sections a bundle carries beside the platform's own,
  written back inside the restore's transaction.
- **`SessionBackups`** mounts the routes on a backend that serves its own
  accounts (`wslib-appliance-https`): `SessionAdmin` with the caller's own
  proof again, a bundle of the accounts, settings and serving pair beside
  the application half (the product's sections and the outbound trust), and
  a restore in place of the first account.
- **`LocalBackups`** mounts them on a backend with no accounts
  (`wslib-appliance-service`), at `Admin` over the control endpoints, with
  the application half alone: the product's sections and the outbound trust.
  Behind a console, `hooks` serves that half to the console to seal, and
  `proxied_routes` to the administrators it asserts.
- **`run_schedule`** takes a sealed backup into `<state_dir>/backups` at the
  interval an administrator sets, under a passphrase of its own.

A bundle is sealed with XChaCha20-Poly1305 under an Argon2id key from a
passphrase of at least `wslib_appliance_types::backup::MIN_PASSPHRASE_LEN`
characters. A bundle is never written unsealed; only the application half
crosses to a console, for it to seal.
