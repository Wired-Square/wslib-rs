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

```rust
impl Sections for MySections {
    async fn names(&self) -> Result<BTreeSet<String>, BackupError> {
        Ok(["devices".to_string()].into())
    }
    async fn capture(&self, store: &Store, into: &mut Snapshot) -> Result<(), BackupError> {
        into.put("devices", &my_devices(store).await?)
    }
    async fn restore(&self, tx: &mut Transaction<'_, Sqlite>, from: &Bundle, chosen: &Chosen)
        -> Result<Vec<String>, BackupError>
    {
        if chosen.app.contains("devices") {
            write_my_devices(tx, &from.take("devices")?.unwrap_or_default()).await?;
        }
        Ok(Vec::new())
    }
    async fn erase(&self, tx: &mut Transaction<'_, Sqlite>) -> Result<(), BackupError> {
        sqlx::query("DELETE FROM devices")
            .execute(&mut **tx)
            .await
            .map_err(|e| BackupError::Internal(e.to_string()))?;
        Ok(())
    }
}

// On wslib-appliance-service; SessionBackups::new takes the same arguments.
let backups = LocalBackups::new(NAME, version, &bootstrap.state_dir, MySections);
let service = service
    .local_api(backups.routes())
    .task(move |app, stop| backups.run_schedule(app, stop));
```

- **`names`** lists every section `capture` may put and `restore` reads, a
  renamed section's old name too; a restore applies only these.
- **`items`** lists the items within a section a restore may choose alone;
  `restore` writes only those `chosen.restores_item(section, item)` answers.
- **`erase`** is a factory reset's half for the product's tables, in the
  same transaction as `Store::erase_platform`. The commit catches a table
  left full only if it references `users` with no `ON DELETE` action or with
  `RESTRICT`, so the list of tables is the product's to keep.
- **`BackupError::Refused(sentence)`** is a refusal an operator should read,
  answered 409 as it stands; `Internal` is the daemon's own fault, its cause
  in the journal alone.
- A bundle is at most `wslib_appliance_types::backup::MAX_BUNDLE_LEN`
  (8 MiB), sealed and as plaintext; a take over it is refused 413.

A bundle is sealed with XChaCha20-Poly1305 under an Argon2id key from a
passphrase of at least `wslib_appliance_types::backup::MIN_PASSPHRASE_LEN`
characters. A bundle is never written unsealed; only the application half
crosses to a console, for it to seal.
