//! The scheduled backup: a quarter-hourly check, a sealed file, and a record.
//!
//! The schedule is read at every check, so an edit takes effect at the next. A
//! failure is recorded and logged, never fatal.

use std::collections::BTreeSet;
use std::path::Path;
use std::sync::atomic::Ordering;

use chrono::{DateTime, Utc};
use wslib_appliance_core::{Actor, ApplianceState, CancellationToken, audit};
use wslib_appliance_types::backup::{BackupSchedule, BackupState};

use crate::routes::{Engine, HostHalf, PASSPHRASE_SECRET, SCHEDULE_SETTING, STATE_KEY};
use crate::{Sections, schedule};

struct Scheduler;

impl Actor for Scheduler {
    fn actor(&self) -> &str {
        "the backup schedule"
    }
}

impl<S, H> Engine<S, H> {
    /// Delete every backup this daemon wrote, for the factory reset: on an
    /// appliance they hold every hash the box had. A scheduled write sealed
    /// before it is not written after. Blocking.
    pub fn erase(&self) -> std::io::Result<()> {
        let mut erasures = self.dir_lock.lock().unwrap_or_else(|e| e.into_inner());
        schedule::rotate(&self.dir, &self.name, 0)?;
        *erasures += 1;
        Ok(())
    }

    /// Blocking.
    pub(crate) fn remove(&self, file: &str) -> std::io::Result<bool> {
        let _writing = self.dir_lock.lock().unwrap_or_else(|e| e.into_inner());
        schedule::remove(&self.dir, &self.name, file)
    }

    pub(crate) fn schedule_runs(&self) -> bool {
        self.schedule_runs.load(Ordering::Relaxed)
    }

    fn erasures(&self) -> u64 {
        *self.dir_lock.lock().unwrap_or_else(|e| e.into_inner())
    }
}

impl<S: Sections, H: HostHalf> Engine<S, H> {
    /// Take a scheduled backup whenever one is due, until `stop` fires; until
    /// it has started, the schedule stays off.
    pub async fn run_schedule(self, app: ApplianceState, stop: CancellationToken) {
        self.schedule_runs.store(true, Ordering::Relaxed);
        // A period first, for a clock that boots behind to be set.
        let first = tokio::time::Instant::now() + schedule::CHECK_EVERY;
        let mut ticks = tokio::time::interval_at(first, schedule::CHECK_EVERY);
        ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        while stop.run_until_cancelled(ticks.tick()).await.is_some() {
            if let Err(e) = self.check(&app).await {
                tracing::warn!(error = %e, "the backup schedule's check could not read or record");
            }
        }
    }

    /// Run if due. The last run is stamped whether it worked or not, so a full
    /// disk is not retried at every check.
    pub(crate) async fn check(
        &self,
        app: &ApplianceState,
    ) -> Result<(), wslib_appliance_store::StoreError> {
        let wanted: BackupSchedule = app.store.setting_doc(SCHEDULE_SETTING).await?;
        let mut record: BackupState = app.store.box_state_doc(STATE_KEY).await?;
        let now = wslib_appliance_store::now();
        if !schedule::due(&wanted, &record, now) {
            return Ok(());
        }

        match self.take_scheduled(app, &wanted, now).await {
            Ok(file) => {
                tracing::info!(%file, "took a scheduled backup");
                audit!(app, &Scheduler, "took a scheduled backup", "file" => &file).await;
                record.file = Some(file);
                record.error = None;
            }
            Err(why) => {
                tracing::warn!(error = %why, "the scheduled backup failed");
                record.error = Some(why);
            }
        }
        record.last_run_at = Some(now);
        app.store.set_box_state_doc(STATE_KEY, &record).await
    }

    /// The error is prose for the schedule's view.
    async fn take_scheduled(
        &self,
        app: &ApplianceState,
        wanted: &BackupSchedule,
        now: DateTime<Utc>,
    ) -> Result<String, String> {
        let passphrase = app
            .store
            .secret(PASSPHRASE_SECRET)
            .await
            .map_err(|e| e.to_string())?
            .ok_or("no passphrase is set, so there is nothing to seal a backup with")?;
        let erasures_before = self.erasures();
        let sealed = self
            .seal(app, &passphrase, BTreeSet::new())
            .await
            .map_err(|e| e.to_string())?;

        let file = schedule::file_name(&self.name, now);
        let (this, keep, written) = (self.clone(), wanted.keep, file.clone());
        tokio::task::spawn_blocking(move || -> Result<(), String> {
            let erasures = this.dir_lock.lock().unwrap_or_else(|e| e.into_inner());
            if *erasures != erasures_before {
                return Err(
                    "a factory reset happened while it was being sealed, so it was not written"
                        .to_string(),
                );
            }
            // To one fewer before the write, so the new file, which sorts oldest
            // on a clock that is behind, is never the one rotation removes.
            std::fs::create_dir_all(&this.dir)
                .map_err(|e| format!("{}: {e}", this.dir.display()))?;
            match schedule::rotate(&this.dir, &this.name, keep.saturating_sub(1)) {
                Ok(gone) if !gone.is_empty() => tracing::info!(?gone, "rotated older backups out"),
                Ok(_) => {}
                Err(e) => tracing::warn!(error = %e, "could not rotate older backups"),
            }
            write_into(&this.dir, &written, sealed.as_bytes())
                .map_err(|e| format!("{written}: {e}"))
        })
        .await
        .map_err(|e| format!("writing the backup panicked: {e}"))??;
        Ok(file)
    }
}

/// Write `bytes` as `dir/file`, `0600` in a `0700` directory, whole or not at
/// all.
fn write_into(dir: &Path, file: &str, bytes: &[u8]) -> std::io::Result<()> {
    let mode = 0o700;
    if let Some(was) = wslib_file_atomic::keep_mode(dir, mode)? {
        tracing::info!(
            dir = %dir.display(),
            was = format!("{was:o}"),
            now = format!("{mode:o}"),
            "the directory's mode was not what the appliance keeps it at; making it so"
        );
    }
    wslib_file_atomic::replace_private(&dir.join(file), bytes)
}
