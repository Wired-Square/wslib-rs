//! The unattended half: when a backup is due, what it is called, and which files
//! on the box are ours.
//!
//! Pure or filesystem-only, with `now` a parameter. The schedule is an interval
//! since a persisted last run, not a clock time: a box with no real-time clock
//! boots behind and jumps when NTP lands.

use std::path::{Path, PathBuf};

use chrono::{DateTime, Duration, Utc};
use wslib_appliance_types::backup::{
    BackupFile, BackupSchedule, BackupState, MAX_EVERY_HOURS, MAX_KEEP, MIN_EVERY_HOURS, MIN_KEEP,
};

/// How often the daemon asks whether a backup is due: the resolution, not the
/// interval.
pub const CHECK_EVERY: std::time::Duration = std::time::Duration::from_secs(15 * 60);

/// Sorts in time order as text.
const STAMP: &str = "%Y%m%dT%H%M%SZ";
const SUFFIX: &str = ".json";
/// A file being written; never listed.
const STAGED: &str = ".json.new";

/// Refuse a schedule that could not run, or could run away.
pub fn validate(schedule: &BackupSchedule, has_passphrase: bool) -> Result<(), String> {
    if !schedule.enabled {
        return Ok(());
    }
    if !has_passphrase {
        return Err(
            "scheduled backups need a passphrase to seal them with — set one before \
             switching the schedule on"
                .to_string(),
        );
    }
    if !(MIN_EVERY_HOURS..=MAX_EVERY_HOURS).contains(&schedule.every_hours) {
        return Err(format!(
            "a backup every {} hours is outside the usable range of {MIN_EVERY_HOURS} to \
             {MAX_EVERY_HOURS}",
            schedule.every_hours
        ));
    }
    if !(MIN_KEEP..=MAX_KEEP).contains(&schedule.keep) {
        return Err(format!(
            "keeping {} backups is outside the usable range of {MIN_KEEP} to {MAX_KEEP}",
            schedule.keep
        ));
    }
    Ok(())
}

/// Whether a backup is due. Never run is due now, and so is a last run in the
/// future: the clock steps backwards, and waiting would stop backups for good.
pub fn due(schedule: &BackupSchedule, state: &BackupState, now: DateTime<Utc>) -> bool {
    if !schedule.enabled {
        return false;
    }
    let Some(last) = state.last_run_at else {
        return true;
    };
    last > now || now - last >= Duration::hours(i64::from(schedule.every_hours))
}

/// `<name>-backup-<stamp>.json`.
pub fn file_name(name: &str, now: DateTime<Utc>) -> String {
    format!("{}{}{SUFFIX}", prefix(name), now.format(STAMP))
}

fn prefix(name: &str) -> String {
    format!("{name}-backup-")
}

/// The instant in a name of the shape this daemon writes, or `None`: the gate
/// on listing, serving and deleting alike.
fn stamp_of(name: &str, file: &str) -> Option<DateTime<Utc>> {
    let stamp = file.strip_prefix(&prefix(name))?.strip_suffix(SUFFIX)?;
    // chrono's `%m` takes one digit, so without this a name never written parses.
    if stamp.len() != "YYYYMMDDTHHMMSSZ".len() {
        return None;
    }
    chrono::NaiveDateTime::parse_from_str(stamp, STAMP)
        .ok()
        .map(|d| d.and_utc())
}

/// Resolve a requested file to a path without building one from it: the
/// directory listing is the allowlist, so a traversal resolves to nothing.
pub fn resolve(dir: &Path, name: &str, file: &str) -> Option<PathBuf> {
    stamp_of(name, file)?;
    std::fs::read_dir(dir)
        .ok()?
        .flatten()
        .find(|entry| entry.file_name().to_str() == Some(file))
        .map(|entry| entry.path())
}

/// `false` for a name that is not one of ours, or is no longer there.
pub fn remove(dir: &Path, name: &str, file: &str) -> std::io::Result<bool> {
    let Some(path) = resolve(dir, name, file) else {
        return Ok(false);
    };
    match std::fs::remove_file(path) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e),
    }
}

/// Every backup of ours in `dir`, newest first; none for a directory not made
/// yet.
pub fn list(dir: &Path, name: &str) -> std::io::Result<Vec<BackupFile>> {
    let mut files: Vec<BackupFile> = entries(dir)?
        .into_iter()
        .filter_map(|entry| {
            let file = entry.file_name().to_str()?.to_string();
            let taken_at = stamp_of(name, &file)?;
            Some(BackupFile {
                bytes: entry.metadata().ok()?.len(),
                name: file,
                taken_at,
            })
        })
        .collect();
    files.sort_by(|a, b| b.name.cmp(&a.name));
    Ok(files)
}

/// Delete all but the newest `keep` of ours, answering what went, and any
/// staging file a crash left behind.
pub fn rotate(dir: &Path, name: &str, keep: u32) -> std::io::Result<Vec<String>> {
    let mut gone = Vec::new();
    for old in list(dir, name)?.into_iter().skip(keep as usize) {
        std::fs::remove_file(dir.join(&old.name))?;
        gone.push(old.name);
    }
    for entry in entries(dir)? {
        let file = entry.file_name();
        let file = file.to_string_lossy();
        if file.starts_with(&prefix(name)) && file.ends_with(STAGED) {
            std::fs::remove_file(entry.path())?;
        }
    }
    Ok(gone)
}

fn entries(dir: &Path) -> std::io::Result<Vec<std::fs::DirEntry>> {
    match std::fs::read_dir(dir) {
        Ok(entries) => Ok(entries.flatten().collect()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    const NAME: &str = "widget-monitor";

    fn at(s: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(s).unwrap().with_timezone(&Utc)
    }

    fn daily() -> BackupSchedule {
        BackupSchedule {
            enabled: true,
            every_hours: 24,
            keep: 3,
        }
    }

    fn ran_at(s: &str) -> BackupState {
        BackupState {
            last_run_at: Some(at(s)),
            ..Default::default()
        }
    }

    #[test]
    fn a_schedule_is_due_when_never_run_after_its_interval_and_on_a_clock_that_went_back() {
        let now = at("2026-08-20T02:00:00Z");
        assert!(due(&daily(), &BackupState::default(), now));
        assert!(!due(&daily(), &ran_at("2026-08-19T02:00:01Z"), now));
        assert!(due(&daily(), &ran_at("2026-08-19T02:00:00Z"), now));
        assert!(
            due(&daily(), &ran_at("2027-01-01T00:00:00Z"), now),
            "a last run in the future is due now, not never again"
        );
        let off = BackupSchedule {
            enabled: false,
            ..daily()
        };
        assert!(!due(&off, &BackupState::default(), now));
    }

    #[test]
    fn a_name_sorts_in_time_order_and_round_trips_through_its_stamp() {
        let older = file_name(NAME, at("2026-08-19T02:00:00Z"));
        let newer = file_name(NAME, at("2026-08-20T02:03:04Z"));
        assert!(older < newer);
        assert_eq!(newer, "widget-monitor-backup-20260820T020304Z.json");
        assert_eq!(stamp_of(NAME, &newer), Some(at("2026-08-20T02:03:04Z")));
    }

    #[test]
    fn a_file_this_daemon_did_not_write_is_not_ours() {
        for theirs in [
            "notes.json",
            "widget-monitor-backup-.json",
            "widget-monitor-backup-20260820T020000Z.json.bak",
            "other-product-backup-20260820T020000Z.json",
            "../../etc/shadow",
            "widget-monitor-backup-20260820T020000Z.json/../../../etc/shadow",
        ] {
            assert!(stamp_of(NAME, theirs).is_none(), "{theirs}");
        }
    }

    #[test]
    fn rotation_keeps_the_newest_and_never_touches_a_file_it_did_not_write() {
        let dir = TempDir::new().unwrap();
        for day in 17..=20 {
            std::fs::write(
                dir.path()
                    .join(file_name(NAME, at(&format!("2026-08-{day}T02:00:00Z")))),
                "x",
            )
            .unwrap();
        }
        std::fs::write(dir.path().join("keep-me-please.json"), "x").unwrap();
        // A crash between the staged write and the rename.
        let staged = format!(
            "{}{STAGED}",
            file_name(NAME, at("2026-08-21T02:00:00Z")).trim_end_matches(SUFFIX)
        );
        std::fs::write(dir.path().join(&staged), "x").unwrap();

        assert_eq!(rotate(dir.path(), NAME, 2).unwrap().len(), 2);
        let left = list(dir.path(), NAME).unwrap();
        assert_eq!(left.len(), 2);
        assert_eq!(left[0].name, file_name(NAME, at("2026-08-20T02:00:00Z")));
        assert!(dir.path().join("keep-me-please.json").exists());
        assert!(
            !dir.path().join(&staged).exists(),
            "the staging file went with the rotation"
        );
    }

    #[test]
    fn a_name_that_is_not_an_entry_in_the_directory_resolves_to_nothing() {
        let dir = TempDir::new().unwrap();
        let real = file_name(NAME, at("2026-08-20T02:00:00Z"));
        std::fs::write(dir.path().join(&real), "x").unwrap();

        assert!(resolve(dir.path(), NAME, &real).is_some());
        assert!(resolve(dir.path(), NAME, "../../etc/shadow").is_none());
        assert!(
            resolve(
                dir.path(),
                NAME,
                &file_name(NAME, at("2026-08-19T02:00:00Z"))
            )
            .is_none(),
            "a well-formed name for a file that is not here is still not a path"
        );
        assert!(
            list(&dir.path().join("absent"), NAME).unwrap().is_empty(),
            "a directory that does not exist yet lists as empty"
        );
    }

    #[test]
    fn only_a_backup_of_ours_that_is_there_can_be_removed() {
        let dir = TempDir::new().unwrap();
        let real = file_name(NAME, at("2026-08-20T02:00:00Z"));
        std::fs::write(dir.path().join(&real), "x").unwrap();
        std::fs::write(dir.path().join("keep-me-please.json"), "x").unwrap();

        assert!(!remove(dir.path(), NAME, "keep-me-please.json").unwrap());
        assert!(!remove(dir.path(), NAME, "../../etc/shadow").unwrap());
        assert!(dir.path().join("keep-me-please.json").exists());

        assert!(remove(dir.path(), NAME, &real).unwrap());
        assert!(!dir.path().join(&real).exists());
        assert!(!remove(dir.path(), NAME, &real).unwrap(), "already gone");
    }

    #[test]
    fn a_schedule_cannot_be_enabled_with_nothing_to_seal_with_or_outside_the_bounds() {
        assert!(validate(&daily(), false).is_err());
        assert!(validate(&daily(), true).is_ok());
        assert!(validate(&BackupSchedule::default(), false).is_ok());
        assert!(
            validate(
                &BackupSchedule {
                    every_hours: 0,
                    ..daily()
                },
                true
            )
            .is_err()
        );
        assert!(validate(&BackupSchedule { keep: 0, ..daily() }, true).is_err());
    }
}
