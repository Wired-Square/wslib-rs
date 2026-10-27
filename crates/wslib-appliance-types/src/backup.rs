//! A backup bundle's plaintext header, which discloses shape (counts, the
//! source host, an opaque box id, the product's section names) and never a
//! username, setting key or endpoint, and is trusted by no opener; and the
//! backup routes' bodies.

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use wslib_secret::Secret;

use crate::totp::FactorProof;

/// The largest bundle anything will read or seal, and every bundle route's body limit.
pub const MAX_BUNDLE_LEN: usize = 8 * 1024 * 1024;

/// The shortest passphrase a bundle may be sealed with.
pub const MIN_PASSPHRASE_LEN: usize = 16;

/// The plaintext half of a bundle: enough to identify it without the passphrase.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts", ts(export))]
#[non_exhaustive]
pub struct BundleHeader {
    pub format: String,

    /// The envelope's version: this header, the KDF and the seal.
    pub version: u32,

    pub created_at: DateTime<Utc>,

    pub source_host: String,

    /// `None` from a format-1 bundle or a box with no machine id: never this box.
    #[serde(default)]
    pub box_id: Option<String>,

    pub app_version: String,

    /// The newest migration of the product's own chain, `0` with none.
    pub app_schema_version: u32,

    #[serde(default)]
    pub contains: Contains,
}

/// Counts and flags, so a picker can say what a file holds; every field defaults.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts", ts(export))]
#[non_exhaustive]
pub struct Contains {
    #[serde(default)]
    pub accounts: usize,

    /// Every key not under the `secret.` or `box.` namespaces.
    #[serde(default)]
    pub settings: usize,

    #[serde(default)]
    pub trusted_certs: usize,

    #[serde(default)]
    pub trusted_cas: usize,

    /// The box's serving certificate and its key.
    #[serde(default)]
    pub serving_certificate: bool,

    /// Authorised-keys files, one per account.
    #[serde(default)]
    pub ssh_keys: usize,

    /// The hostname and how each interface is addressed.
    #[serde(default)]
    pub host: bool,

    /// The consuming product's own sections, by name and row count.
    #[serde(default)]
    pub app: BTreeMap<String, usize>,
}

impl Contains {
    /// Whether any section that restores only onto an appliance is carried.
    pub fn carries_appliance_half(&self) -> bool {
        let Self {
            accounts,
            settings,
            trusted_certs: _,
            trusted_cas: _,
            serving_certificate,
            ssh_keys,
            host,
            app: _,
        } = self;
        *accounts > 0 || *settings > 0 || *serving_certificate || *ssh_keys > 0 || *host
    }
}

/// The body `POST /api/backup` takes.
#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts", ts(export))]
pub struct TakeBackup {
    #[cfg_attr(feature = "ts", ts(as = "String"))]
    pub passphrase: Secret,
    /// The caller's own fresh proof, refused when empty wherever accounts exist.
    #[serde(flatten)]
    #[cfg_attr(feature = "ts", ts(flatten))]
    pub proof: FactorProof,
    /// The product's sections to leave out; the appliance's own are always taken.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    #[cfg_attr(feature = "ts", ts(as = "Option<BTreeSet<String>>", optional))]
    pub leave_out: BTreeSet<String>,
}

/// The body `POST /api/backup/inspect` takes.
#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts", ts(export))]
pub struct OpenBundle {
    #[cfg_attr(feature = "ts", ts(as = "String"))]
    pub passphrase: Secret,
    /// The whole text of the bundle file.
    pub bundle: String,
}

/// The body `POST /api/onboarding/restore` takes: `sections` absent applies
/// everything carried, and a choice without `accounts` is refused.
#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts", ts(export))]
pub struct RestoreUnclaimed {
    #[cfg_attr(feature = "ts", ts(as = "String"))]
    pub passphrase: Secret,
    pub bundle: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts", ts(optional))]
    pub sections: Option<Chosen>,
}

/// The body `POST /api/backup/restore` takes; no section defaults on.
#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts", ts(export))]
pub struct RestoreBundle {
    #[cfg_attr(feature = "ts", ts(as = "String"))]
    pub passphrase: Secret,
    pub bundle: String,
    pub sections: Chosen,
    /// As [`TakeBackup::proof`].
    #[serde(flatten)]
    #[cfg_attr(feature = "ts", ts(flatten))]
    pub proof: FactorProof,
}

/// Which of a bundle's sections a restore applies; one not carried is left alone.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts", ts(export))]
pub struct Chosen {
    pub accounts: bool,
    pub settings: bool,
    pub trusted_certs: bool,
    pub trusted_cas: bool,
    /// Install the serving pair after the commit, giving this box the other one's identity.
    pub serving_certificate: bool,
    /// Replace this box's authorised-keys files with the bundle's, after the
    /// commit; keys in anyone's `~/.ssh` are neither carried nor touched.
    pub ssh_keys: bool,
    /// Rename this box after the other, after the commit; its addressing is
    /// reported, never applied.
    pub host: bool,
    pub app: BTreeSet<String>,
}

impl Chosen {
    /// Everything `contains` says the bundle holds.
    pub fn everything_in(contains: &Contains) -> Self {
        Self {
            accounts: true,
            settings: true,
            trusted_certs: true,
            trusted_cas: true,
            serving_certificate: true,
            ssh_keys: true,
            host: true,
            app: contains.app.keys().cloned().collect(),
        }
        .carried_by(contains)
    }

    /// These, less every section `contains` says the bundle does not hold.
    pub fn carried_by(&self, contains: &Contains) -> Self {
        Self {
            accounts: self.accounts && contains.accounts > 0,
            settings: self.settings && contains.settings > 0,
            trusted_certs: self.trusted_certs && contains.trusted_certs > 0,
            trusted_cas: self.trusted_cas && contains.trusted_cas > 0,
            serving_certificate: self.serving_certificate && contains.serving_certificate,
            ssh_keys: self.ssh_keys && contains.ssh_keys > 0,
            host: self.host && contains.host,
            app: self
                .app
                .iter()
                .filter(|name| contains.app.contains_key(*name))
                .cloned()
                .collect(),
        }
    }

    /// Whether a restore with these would write anything at all.
    pub fn any(&self) -> bool {
        *self != Self::default()
    }

    /// These, less the sections that restore only onto an appliance.
    pub fn application_half(&self) -> Self {
        let Self {
            accounts: _,
            settings: _,
            trusted_certs,
            trusted_cas,
            serving_certificate: _,
            ssh_keys: _,
            host: _,
            app,
        } = self;
        Self {
            trusted_certs: *trusted_certs,
            trusted_cas: *trusted_cas,
            app: app.clone(),
            ..Self::default()
        }
    }
}

/// What a bundle holds, once opened: the header with its counts recomputed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts", ts(export))]
pub struct Inspection {
    pub header: BundleHeader,
    /// Each a sentence, never a refusal.
    pub warnings: Vec<String>,
    /// The product's sections a restore may not choose now, each with why.
    #[serde(default)]
    pub blocked: BTreeMap<String, String>,
}

/// What a restore did.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts", ts(export))]
pub struct RestoreReport {
    /// The sections written; one that did not take is cleared, but a serving pair
    /// written and not yet installed stays set, and a warning says why.
    pub applied: Chosen,
    /// Each a sentence.
    pub warnings: Vec<String>,
    /// Whether every session on this box, the caller's included, is over.
    pub signed_out: bool,
}

/// The shortest and longest intervals a schedule may run at, in hours.
pub const MIN_EVERY_HOURS: u32 = 1;
pub const MAX_EVERY_HOURS: u32 = 24 * 30;
/// How many files a schedule may keep on the box.
pub const MIN_KEEP: u32 = 1;
pub const MAX_KEEP: u32 = 365;

/// What the operator asked for, an interval since the last run; it travels in a backup.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts", ts(export))]
pub struct BackupSchedule {
    pub enabled: bool,
    pub every_hours: u32,
    /// How many sealed files to keep; the oldest goes when a new one lands.
    pub keep: u32,
}

impl Default for BackupSchedule {
    fn default() -> Self {
        Self {
            enabled: false,
            every_hours: 24,
            keep: 7,
        }
    }
}

/// What the schedule last did. This box's own state, never in a bundle.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts", ts(export))]
pub struct BackupState {
    pub last_run_at: Option<DateTime<Utc>>,
    /// The file the last successful run wrote.
    pub file: Option<String>,
    /// Why the last attempt failed, cleared by a success.
    pub error: Option<String>,
}

/// One sealed file on the box.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts", ts(export))]
pub struct BackupFile {
    pub name: String,
    #[cfg_attr(feature = "ts", ts(type = "number"))]
    pub bytes: u64,
    /// Read from the name, not the mtime.
    pub taken_at: DateTime<Utc>,
}

/// What `GET /api/backup/schedule` answers; never the passphrase.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts", ts(export))]
pub struct ScheduleView {
    pub schedule: BackupSchedule,
    pub passphrase_set: bool,
    /// Whether this appliance runs the schedule at all.
    pub runs: bool,
    pub state: BackupState,
    pub files: Vec<BackupFile>,
}

/// The body `PUT /api/backup/schedule` takes: `passphrase` absent or `null`
/// keeps the stored one, and one supplied wants `proof`. A schedule has a
/// passphrase of its own, never a manual backup's.
#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts", ts(export))]
pub struct ScheduleUpdate {
    pub schedule: BackupSchedule,
    #[serde(default)]
    #[cfg_attr(feature = "ts", ts(as = "Option<String>"))]
    pub passphrase: Option<Secret>,
    /// As [`TakeBackup::proof`], asked only with a `passphrase`.
    #[serde(flatten)]
    #[cfg_attr(feature = "ts", ts(flatten))]
    pub proof: FactorProof,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_header_from_an_older_build_still_parses() {
        let older = serde_json::json!({
            "format": "appliance-backup",
            "version": 1,
            "created_at": "2026-09-07T00:00:00.000000Z",
            "source_host": "widget-01",
            "app_version": "0.1.0",
            "app_schema_version": 1,
            "contains": { "accounts": 3 }
        });
        let header: BundleHeader = serde_json::from_value(older).expect("parse");
        assert_eq!(header.box_id, None);
        assert_eq!(header.contains.accounts, 3);
        assert_eq!(header.contains.trusted_certs, 0);
        assert!(header.contains.app.is_empty());

        let bare = serde_json::json!({
            "format": "appliance-backup",
            "version": 1,
            "created_at": "2026-09-07T00:00:00.000000Z",
            "source_host": "widget-01",
            "app_version": "0.1.0",
            "app_schema_version": 1
        });
        let header: BundleHeader = serde_json::from_value(bare).expect("parse");
        assert_eq!(header.contains, Contains::default());
    }

    #[test]
    fn the_application_half_is_the_products_sections_and_the_outbound_trust() {
        let contains = Contains {
            trusted_certs: 1,
            trusted_cas: 1,
            app: [("widgets".to_string(), 2)].into(),
            ..Contains::default()
        };
        assert!(!contains.carries_appliance_half());

        let application = Chosen::everything_in(&contains);
        assert_eq!(application.application_half(), application);

        for appliance in [
            Contains {
                accounts: 1,
                ..Contains::default()
            },
            Contains {
                settings: 1,
                ..Contains::default()
            },
            Contains {
                serving_certificate: true,
                ..Contains::default()
            },
            Contains {
                ssh_keys: 1,
                ..Contains::default()
            },
            Contains {
                host: true,
                ..Contains::default()
            },
        ] {
            assert!(appliance.carries_appliance_half(), "{appliance:?}");
            assert!(
                !Chosen::everything_in(&appliance).application_half().any(),
                "{appliance:?}"
            );
        }
    }
}
