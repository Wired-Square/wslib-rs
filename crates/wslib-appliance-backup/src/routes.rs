//! The routes, and the work they share with the schedule.
//!
//! The rung is the constructor. On an appliance every signed-in route is
//! [`SessionAdmin`], never `Admin`: the control socket's group must not take
//! every password hash, nor write the accounts. There a take, a restore and a new
//! schedule passphrase want the caller's own proof again ([`prove_caller`]). On
//! a backend with no accounts every route is `Admin` and nothing is re-asked,
//! since its bundles carry only the application half. Behind a console the
//! application half is taken and restored at `SessionAdmin`, with no schedule.
//!
//! One key derivation runs at a time across every route and the schedule. The
//! permit travels into the blocking closure, so a client that disconnects
//! mid-derivation does not free it while the thread runs on.

use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use axum::extract::{DefaultBodyLimit, FromRef, FromRequestParts, Path, State};
use axum::response::Response;
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use wslib_appliance_core::backend::{self, HookCaller, serves_tls};
use wslib_appliance_core::tls::TlsError;
use wslib_appliance_core::{
    Actor, Admin, ApiError, ApplianceState, Identity, Mount, Reached, SessionAdmin, Unclaimed,
    audit, prove_caller,
};
use wslib_appliance_store::{Store, StoreError};
use wslib_appliance_types::backup::{
    BackupSchedule, BackupState, Chosen, Inspection, MAX_BUNDLE_LEN, OpenBundle, RestoreBundle,
    RestoreReport, RestoreUnclaimed, ScheduleUpdate, ScheduleView, SectionItem, TakeBackup,
};
use wslib_appliance_types::host::{HostSection, SshKeyFile};
use wslib_appliance_types::tls::ServingPair;
use wslib_appliance_types::totp::FactorProof;
use wslib_http_scaffold::attachment;
use wslib_secret::Secret;

use crate::envelope::Provenance;
use crate::snapshot::{check_passphrase, is_section_name};
use crate::{BackupError, Bundle, Sections, Snapshot, schedule};

/// A setting, so the schedule travels in a bundle.
pub(crate) const SCHEDULE_SETTING: &str = "backup.schedule";
/// Box state, so the last run does not travel.
pub(crate) const STATE_KEY: &str = "backup.state";
/// The schedule's own passphrase, apart from any typed for a manual backup.
pub const PASSPHRASE_SECRET: &str = "backup.schedule_passphrase";

/// Room for a request's fields, and the escaping of a bundle sent as a string.
pub(crate) const ROOM_BESIDE_A_BUNDLE: usize = 64 * 1024;

const MOST_SECTIONS_CHOSEN: usize = 256;
const MOST_ITEMS_CHOSEN: usize = 512;

const NOT_RUN: &str = "this backend does not run the backup schedule";
const APPLIANCE_HALF_LEFT_OUT: &str = "This backup also carries an appliance's own half — \
     accounts, settings, a serving certificate, authorised keys or a hostname — which restores \
     only onto an appliance and is left out here.";
const ANOTHER_PRODUCTS_APPLIANCE_HALF_RESTORES: &str = "This backup carries another app's \
     sections and none of this one's; only the appliance's own sections restore from it, and \
     they replace this box's.";
const ANOTHER_PRODUCTS_NOTHING_RESTORES: &str = "This backup carries another app's sections and \
     none of this one's, so it will not restore here.";

/// What a backend with host administration carries beside the database; `()`
/// for one without, which carries nothing and applies nothing.
pub trait HostHalf: Clone + Send + Sync + 'static {
    /// The authorised-keys files, and the name and addressing if the host can
    /// say.
    fn capture(
        &self,
    ) -> impl Future<Output = Result<(Vec<SshKeyFile>, Option<HostSection>), BackupError>> + Send;

    /// After the commit, what `applied` chooses of the carried key files and
    /// name, clearing each that did not take, and the addressing reported. On
    /// the restore's own task, so it must not read state from task-locals.
    fn apply(
        &self,
        keys: &[SshKeyFile],
        host: Option<&HostSection>,
        applied: &mut Chosen,
    ) -> impl Future<Output = Vec<String>> + Send;

    /// The routes that need an administrator, at the rung the host asks for:
    /// as they are, unless it asks for host admins.
    fn gate<S: Clone + Send + Sync + 'static>(&self, routes: Router<S>) -> Router<S> {
        routes
    }
}

impl HostHalf for () {
    async fn capture(&self) -> Result<(Vec<SshKeyFile>, Option<HostSection>), BackupError> {
        Ok((Vec::new(), None))
    }

    async fn apply(
        &self,
        _: &[SshKeyFile],
        _: Option<&HostSection>,
        applied: &mut Chosen,
    ) -> Vec<String> {
        applied.ssh_keys = false;
        applied.host = false;
        Vec::new()
    }
}

#[derive(Debug, Clone, Copy)]
enum Rung {
    Session,
    Local,
}

impl Rung {
    fn carries_appliance_half(self) -> bool {
        matches!(self, Self::Session)
    }
}

/// The backup routes and the schedule, over a product's [`Sections`] and a
/// backend's [`HostHalf`].
#[derive(Debug, Clone)]
pub struct Engine<S, H> {
    /// The product's system name: what the files are called.
    pub name: String,
    pub(crate) version: String,
    pub(crate) dir: PathBuf,
    pub host: H,
    pub sections: S,
    rung: Rung,
    kdf: Arc<Semaphore>,
    /// The one application-half capture, take or restore at a time.
    busy: Arc<Semaphore>,
    /// Held while files in `dir` are written or removed, never across an
    /// await, and counts the erases: a scheduled write sealed before a reset
    /// must not land in the emptied directory.
    pub(crate) dir_lock: Arc<std::sync::Mutex<u64>>,
    pub(crate) schedule_runs: Arc<AtomicBool>,
}

impl<S: Sections> Engine<S, ()> {
    pub(crate) fn local(
        name: &str,
        version: &str,
        state_dir: &std::path::Path,
        sections: S,
    ) -> Self {
        Self::with_rung(Rung::Local, name, version, state_dir, (), sections)
    }

    pub(crate) fn proxied_routes(&self) -> Mount {
        let engine = self.clone();
        Mount::new(
            take_and_restore::<S, (), SessionAdmin, Turn>(),
            move |app| BackupsState { app, engine },
        )
    }
}

impl<S: Sections, H: HostHalf> Engine<S, H> {
    /// The appliance's rung: `SessionAdmin`, the caller's own proof again, and
    /// the first-run restore.
    pub fn session(
        name: &str,
        version: &str,
        state_dir: &std::path::Path,
        host: H,
        sections: S,
    ) -> Self {
        Self::with_rung(Rung::Session, name, version, state_dir, host, sections)
    }

    fn with_rung(
        rung: Rung,
        name: &str,
        version: &str,
        state_dir: &std::path::Path,
        host: H,
        sections: S,
    ) -> Self {
        #[cfg(test)]
        crate::install_test_provider();
        Self {
            name: name.to_string(),
            version: version.to_string(),
            dir: state_dir.join("backups"),
            host,
            sections,
            rung,
            kdf: Arc::new(Semaphore::new(1)),
            busy: Arc::new(Semaphore::new(1)),
            dir_lock: Arc::default(),
            schedule_runs: Arc::default(),
        }
    }

    /// Every route of the rung, and `beside` on the same state.
    pub fn routes(&self, beside: Router<BackupsState<S, H>>) -> Mount {
        let routes = match self.rung {
            Rung::Session => self
                .host
                .gate(at::<S, H, SessionAdmin>().merge(beside))
                .route(
                    "/onboarding/restore",
                    post(restore_unclaimed).layer(bundle_sized()),
                ),
            Rung::Local => at::<S, H, Admin>().merge(beside),
        };
        let engine = self.clone();
        Mount::new(routes, move |app| BackupsState { app, engine })
    }

    /// This box, sealed under `passphrase`, less the product's sections in
    /// `leave_out`.
    pub(crate) async fn seal(
        &self,
        app: &ApplianceState,
        passphrase: &Secret,
        leave_out: BTreeSet<String>,
    ) -> Result<String, ApiError> {
        let captured = self.capture(app, leave_out).await?;
        self.seal_captured(captured, passphrase).await
    }

    async fn capture(
        &self,
        app: &ApplianceState,
        leave_out: BTreeSet<String>,
    ) -> Result<(Snapshot, Provenance), ApiError> {
        let pair = match self.rung.carries_appliance_half() && serves_tls(&app.tls) {
            true => Some(app.tls.pair().await?),
            false => None,
        };
        Ok(self.snapshot(&app.store, pair, leave_out).await?)
    }

    async fn seal_captured(
        &self,
        (snapshot, provenance): (Snapshot, Provenance),
        passphrase: &Secret,
    ) -> Result<String, ApiError> {
        let passphrase = passphrase.clone();
        self.blocking("seal the backup", true, move || {
            snapshot.seal(&passphrase, &provenance)
        })
        .await
    }

    /// A host's offline backup: written `0600`, never over a file that exists.
    /// It takes none of the engine's locks or its derivation permit.
    pub async fn seal_offline(
        &self,
        store: &Store,
        pair: ServingPair,
        passphrase: &Secret,
        out: &std::path::Path,
    ) -> Result<(), BackupError> {
        let (snapshot, provenance) = self.snapshot(store, Some(pair), BTreeSet::new()).await?;
        let (passphrase, file) = (passphrase.clone(), out.to_path_buf());
        tokio::task::spawn_blocking(move || {
            let sealed = snapshot.seal(&passphrase, &provenance)?;
            wslib_file_atomic::write_private(&file, sealed.as_bytes())
                .map_err(|e| BackupError::Internal(format!("writing {}: {e}", file.display())))
        })
        .await
        .map_err(BackupError::internal)?
    }

    async fn snapshot(
        &self,
        store: &Store,
        pair: Option<ServingPair>,
        leave_out: BTreeSet<String>,
    ) -> Result<(Snapshot, Provenance), BackupError> {
        let mut snapshot = match self.rung.carries_appliance_half() {
            true => Snapshot::capture(store).await?,
            false => Snapshot::capture_application(store).await?,
        }
        .leaving_out(leave_out);
        snapshot.capture_sections(&self.sections, store).await?;
        if let Some(pair) = pair {
            snapshot.put_serving_pair(pair);
        }
        let (keys, host) = self.host.capture().await?;
        snapshot.put_ssh_keys(keys);
        if let Some(section) = host {
            snapshot.put_host(section);
        }
        let provenance = Provenance {
            source_host: wslib_appliance_core::hostname()
                .unwrap_or_else(|| "a computer with no name".to_string()),
            box_id: wslib_appliance_core::box_id(),
            app_version: self.version.clone(),
            app_schema_version: store.app_schema_version(),
        };
        Ok((snapshot, provenance))
    }

    /// Open a bundle off the runtime workers. `queue` is whether to wait for the
    /// derivation permit; the first-run route, with no session, does not.
    async fn open(
        &self,
        app: &ApplianceState,
        body: OpenBundle,
        with: fn(&str, &Secret, u32) -> Result<Bundle, BackupError>,
        queue: bool,
    ) -> Result<Bundle, ApiError> {
        let ours = app.store.app_schema_version();
        self.blocking("open the backup", queue, move || {
            with(&body.bundle, &body.passphrase, ours)
        })
        .await
    }

    /// What the product says of the file, and what of it this rung leaves out;
    /// `ours` is the request's one read of `Sections::names`.
    pub(crate) fn warnings(&self, bundle: &Bundle, ours: &BTreeSet<String>) -> Vec<String> {
        let mut warnings = self.sections.warnings(bundle);
        let carried = &bundle.header().contains;
        if !self.rung.carries_appliance_half() && carried.carries_appliance_half() {
            warnings.push(APPLIANCE_HALF_LEFT_OUT.to_string());
        }
        if none_ours(ours, carried.app.keys()) {
            warnings.push(
                match self.rung.carries_appliance_half() {
                    true => ANOTHER_PRODUCTS_APPLIANCE_HALF_RESTORES,
                    false => ANOTHER_PRODUCTS_NOTHING_RESTORES,
                }
                .to_string(),
            );
        }
        warnings
    }

    /// The product's choosable items, for the sections `bundle` carries and `ours` names.
    pub(crate) fn items(
        &self,
        bundle: &Bundle,
        ours: &BTreeSet<String>,
    ) -> BTreeMap<String, Vec<SectionItem>> {
        let mut items = self.sections.items(bundle);
        let carried = &bundle.header().contains.app;
        items.retain(|name, _| carried.contains_key(name) && ours.contains(name));
        items
    }

    pub(crate) async fn blocked<'a>(
        &self,
        store: &Store,
        names: impl IntoIterator<Item = &'a String>,
    ) -> BTreeMap<String, String> {
        let asked: BTreeSet<String> = names.into_iter().cloned().collect();
        if asked.is_empty() {
            return BTreeMap::new();
        }
        let mut blocked = self.sections.blocked(store, &asked).await;
        blocked.retain(|name, _| asked.contains(name));
        blocked
    }

    pub(crate) async fn refuse_blocked(
        &self,
        store: &Store,
        chosen: &BTreeSet<String>,
    ) -> Result<(), BackupError> {
        let blocked = self.blocked(store, chosen).await;
        match blocked.is_empty() {
            true => Ok(()),
            false => Err(BackupError::Refused(
                blocked.into_values().collect::<Vec<_>>().join(" "),
            )),
        }
    }

    /// Apply `bundle`, the platform's sections and the product's in one
    /// transaction, then the serving pair and the host half after the commit.
    pub(crate) async fn apply(
        &self,
        app: &ApplianceState,
        bundle: Bundle,
        chosen: &Chosen,
        ours: &BTreeSet<String>,
        who: Restorer<'_>,
    ) -> Result<RestoreReport, ApiError> {
        let chosen = match self.rung.carries_appliance_half() {
            true => chosen.clone(),
            false => chosen.application_half(),
        };
        let mut applied = chosen.carried_by(&bundle.header().contains);
        // Another product's bundle still gives a box the platform's sections.
        let foreign = match self.rung.carries_appliance_half() {
            true => none_ours(ours, applied.app.iter()),
            false => none_ours(ours, bundle.header().contains.app.keys()),
        };
        // The hooks check the product by name; a sealed header names none.
        if foreign && !matches!(who, Restorer::Console(_)) {
            return Err(BackupError::OtherProduct.into());
        }
        let left_out: BTreeSet<String>;
        (applied.app, left_out) = std::mem::take(&mut applied.app)
            .into_iter()
            .partition(|name| ours.contains(name));
        applied.items.retain(|name, _| applied.app.contains(name));
        if !applied.any() {
            return Err(ApiError::BadRequest(
                "choose at least one section this backup carries".to_string(),
            ));
        }
        // A first-run restore must claim the box, or the next person makes the
        // first account on a box that looks fresh and is not.
        let first_run = matches!(who, Restorer::Nobody(_));
        if (applied.accounts || first_run) && !bundle.has_enabled_admin() {
            return Err(ApiError::Conflict(
                who.no_administrator(&bundle).to_string(),
            ));
        }
        if first_run && !applied.accounts {
            return Err(ApiError::BadRequest(
                "a first-run restore must bring the accounts, since they are what claims the \
                 box — to leave them out, make the first account, then restore the rest from \
                 Settings"
                    .to_string(),
            ));
        }
        let mut warnings = self.warnings(&bundle, ours);
        warnings.extend(left_out.iter().map(|name| {
            format!(
                "The section “{name}” this backup carries is not one this build restores, and \
                 was left out."
            )
        }));
        // The pair goes in after the commit, so whether it can is asked first. At
        // first run one that cannot, or one named in the configuration, is left
        // out and said so.
        applied.serving_certificate &= serves_tls(&app.tls);
        if applied.serving_certificate {
            let refused = match app.tls.replaceable() {
                Err(e) => Some(ApiError::from(e)),
                Ok(()) if first_run && app.tls.named() => Some(ApiError::Conflict(
                    "this box serves a certificate somebody named in its configuration".to_string(),
                )),
                Ok(()) => None,
            };
            match refused {
                Some(why) if first_run => {
                    applied.serving_certificate = false;
                    warnings.push(format!(
                        "The serving certificate this backup carried was not installed — {why}. \
                         This box is still serving its own."
                    ));
                }
                Some(why) => return Err(why),
                None => {}
            }
        }

        // Read before the write, which may delete the row.
        let signed_out = match who.actor_id() {
            Some(id) if applied.accounts => app.store.user_by_id(id).await?.is_some(),
            _ => false,
        };
        let mut tx = who.begin(app).await?;
        if let Restorer::Identified(who) = who
            && applied.accounts
        {
            refuse_a_host_admin_change(&mut tx, who, &bundle).await?;
        }
        bundle
            .restore_platform(&app.store, &mut tx, &applied)
            .await?;
        warnings.extend(self.sections.restore(&mut tx, &bundle, &applied).await?);
        tx.commit().await.map_err(StoreError::from)?;
        if applied.settings {
            app.store.settings_replaced();
        }
        // Past the commit a failure is a warning: the restore happened.
        if applied.trusted_certs || applied.trusted_cas {
            warnings.extend(reload_outbound_trust(app, "restored").await);
        }
        if applied.settings {
            let said = switch_off_an_unusable_schedule(&app.store, self.schedule_runs())
                .await
                .unwrap_or_else(|e| {
                    tracing::warn!(error = %e, "could not check the restored backup schedule");
                    Some(
                        "The backup schedule this file carried could not be checked; look at \
                         it under Backup."
                            .to_string(),
                    )
                });
            warnings.extend(said);
        }
        if applied.serving_certificate
            && let Some(pair) = bundle.serving_pair()
        {
            match app
                .tls
                .install_pem(&pair.cert_pem, &pair.key_pem, None)
                .await
            {
                Ok(report) => warnings.extend(report.warnings),
                Err(e) => {
                    applied.serving_certificate = matches!(e, TlsError::Unfinished { .. });
                    warnings.push(pair_not_installed(&e));
                }
            }
        }
        warnings.extend(
            self.host
                .apply(bundle.ssh_keys(), bundle.host(), &mut applied)
                .await,
        );
        // Last, so `applied` is what was applied.
        warnings.extend(
            self.sections
                .after_restore(&app.store, &bundle, &applied)
                .await,
        );

        let header = bundle.header();
        let kept_or = |applied: bool, did: &'static str| if applied { did } else { "kept" };
        // From the file, so bounded before it reaches a row.
        let from: String = header.source_host.chars().take(64).collect();
        audit!(
            &app, &who, who.message(),
            "from" => &from,
            "taken" => &header.created_at.to_rfc3339(),
            "accounts" => kept_or(applied.accounts, "restored"),
            "settings" => kept_or(applied.settings, "restored"),
            "trusted_certs" => kept_or(applied.trusted_certs, "restored"),
            "trusted_cas" => kept_or(applied.trusted_cas, "restored"),
            "serving_certificate" => kept_or(applied.serving_certificate, "installed"),
            "ssh_keys" => kept_or(applied.ssh_keys, "restored"),
            "host" => kept_or(applied.host, "renamed"),
            "app" => &applied.app.iter().map(String::as_str).collect::<Vec<_>>().join(" "),
        )
        .await;

        Ok(RestoreReport {
            signed_out,
            applied,
            warnings,
        })
    }
}

/// The appliance's state and the engine, for a route mounted beside the
/// engine's.
#[derive(Clone)]
pub struct BackupsState<S, H> {
    app: ApplianceState,
    engine: Engine<S, H>,
}

impl<S, H> FromRef<BackupsState<S, H>> for ApplianceState {
    fn from_ref(state: &BackupsState<S, H>) -> Self {
        state.app.clone()
    }
}

impl<S: Clone, H: Clone> FromRef<BackupsState<S, H>> for Engine<S, H> {
    fn from_ref(state: &BackupsState<S, H>) -> Self {
        state.engine.clone()
    }
}

/// A rung the routes mount at, and what it asks before a take, a restore or a
/// new schedule passphrase.
trait Caller: Send + 'static {
    fn identity(&self) -> &Identity;

    fn prove(
        &self,
        app: &ApplianceState,
        reached: &Reached,
        proof: FactorProof,
        what: &'static str,
    ) -> impl Future<Output = Result<(), ApiError>> + Send;
}

impl Caller for SessionAdmin {
    fn identity(&self) -> &Identity {
        &self.0
    }

    async fn prove(
        &self,
        app: &ApplianceState,
        reached: &Reached,
        proof: FactorProof,
        what: &'static str,
    ) -> Result<(), ApiError> {
        prove_caller(app, &self.0, reached, proof, what)
            .await
            .map(drop)
    }
}

impl Caller for Admin {
    fn identity(&self) -> &Identity {
        &self.0
    }

    /// Nothing to re-ask of a control endpoint; an account is refused.
    async fn prove(
        &self,
        _: &ApplianceState,
        _: &Reached,
        _: FactorProof,
        _: &'static str,
    ) -> Result<(), ApiError> {
        match self.0.is_local() {
            true => Ok(()),
            false => Err(ApiError::Forbidden(
                "this backend's backups are taken and restored over its control endpoints \
                 only"
                    .to_string(),
            )),
        }
    }
}

pub(crate) struct Turn {
    _held: OwnedSemaphorePermit,
}

impl Turn {
    pub(crate) fn take<S, H>(engine: &Engine<S, H>) -> Result<Self, ApiError> {
        let _held = try_take(&engine.busy, "capturing or restoring its sections")?;
        Ok(Self { _held })
    }
}

/// What a take or restore holds while it reads or writes the box, taken only
/// once its caller is proved and its file opened.
trait Holds: Sized + Send + 'static {
    fn hold<S, H>(engine: &Engine<S, H>) -> Result<Self, ApiError>;
}

impl Holds for () {
    fn hold<S, H>(_: &Engine<S, H>) -> Result<Self, ApiError> {
        Ok(())
    }
}

impl Holds for Turn {
    fn hold<S, H>(engine: &Engine<S, H>) -> Result<Self, ApiError> {
        Self::take(engine)
    }
}

pub(crate) fn try_take(
    busy: &Arc<Semaphore>,
    doing: &str,
) -> Result<OwnedSemaphorePermit, ApiError> {
    busy.clone().try_acquire_owned().map_err(|_| {
        ApiError::Conflict(format!(
            "this app is already {doing}; try again when it has finished"
        ))
    })
}

fn at<S, H, R>() -> Router<BackupsState<S, H>>
where
    S: Sections,
    H: HostHalf,
    R: Caller + FromRequestParts<BackupsState<S, H>>,
{
    take_and_restore::<S, H, R, ()>()
        .route(
            "/backup/schedule",
            get(schedule_view::<S, H, R>).put(schedule_update::<S, H, R>),
        )
        .route(
            "/backup/schedule/passphrase",
            delete(schedule_forget::<S, H, R>),
        )
        .route(
            "/backup/files/{file}",
            get(download::<S, H, R>).delete(remove::<S, H, R>),
        )
}

fn take_and_restore<S, H, R, T>() -> Router<BackupsState<S, H>>
where
    S: Sections,
    H: HostHalf,
    R: Caller + FromRequestParts<BackupsState<S, H>>,
    T: Holds,
{
    Router::new()
        .route("/backup", post(take::<S, H, R, T>))
        .route(
            "/backup/inspect",
            post(inspect::<S, H, R>).layer(bundle_sized()),
        )
        .route(
            "/backup/restore",
            post(restore::<S, H, R, T>).layer(bundle_sized()),
        )
}

/// The body limit of a route that takes a bundle; every other route keeps
/// axum's default.
pub(crate) fn bundle_sized() -> DefaultBodyLimit {
    DefaultBodyLimit::max(MAX_BUNDLE_LEN + ROOM_BESIDE_A_BUNDLE)
}

/// Reload the outbound verifier once a transaction that wrote the pins or
/// authorities has committed; a failure is a sentence for the report.
pub async fn reload_outbound_trust(app: &ApplianceState, did: &str) -> Option<String> {
    app.outbound.reload(&app.store).await.err().map(|e| {
        format!(
            "What this box trusts for outbound connections was {did} but not reloaded ({e}); \
             it applies at the next restart."
        )
    })
}

fn pair_not_installed(e: &TlsError) -> String {
    match e {
        TlsError::Unfinished { because, next } => format!(
            "The serving certificate this backup carried was written but not finished \
             ({because}); this box is still serving its own. Installing it again serves it at \
             once, and {next}."
        ),
        e => format!(
            "The serving certificate this backup carried was not installed — {}. This box \
             is still serving its own.",
            e.to_string().trim_end_matches('.')
        ),
    }
}

fn none_ours<'a>(
    ours: &BTreeSet<String>,
    mut names: impl ExactSizeIterator<Item = &'a String>,
) -> bool {
    names.len() > 0 && !names.any(|name| ours.contains(name))
}

/// A restore's [`Engine::apply`], run to its end whatever becomes of the
/// request; shutdown waits for it for its grace.
pub(crate) async fn to_completion<T: Send + 'static>(
    app: &ApplianceState,
    apply: impl Future<Output = Result<T, ApiError>> + Send + 'static,
) -> Result<T, ApiError> {
    backend::to_completion(app, apply)
        .await
        .map_err(|e| ApiError::internal("run the restore", &e))?
}

/// A restored schedule the schedule route would refuse, such as one whose
/// passphrase did not travel, is switched off and the reason handed back.
async fn switch_off_an_unusable_schedule(
    store: &Store,
    schedule_runs: bool,
) -> Result<Option<String>, StoreError> {
    let schedule: BackupSchedule = store.setting_doc(SCHEDULE_SETTING).await?;
    let has_passphrase = store.secret(PASSPHRASE_SECRET).await?.is_some();
    let why = match schedule::validate(&schedule, has_passphrase) {
        _ if schedule.enabled && !schedule_runs => NOT_RUN.to_string(),
        Err(why) => why,
        Ok(()) => return Ok(None),
    };
    store
        .set_setting_doc(
            SCHEDULE_SETTING,
            &BackupSchedule {
                enabled: false,
                ..schedule
            },
        )
        .await?;
    Ok(Some(format!(
        "The backup schedule this file carried is switched off: {why}."
    )))
}

pub(crate) enum Restorer<'a> {
    Identified(&'a Identity),
    /// The first-run screen, before any account exists.
    Nobody(&'a Unclaimed),
    Console(&'a HookCaller),
}

impl Actor for Restorer<'_> {
    fn actor(&self) -> &str {
        match self {
            Self::Identified(who) => who.actor(),
            Self::Nobody(unclaimed) => unclaimed.actor(),
            Self::Console(console) => console.actor(),
        }
    }

    fn actor_id(&self) -> Option<&str> {
        match self {
            Self::Identified(who) => who.account_id(),
            Self::Nobody(_) => None,
            Self::Console(console) => console.actor_id(),
        }
    }
}

impl Restorer<'_> {
    fn message(&self) -> &'static str {
        match self {
            Self::Identified(_) | Self::Console(_) => "restored a backup",
            Self::Nobody(_) => "restored a backup onto a box with no accounts",
        }
    }

    /// On the first-run path, re-checks that nobody has claimed the box since.
    async fn begin<'s>(
        &self,
        app: &'s ApplianceState,
    ) -> Result<
        wslib_appliance_store::sqlx::Transaction<'s, wslib_appliance_store::sqlx::Sqlite>,
        ApiError,
    > {
        match self {
            Self::Identified(_) | Self::Console(_) => Ok(app.store.begin().await?),
            Self::Nobody(unclaimed) => unclaimed.hold(&app.store).await,
        }
    }

    fn no_administrator(&self, bundle: &Bundle) -> &'static str {
        match self {
            Self::Identified(_) | Self::Console(_) => {
                "this backup has no enabled administrator in it, so restoring its accounts \
                 would leave nobody able to sign in — untick the accounts to restore the rest"
            }
            Self::Nobody(_) if bundle.header().contains.accounts == 0 => {
                "this backup carries no accounts, so it cannot give this box its first \
                 administrator — make the first account, then restore this backup from \
                 Settings, where what it does carry applies"
            }
            Self::Nobody(_) => {
                "this backup has no enabled administrator in it, so this box would still have \
                 nobody able to sign in — make the first account instead"
            }
        }
    }
}

/// Refuse to restore accounts that make, keep or remove a host admin unless a
/// host admin is signed in, or that leave a box that has an enabled one without.
async fn refuse_a_host_admin_change(
    tx: &mut wslib_appliance_store::sqlx::Transaction<'_, wslib_appliance_store::sqlx::Sqlite>,
    who: &Identity,
    bundle: &Bundle,
) -> Result<(), ApiError> {
    let (on_the_box, enabled_on_the_box) = Store::host_admins_in(tx).await?;
    let (in_the_bundle, enabled_in_the_bundle) = bundle.host_admins();
    if (in_the_bundle || on_the_box) && !who.is_host_admin() {
        return Err(ApiError::Forbidden(
            "only a host admin, signed in, restores accounts onto a box that has a host admin \
             or from a backup that carries one — untick the accounts to restore the rest"
                .to_string(),
        ));
    }
    if enabled_on_the_box && !enabled_in_the_bundle {
        return Err(ApiError::Conflict(
            "this box has a host admin and this backup has no enabled one, so restoring its \
             accounts would leave the box without — untick the accounts to restore the rest"
                .to_string(),
        ));
    }
    Ok(())
}

/// Audited after the seal, so a refused passphrase leaves no row.
async fn take<S: Sections, H: HostHalf, R: Caller, T: Holds>(
    State(backups): State<Engine<S, H>>,
    caller: R,
    State(app): State<ApplianceState>,
    reached: Reached,
    Json(body): Json<TakeBackup>,
) -> Result<Response, ApiError> {
    check_passphrase(&body.passphrase)?;
    caller.prove(&app, &reached, body.proof, "backup").await?;
    // The request's names: bounded, and only section-shaped ones reach the row.
    let left_out = body
        .leave_out
        .iter()
        .filter(|name| is_section_name(name))
        .take(16)
        .map(String::as_str)
        .collect::<Vec<_>>()
        .join(" ");
    let turn = T::hold(&backups)?;
    let captured = backups.capture(&app, body.leave_out).await?;
    drop(turn);
    let sealed = backups.seal_captured(captured, &body.passphrase).await?;
    audit!(&app, caller.identity(), "took a backup", "leave_out" => &left_out).await;
    Ok(attachment(
        "application/json",
        &schedule::file_name(&backups.name, wslib_appliance_store::now()),
        sealed,
    ))
}

async fn inspect<S: Sections, H: HostHalf, R: Caller>(
    State(backups): State<Engine<S, H>>,
    _: R,
    State(app): State<ApplianceState>,
    Json(body): Json<OpenBundle>,
) -> Result<Json<Inspection>, ApiError> {
    let bundle = backups.open(&app, body, Bundle::open, true).await?;
    let ours = backups.sections.names().await?;
    let mut warnings = backups.warnings(&bundle, &ours);
    if backups.rung.carries_appliance_half()
        && bundle.header().contains.accounts > 0
        && !bundle.has_enabled_admin()
    {
        warnings.push(
            "This backup has no enabled administrator, so it cannot be restored with its \
             accounts selected — untick Accounts to restore the rest of it."
                .to_string(),
        );
    }
    let blocked = backups
        .blocked(&app.store, bundle.header().contains.app.keys())
        .await;
    Ok(Json(Inspection {
        header: bundle.header().clone(),
        warnings,
        blocked,
        items: backups.items(&bundle, &ours),
    }))
}

/// A restore of the accounts ends every session, the caller's too, and the
/// report says so. A bad section choice or a blocked section is refused before
/// the proof, which it does not spend; any refusal after it has spent it.
async fn restore<S: Sections, H: HostHalf, R: Caller, T: Holds>(
    State(backups): State<Engine<S, H>>,
    caller: R,
    State(app): State<ApplianceState>,
    reached: Reached,
    Json(body): Json<RestoreBundle>,
) -> Result<Json<RestoreReport>, ApiError> {
    let chosen = &body.sections.app;
    if chosen.len() > MOST_SECTIONS_CHOSEN || !chosen.iter().all(|name| is_section_name(name)) {
        return Err(ApiError::BadRequest(format!(
            "choose at most {MOST_SECTIONS_CHOSEN} of this app's sections, each by its name"
        )));
    }
    let items = &body.sections.items;
    if !items.keys().all(|name| chosen.contains(name))
        || items.values().map(BTreeSet::len).sum::<usize>() > MOST_ITEMS_CHOSEN
        || !items.values().flatten().all(|name| is_section_name(name))
    {
        return Err(ApiError::BadRequest(format!(
            "choose at most {MOST_ITEMS_CHOSEN} items, each by its name and within a section chosen"
        )));
    }
    let ours = backups.sections.names().await?;
    backups.refuse_blocked(&app.store, chosen).await?;
    caller.prove(&app, &reached, body.proof, "restore").await?;
    let open = OpenBundle {
        passphrase: body.passphrase,
        bundle: body.bundle,
    };
    let bundle = backups.open(&app, open, Bundle::open, true).await?;
    let turn = T::hold(&backups)?;
    let who = caller.identity().clone();
    let report = to_completion(&app.clone(), async move {
        let _turn = turn;
        backups
            .apply(
                &app,
                bundle,
                &body.sections,
                &ours,
                Restorer::Identified(&who),
            )
            .await
    })
    .await?;
    Ok(Json(report))
}

/// Put a bundle onto a box with no accounts: the sections chosen, or all it
/// carries. A choice without the accounts is refused.
async fn restore_unclaimed<S: Sections, H: HostHalf>(
    State(backups): State<Engine<S, H>>,
    unclaimed: Unclaimed,
    State(app): State<ApplianceState>,
    Json(body): Json<RestoreUnclaimed>,
) -> Result<Json<RestoreReport>, ApiError> {
    let open = OpenBundle {
        passphrase: body.passphrase,
        bundle: body.bundle,
    };
    let bundle = backups
        .open(&app, open, Bundle::open_unauthenticated, false)
        .await?;
    let chosen = body
        .sections
        .unwrap_or_else(|| Chosen::everything_in(&bundle.header().contains));
    let ours = backups.sections.names().await?;
    let carried = chosen.carried_by(&bundle.header().contains).app;
    backups.refuse_blocked(&app.store, &carried).await?;
    let report = to_completion(&app.clone(), async move {
        backups
            .apply(&app, bundle, &chosen, &ours, Restorer::Nobody(&unclaimed))
            .await
    })
    .await?;
    Ok(Json(report))
}

async fn schedule_view<S: Sections, H: HostHalf, R: Caller>(
    State(backups): State<Engine<S, H>>,
    _: R,
    State(app): State<ApplianceState>,
) -> Result<Json<ScheduleView>, ApiError> {
    Ok(Json(view(&backups, &app).await?))
}

/// A passphrase in the update replaces the stored one, proven as a take is. A
/// schedule cannot be switched on without one, nor where `run_schedule` has
/// not started.
async fn schedule_update<S: Sections, H: HostHalf, R: Caller>(
    State(backups): State<Engine<S, H>>,
    caller: R,
    State(app): State<ApplianceState>,
    reached: Reached,
    Json(update): Json<ScheduleUpdate>,
) -> Result<Json<ScheduleView>, ApiError> {
    let wanted = update.schedule;
    if wanted.enabled && !backups.schedule_runs() {
        return Err(ApiError::Unsupported(format!(
            "{NOT_RUN}, so the schedule cannot be switched on"
        )));
    }
    let has_passphrase = match &update.passphrase {
        Some(typed) => {
            check_passphrase(typed)?;
            true
        }
        None => app.store.secret(PASSPHRASE_SECRET).await?.is_some(),
    };
    schedule::validate(&wanted, has_passphrase).map_err(ApiError::BadRequest)?;
    if update.passphrase.is_some() {
        caller
            .prove(&app, &reached, update.proof, "backup schedule")
            .await?;
    }

    if let Some(typed) = &update.passphrase {
        app.store.set_secret(PASSPHRASE_SECRET, typed).await?;
    }
    app.store.set_setting_doc(SCHEDULE_SETTING, &wanted).await?;
    audit!(
        &app, caller.identity(), "changed the backup schedule",
        "enabled" => &wanted.enabled.to_string(),
        "every_hours" => &wanted.every_hours.to_string(),
        "keep" => &wanted.keep.to_string(),
        "passphrase" => if update.passphrase.is_some() { "changed" } else { "kept" },
    )
    .await;
    Ok(Json(view(&backups, &app).await?))
}

/// Forget the schedule's passphrase, switching the schedule off with it.
async fn schedule_forget<S: Sections, H: HostHalf, R: Caller>(
    State(backups): State<Engine<S, H>>,
    caller: R,
    State(app): State<ApplianceState>,
) -> Result<Json<ScheduleView>, ApiError> {
    if app.store.secret(PASSPHRASE_SECRET).await?.is_some() {
        let stored: BackupSchedule = app.store.setting_doc(SCHEDULE_SETTING).await?;
        let off = BackupSchedule {
            enabled: false,
            ..stored
        };
        // Off first, so a tick between the writes finds nothing to do.
        app.store.set_setting_doc(SCHEDULE_SETTING, &off).await?;
        app.store.clear_secret(PASSPHRASE_SECRET).await?;
        audit!(
            &app,
            caller.identity(),
            "forgot the backup schedule's passphrase"
        )
        .await;
    }
    Ok(Json(view(&backups, &app).await?))
}

/// No passphrase: the file is already sealed. Never `dir.join(name)`; see
/// `schedule::resolve`.
async fn download<S: Sections, H: HostHalf, R: Caller>(
    State(backups): State<Engine<S, H>>,
    _: R,
    Path(file): Path<String>,
) -> Result<Response, ApiError> {
    let path = schedule::resolve(&backups.dir, &backups.name, &file)
        .ok_or_else(|| ApiError::NotFound(format!("no such backup: {file}")))?;
    let sealed = tokio::fs::read(&path).await.map_err(|e| match e.kind() {
        std::io::ErrorKind::NotFound => ApiError::NotFound(format!("no such backup: {file}")),
        _ => ApiError::internal("read the backup", &e),
    })?;
    Ok(attachment("application/json", &file, sealed))
}

async fn remove<S: Sections, H: HostHalf, R: Caller>(
    State(backups): State<Engine<S, H>>,
    caller: R,
    State(app): State<ApplianceState>,
    Path(file): Path<String>,
) -> Result<Json<ScheduleView>, ApiError> {
    let (this, doomed) = (backups.clone(), file.clone());
    // Off the runtime: a scheduled write holds the lock across its fsyncs.
    let removed = tokio::task::spawn_blocking(move || this.remove(&doomed))
        .await
        .map_err(|e| ApiError::internal("run the backup deletion", &e))?
        .map_err(|e| ApiError::internal("delete the backup", &e))?;
    if !removed {
        return Err(ApiError::NotFound(format!("no such backup: {file}")));
    }
    audit!(&app, caller.identity(), "deleted a backup", "file" => &file).await;
    Ok(Json(view(&backups, &app).await?))
}

async fn view<S, H>(
    backups: &Engine<S, H>,
    app: &ApplianceState,
) -> Result<ScheduleView, ApiError> {
    Ok(ScheduleView {
        schedule: app
            .store
            .setting_doc::<BackupSchedule>(SCHEDULE_SETTING)
            .await?,
        passphrase_set: app.store.secret(PASSPHRASE_SECRET).await?.is_some(),
        runs: backups.schedule_runs(),
        state: app.store.box_state_doc::<BackupState>(STATE_KEY).await?,
        files: schedule::list(&backups.dir, &backups.name)
            .map_err(|e| ApiError::internal("read the backup directory", &e))?,
    })
}

impl<S, H> Engine<S, H> {
    /// A key-deriving step off the runtime workers, one at a time.
    async fn blocking<T: Send + 'static>(
        &self,
        what: &'static str,
        queue: bool,
        step: impl FnOnce() -> Result<T, BackupError> + Send + 'static,
    ) -> Result<T, ApiError> {
        let turn = if queue {
            self.kdf
                .clone()
                .acquire_owned()
                .await
                .map_err(|e| ApiError::internal(what, &e))?
        } else {
            self.kdf.clone().try_acquire_owned().map_err(|_| {
                ApiError::Unsupported(
                    "this appliance is already opening a backup; try again in a moment".to_string(),
                )
            })?
        };
        tokio::task::spawn_blocking(move || {
            let _turn = turn;
            step()
        })
        .await
        .map_err(|e| ApiError::internal(what, &e))?
        .map_err(ApiError::from)
    }
}

#[cfg(test)]
pub(crate) mod tests;
