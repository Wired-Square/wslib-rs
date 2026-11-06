//! What is inside a bundle: the platform's sections, the serving pair, the
//! authorised-keys files, and the named sections a product
//! [`put`](Snapshot::put)s and [`take`](Bundle::take)s back.
//!
//! A bundle is never written unsealed: [`Snapshot`] has private fields and no
//! `Serialize`, so the way out of one is the seal. It carries password hashes,
//! TOTP keys, recovery-code hashes and passkeys, and never the `secret.` and
//! `box.` settings, the audit log, the asserted roles, the sessions or a
//! session cutoff. `{:?}` on a [`Snapshot`] or a [`Bundle`] prints counts and
//! names, never a hash or a product's data.

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Utc};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use wslib_appliance_core::backend::{MAX_APP_LEN, is_app_name};
use wslib_appliance_store::{Account, Passkey, SecondFactors, Store, Totp};
use wslib_appliance_types::backup::{BundleHeader, Chosen, Contains, MIN_PASSPHRASE_LEN};
use wslib_appliance_types::host::{HostSection, SshKeyFile};
use wslib_appliance_types::tls::ServingPair;
use wslib_appliance_types::{AppRole, Role, TrustedCa, TrustedCert, User};
use wslib_secret::Secret;
// The store's own `sqlx`, so the `Transaction` is the type it takes.
use wslib_appliance_store::sqlx::{Sqlite, Transaction};

use crate::envelope::{self, Ceiling, Provenance};
use crate::hooks::{APP_SECTIONS, APP_SECTIONS_VERSION, AppSections};
use crate::{BackupError, Sections};

/// A `users` row as a bundle carries it. [`User`] is flattened whole, so a field
/// added to it reaches a bundle.
#[derive(Clone, Serialize, Deserialize)]
struct StoredAccount {
    #[serde(flatten)]
    user: User,
    password_hash: Secret,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    totp: Option<StoredTotp>,
    /// Lowercase hex SHA-256 of each unused recovery code.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    recovery_codes: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    passkeys: Vec<StoredPasskey>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    totp_required: bool,
}

#[derive(Clone, Serialize, Deserialize)]
struct StoredTotp {
    secret: Secret,
    confirmed: bool,
    last_step: Option<u64>,
}

#[derive(Clone, Serialize, Deserialize)]
struct StoredPasskey {
    id: String,
    credential_id: Vec<u8>,
    public_key: Vec<u8>,
    sign_count: u32,
    name: String,
    rp_id: String,
    created_at: DateTime<Utc>,
    last_used_at: Option<DateTime<Utc>>,
}

impl StoredAccount {
    fn new(account: Account, factors: Option<SecondFactors>) -> Self {
        let factors = factors.unwrap_or_default();
        Self {
            user: account.user,
            password_hash: account.password_hash,
            totp: factors.totp.map(|t| StoredTotp {
                secret: t.secret,
                confirmed: t.confirmed,
                last_step: t.last_step,
            }),
            recovery_codes: factors.recovery_codes,
            passkeys: factors
                .passkeys
                .into_iter()
                .map(|p| StoredPasskey {
                    id: p.id,
                    credential_id: p.credential_id,
                    public_key: p.public_key,
                    sign_count: p.sign_count,
                    name: p.name,
                    rp_id: p.rp_id,
                    created_at: p.created_at,
                    last_used_at: p.last_used_at,
                })
                .collect(),
            totp_required: factors.totp_required,
        }
    }

    fn second_factors(&self) -> SecondFactors {
        let user_id = &self.user.id;
        SecondFactors {
            user_id: user_id.clone(),
            totp: self.totp.as_ref().map(|t| Totp {
                secret: t.secret.clone(),
                confirmed: t.confirmed,
                last_step: t.last_step,
            }),
            recovery_codes: self.recovery_codes.clone(),
            passkeys: self
                .passkeys
                .iter()
                .map(|p| Passkey {
                    id: p.id.clone(),
                    user_id: user_id.clone(),
                    credential_id: p.credential_id.clone(),
                    public_key: p.public_key.clone(),
                    sign_count: p.sign_count,
                    name: p.name.clone(),
                    rp_id: p.rp_id.clone(),
                    created_at: p.created_at,
                    last_used_at: p.last_used_at,
                })
                .collect(),
            totp_required: self.totp_required,
        }
    }
}

/// The sections as serialised inside the seal, apart from [`Snapshot`] so the
/// handle a consumer holds is not serialisable.
#[derive(Clone, Default, Serialize, Deserialize)]
struct Body {
    #[serde(default)]
    users: Vec<StoredAccount>,
    #[serde(default)]
    app_roles: Vec<AppRole>,
    #[serde(default)]
    settings: BTreeMap<String, String>,
    #[serde(default)]
    trusted_certs: Vec<TrustedCert>,
    #[serde(default)]
    trusted_cas: Vec<TrustedCa>,

    /// Beside [`app`](Self::app), never a name in it, so a product's own
    /// section of that name cannot collide.
    #[serde(default)]
    serving_certificate: Option<ServingPair>,
    #[serde(default)]
    ssh_keys: Vec<SshKeyFile>,
    /// The name is applied after the commit; the addressing is only reported.
    #[serde(default)]
    host: Option<HostSection>,
    /// The product's own sections, as raw JSON, so one a different build wrote
    /// survives a round trip.
    #[serde(default)]
    app: BTreeMap<String, serde_json::Value>,
}

impl Body {
    /// Refuse what this crate would not have written, and count what it holds:
    /// the counts are recomputed, never trusted.
    fn check(&self) -> Result<Contains, BackupError> {
        if let Some(name) = self.app.keys().find(|name| !is_section_name(name)) {
            return Err(BackupError::Malformed(format!(
                "a section has a name this crate would not have written ({} bytes long)",
                name.len()
            )));
        }
        check_app_roles(&self.app_roles)?;
        check_accounts(&self.users)?;
        Ok(self.contains())
    }

    fn contains(&self) -> Contains {
        let mut contains = Contains::default();
        contains.accounts = self.users.len();
        contains.settings = self.settings.len();
        contains.trusted_certs = self.trusted_certs.len();
        contains.trusted_cas = self.trusted_cas.len();
        contains.serving_certificate = self.serving_certificate.is_some();
        contains.ssh_keys = self.ssh_keys.len();
        contains.host = self.host.is_some();
        contains.app = self
            .app
            .iter()
            .map(|(name, value)| (name.clone(), value.as_array().map_or(1, Vec::len)))
            .collect();
        contains
    }
}

impl std::fmt::Debug for Body {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.contains().fmt(f)
    }
}

/// A box's configuration on its way into a bundle, which is its only way out.
#[derive(Debug)]
pub struct Snapshot {
    body: Body,
    leave_out: BTreeSet<String>,
    names: BTreeSet<String>,
}

impl Snapshot {
    /// Read the platform's sections, one read each rather than one transaction,
    /// so a write between them can land in a bundle half-seen.
    pub(crate) async fn capture(store: &Store) -> Result<Self, BackupError> {
        let mut factors: BTreeMap<String, SecondFactors> = store
            .second_factors()
            .await?
            .into_iter()
            .map(|f| (f.user_id.clone(), f))
            .collect();
        Ok(Self::of(Body {
            users: store
                .accounts()
                .await?
                .into_iter()
                .map(|a| {
                    let theirs = factors.remove(&a.user.id);
                    StoredAccount::new(a, theirs)
                })
                .collect(),
            app_roles: store.app_roles().await?,
            settings: store.exportable_settings().await?,
            trusted_certs: store.trusted_certs().await?,
            trusted_cas: store.trusted_cas().await?,
            serving_certificate: None,
            ssh_keys: Vec::new(),
            host: None,
            app: BTreeMap::new(),
        }))
    }

    /// The outbound trust alone.
    pub(crate) async fn capture_application(store: &Store) -> Result<Self, BackupError> {
        Ok(Self::of(Body {
            trusted_certs: store.trusted_certs().await?,
            trusted_cas: store.trusted_cas().await?,
            ..Body::default()
        }))
    }

    fn of(body: Body) -> Self {
        Self {
            body,
            leave_out: BTreeSet::new(),
            names: BTreeSet::new(),
        }
    }

    pub(crate) async fn capture_sections(
        &mut self,
        sections: &impl Sections,
        store: &Store,
    ) -> Result<(), BackupError> {
        self.names = sections.names().await?;
        sections.capture(store, self).await
    }

    /// What [`Sections::names`] answered for this take: the only names
    /// [`put`](Self::put) accepts.
    pub fn names(&self) -> &BTreeSet<String> {
        &self.names
    }

    /// Add a product's own section under `name`, which travels in the plaintext
    /// header. Refused if it is not identifier-shaped or not one of the take's
    /// [`names`](Self::names); dropped if the take
    /// [leaves it out](Self::leaves_out).
    pub fn put<T: Serialize>(&mut self, name: &str, rows: &T) -> Result<(), BackupError> {
        if !is_section_name(name) {
            return Err(BackupError::Internal(format!(
                "a section name may hold only letters, digits, hyphens and underscores, \
                 up to {MOST_A_SECTION_NAME}, because it travels in the bundle's plaintext \
                 header — {name:?} does not"
            )));
        }
        if !self.names.contains(name) {
            return Err(BackupError::Internal(format!(
                "the section {name:?} is not one `Sections::names` answered for this take"
            )));
        }
        if self.leaves_out(name) {
            return Ok(());
        }
        let value = serde_json::to_value(rows).map_err(BackupError::internal)?;
        self.body.app.insert(name.to_string(), value);
        Ok(())
    }

    /// Whether the take leaves the product's section `name` out.
    pub fn leaves_out(&self, name: &str) -> bool {
        self.leave_out.contains(name)
    }

    pub(crate) fn leaving_out(self, leave_out: BTreeSet<String>) -> Self {
        Self { leave_out, ..self }
    }

    pub(crate) fn put_serving_pair(&mut self, pair: ServingPair) {
        self.body.serving_certificate = Some(pair);
    }

    pub(crate) fn put_ssh_keys(&mut self, files: Vec<SshKeyFile>) {
        self.body.ssh_keys = files;
    }

    pub(crate) fn put_host(&mut self, host: HostSection) {
        self.body.host = Some(host);
    }

    #[cfg(test)]
    pub(crate) fn put_app_roles(&mut self, rows: Vec<AppRole>) {
        self.body.app_roles = rows;
    }

    /// The application half, unsealed, for a console to seal.
    pub(crate) fn for_console(self, product: &str, version: &str, schema: u32) -> AppSections {
        let Body {
            trusted_certs,
            trusted_cas,
            app,
            ..
        } = self.body;
        AppSections {
            format: APP_SECTIONS.to_string(),
            version: APP_SECTIONS_VERSION,
            product: product.to_string(),
            app_version: version.to_string(),
            app_schema_version: schema,
            taken_at: wslib_appliance_store::now(),
            trusted_certs,
            trusted_cas,
            app,
        }
    }

    pub(crate) fn seal(
        &self,
        passphrase: &Secret,
        provenance: &Provenance,
    ) -> Result<String, BackupError> {
        check_passphrase(passphrase)?;
        let mut plaintext = envelope::Wiping::default();
        serde_json::to_writer(&mut plaintext, &self.body).map_err(BackupError::internal)?;
        envelope::seal(
            &plaintext.0,
            self.body.contains(),
            passphrase.expose(),
            provenance,
        )
    }
}

const MOST_A_SECTION_NAME: usize = 64;

pub(crate) fn is_section_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MOST_A_SECTION_NAME
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

fn check_app_roles(rows: &[AppRole]) -> Result<(), BackupError> {
    let mut seen = std::collections::HashSet::new();
    for row in rows {
        if row.role == Role::HostAdmin {
            return Err(BackupError::malformed(
                "an account's role in an app is host admin",
            ));
        }
        if !is_app_name(&row.app) {
            return Err(BackupError::malformed(format!(
                "an app's name is not one path segment of at most {MAX_APP_LEN} bytes \
                 ({} bytes long)",
                row.app.len()
            )));
        }
        if !seen.insert((&row.user_id, &row.app)) {
            return Err(BackupError::malformed(
                "an account has two roles in one app",
            ));
        }
    }
    Ok(())
}

fn check_accounts(users: &[StoredAccount]) -> Result<(), BackupError> {
    let mut accounts = std::collections::HashSet::new();
    if !users.iter().all(|a| accounts.insert(&a.user.id)) {
        return Err(BackupError::malformed("two accounts in it share an id"));
    }
    let is_hash =
        |h: &String| h.len() == 64 && h.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
    if !users.iter().flat_map(|a| &a.recovery_codes).all(is_hash) {
        return Err(BackupError::malformed(
            "a recovery code's hash is not 64 lowercase hex digits",
        ));
    }
    let mut ids = std::collections::HashSet::new();
    let mut credentials = std::collections::HashSet::new();
    for passkey in users.iter().flat_map(|a| &a.passkeys) {
        if !ids.insert(&passkey.id) || !credentials.insert(&passkey.credential_id) {
            return Err(BackupError::malformed("two passkeys in it are one"));
        }
    }
    Ok(())
}

pub fn check_passphrase(passphrase: &Secret) -> Result<(), BackupError> {
    if passphrase.expose().chars().count() < MIN_PASSPHRASE_LEN {
        return Err(BackupError::Passphrase(format!(
            "a backup passphrase must be at least {MIN_PASSPHRASE_LEN} characters — \
             it is the only thing protecting a file that leaves the box"
        )));
    }
    Ok(())
}

#[derive(Debug)]
pub struct Bundle {
    header: BundleHeader,
    body: Body,
}

impl Bundle {
    /// `ours` is this build's schema version. Synchronous and dear: call it
    /// from `spawn_blocking`.
    pub(crate) fn open(text: &str, passphrase: &Secret, ours: u32) -> Result<Self, BackupError> {
        Self::open_within(text, passphrase, ours, Ceiling::General)
    }

    /// [`Bundle::open`] for a route with no session behind it, at the lower
    /// KDF ceiling.
    pub(crate) fn open_unauthenticated(
        text: &str,
        passphrase: &Secret,
        ours: u32,
    ) -> Result<Self, BackupError> {
        Self::open_within(text, passphrase, ours, Ceiling::Unauthenticated)
    }

    fn open_within(
        text: &str,
        passphrase: &Secret,
        ours: u32,
        ceiling: Ceiling,
    ) -> Result<Self, BackupError> {
        check_passphrase(passphrase)?;
        let (mut header, plaintext) = envelope::open(text, passphrase.expose(), ours, ceiling)?;

        // serde's message embeds the offending value, which may be a hash.
        let body: Body = serde_json::from_slice(&plaintext).map_err(|e| {
            BackupError::Malformed(format!(
                "the snapshot inside it did not parse, at line {} column {}",
                e.line(),
                e.column()
            ))
        })?;
        header.contains = body.check()?;
        Ok(Self { header, body })
    }

    /// The application half a console captured, with the checks
    /// [`Bundle::open`] makes.
    pub(crate) fn from_console(
        sections: AppSections,
        product: &str,
        ours: u32,
    ) -> Result<Self, BackupError> {
        if sections.product != product {
            return Err(BackupError::OtherProduct);
        }
        if sections.app_schema_version > ours {
            return Err(BackupError::SchemaTooNew {
                theirs: sections.app_schema_version,
                ours,
            });
        }
        let body = Body {
            trusted_certs: sections.trusted_certs,
            trusted_cas: sections.trusted_cas,
            app: sections.app,
            ..Body::default()
        };
        let mut header = BundleHeader::default();
        header.format = sections.format;
        header.version = sections.version;
        header.created_at = sections.taken_at;
        header.app_version = sections.app_version;
        header.app_schema_version = sections.app_schema_version;
        header.contains = body.check()?;
        Ok(Self { header, body })
    }

    /// The file's header, its counts recomputed from what it holds.
    pub fn header(&self) -> &BundleHeader {
        &self.header
    }

    /// Whether this bundle would leave the box an administrator who can sign in.
    pub(crate) fn has_enabled_admin(&self) -> bool {
        self.body
            .users
            .iter()
            .any(|a| a.user.enabled && a.user.role.allows(Role::Admin))
    }

    /// Whether a restore of this bundle's accounts would seat an enabled host admin.
    pub fn carries_enabled_host_admin(&self) -> bool {
        self.host_admins().1
    }

    /// Whether this bundle carries a host admin, and whether an enabled one.
    pub(crate) fn host_admins(&self) -> (bool, bool) {
        let host_admins = || {
            self.body
                .users
                .iter()
                .filter(|a| a.user.role == Role::HostAdmin)
        };
        (
            host_admins().next().is_some(),
            host_admins().any(|a| a.user.enabled),
        )
    }

    /// A product's own section, parsed; `Ok(None)` when the bundle does not
    /// carry it.
    pub fn take<T: DeserializeOwned>(&self, name: &str) -> Result<Option<T>, BackupError> {
        self.body
            .app
            .get(name)
            .map(|value| {
                // serde's message is dropped, as in `open`.
                T::deserialize(value).map_err(|_| {
                    BackupError::Malformed(format!("the {name:?} section did not parse"))
                })
            })
            .transpose()
    }

    pub(crate) fn serving_pair(&self) -> Option<&ServingPair> {
        self.body.serving_certificate.as_ref()
    }

    pub(crate) fn ssh_keys(&self) -> &[SshKeyFile] {
        &self.body.ssh_keys
    }

    pub(crate) fn host(&self) -> Option<&HostSection> {
        self.body.host.as_ref()
    }

    /// Write the chosen platform sections into `tx`, in the transaction a
    /// product's [`Sections::restore`] writes into. Each chosen section
    /// replaces the box's; restoring the accounts signs everybody out.
    pub(crate) async fn restore_platform(
        &self,
        store: &Store,
        tx: &mut Transaction<'_, Sqlite>,
        sections: &Chosen,
    ) -> Result<(), BackupError> {
        if sections.accounts {
            let accounts: Vec<Account> = self
                .body
                .users
                .iter()
                .map(|stored| Account {
                    user: stored.user.clone(),
                    password_hash: stored.password_hash.clone(),
                    // Ignored: `replace_accounts` stamps its own.
                    sessions_valid_from: Utc::now(),
                })
                .collect();
            let factors: Vec<SecondFactors> = self
                .body
                .users
                .iter()
                .map(StoredAccount::second_factors)
                .collect();
            store
                .replace_accounts(tx, &accounts, &self.body.app_roles, &factors)
                .await
                .map_err(|e| match &e {
                    wslib_appliance_store::StoreError::Db(
                        wslib_appliance_store::sqlx::Error::Database(db),
                    ) if db.is_unique_violation() => {
                        BackupError::malformed("two accounts in it share a username")
                    }
                    _ => BackupError::Store(e),
                })?;
        }
        if sections.settings {
            store
                .replace_exportable_settings(tx, &self.body.settings)
                .await?;
        }
        if sections.trusted_certs {
            Store::replace_trusted_certs(tx, &self.body.trusted_certs).await?;
        }
        if sections.trusted_cas {
            Store::replace_trusted_cas(tx, &self.body.trusted_cas).await?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::DateTime;

    fn passphrase() -> Secret {
        Secret::new("correct horse battery staple")
    }

    fn provenance() -> Provenance {
        Provenance {
            source_host: "widget-01".to_string(),
            box_id: None,
            app_version: "0.1.0".to_string(),
            app_schema_version: 1,
        }
    }

    /// A store with two accounts, two settings (one secret), a pinned cert and a
    /// trusted authority.
    async fn furnished() -> Store {
        let store = Store::open_in_memory(None).await.expect("store");
        store
            .create_user("admin", "$argon2id$v=19$fake$hash", Role::Admin)
            .await
            .expect("create");
        store
            .create_user("viewer", "$argon2id$v=19$fake$hash2", Role::Viewer)
            .await
            .expect("create");
        store
            .set_setting("branding.app_name", "Widget Monitor")
            .await
            .expect("set");
        store
            .set_secret("sample_secret", &Secret::new("d0not1eak"))
            .await
            .expect("set");
        store
            .pin_cert(&TrustedCert {
                host: "widget-02.local".to_string(),
                sha256: "aa11".to_string(),
                subject: "CN=widget-02".to_string(),
                issuer: "CN=widget-02".to_string(),
                not_before: DateTime::from_timestamp(1_757_000_000, 0).unwrap(),
                not_after: DateTime::from_timestamp(1_788_536_000, 0).unwrap(),
                added_at: DateTime::from_timestamp(1_757_000_100, 0).unwrap(),
                added_by: "admin".to_string(),
            })
            .await
            .expect("pin");
        store
            .trust_ca(&TrustedCa {
                sha256: "bb22".to_string(),
                subject: "CN=Widget Root".to_string(),
                not_before: DateTime::from_timestamp(1_757_000_000, 0).unwrap(),
                not_after: DateTime::from_timestamp(2_072_536_000, 0).unwrap(),
                added_at: DateTime::from_timestamp(1_757_000_100, 0).unwrap(),
                added_by: "admin".to_string(),
                pem: "-----BEGIN CERTIFICATE-----\nbb22\n-----END CERTIFICATE-----\n".to_string(),
            })
            .await
            .expect("trust");
        store
    }

    async fn sealed(store: &Store) -> String {
        Snapshot::capture(store)
            .await
            .expect("capture")
            .seal(&passphrase(), &provenance())
            .expect("seal")
    }

    async fn naming(store: &Store, name: &str) -> Snapshot {
        let mut snapshot = Snapshot::capture(store).await.expect("capture");
        snapshot.names.insert(name.to_string());
        snapshot
    }

    /// An empty store's bundle with one product section in it, sealed and opened.
    async fn bundle_with(name: &str, value: &impl Serialize) -> Bundle {
        let store = Store::open_in_memory(None).await.expect("store");
        let mut snapshot = naming(&store, name).await;
        snapshot.put(name, value).expect("put");
        let text = snapshot.seal(&passphrase(), &provenance()).expect("seal");
        Bundle::open(&text, &passphrase(), 1).expect("open")
    }

    async fn restored_onto_a_fresh_box(text: &str) -> Store {
        let target = Store::open_in_memory(None).await.expect("store");
        let bundle = Bundle::open(text, &passphrase(), 1).expect("open");
        let mut tx = target.begin().await.expect("begin");
        bundle
            .restore_platform(&target, &mut tx, &everything())
            .await
            .expect("restore");
        tx.commit().await.expect("commit");
        target
    }

    fn everything() -> Chosen {
        Chosen {
            accounts: true,
            settings: true,
            trusted_certs: true,
            trusted_cas: true,
            ..Default::default()
        }
    }

    /// `text` applied onto `furnished()`'s own state, with only `sections`.
    async fn restored_onto_a_used_box(text: &str, sections: Chosen) -> Store {
        let target = furnished().await;
        // Something to tell "left alone" from "replaced with the same".
        target
            .create_user("operator", "$argon2id$v=19$fake$hash3", Role::Operator)
            .await
            .expect("create");
        target
            .set_setting("branding.app_name", "Something Else")
            .await
            .expect("set");
        target
            .pin_cert(&TrustedCert {
                host: "widget-03.local".to_string(),
                sha256: "bb22".to_string(),
                subject: "CN=widget-03".to_string(),
                issuer: "CN=widget-03".to_string(),
                not_before: DateTime::from_timestamp(1_757_000_000, 0).unwrap(),
                not_after: DateTime::from_timestamp(1_788_536_000, 0).unwrap(),
                added_at: DateTime::from_timestamp(1_757_000_100, 0).unwrap(),
                added_by: "admin".to_string(),
            })
            .await
            .expect("pin");
        wslib_appliance_store::sqlx::query(
            "UPDATE users SET sessions_valid_from = '1970-01-01T00:00:00.000000Z'",
        )
        .execute(target.pool())
        .await
        .expect("an old cutoff");
        let bundle = Bundle::open(text, &passphrase(), 1).expect("open");
        let mut tx = target.begin().await.expect("begin");
        bundle
            .restore_platform(&target, &mut tx, &sections)
            .await
            .expect("restore");
        tx.commit().await.expect("commit");
        target
    }

    #[tokio::test]
    async fn a_box_survives_being_carried_to_a_replacement() {
        let source = furnished().await;
        let target = restored_onto_a_fresh_box(&sealed(&source).await).await;

        let users = target.users().await.expect("users");
        assert_eq!(users.len(), 2);
        assert_eq!(users[0].username, "admin");
        assert_eq!(users[0].role, Role::Admin);
        assert_eq!(
            target
                .user_by_username("admin")
                .await
                .unwrap()
                .unwrap()
                .password_hash
                .expose(),
            "$argon2id$v=19$fake$hash"
        );
        assert_eq!(
            target.setting("branding.app_name").await.unwrap(),
            Some("Widget Monitor".to_string())
        );
        assert_eq!(target.trusted_certs().await.unwrap().len(), 1);
        let authorities = target.trusted_cas().await.unwrap();
        assert_eq!(authorities.len(), 1);
        assert!(authorities[0].pem.contains("bb22"), "the bytes travelled");
    }

    #[tokio::test]
    async fn a_restore_does_not_move_a_session_revocation_backwards() {
        // A carried cutoff would un-revoke a stolen cookie by restoring a backup
        // taken before the password was rotated.
        let source = furnished().await;
        let text = sealed(&source).await;

        let before = source
            .user_by_username("admin")
            .await
            .unwrap()
            .unwrap()
            .sessions_valid_from;

        let target = restored_onto_a_fresh_box(&text).await;
        let after = target
            .user_by_username("admin")
            .await
            .unwrap()
            .unwrap()
            .sessions_valid_from;

        assert!(
            after >= before,
            "the cutoff only ever moves forward: {before} -> {after}"
        );
    }

    #[tokio::test]
    async fn a_secret_does_not_travel() {
        let source = furnished().await;
        let text = sealed(&source).await;

        assert!(!text.contains("d0not1eak"), "not in the file at all");
        let target = restored_onto_a_fresh_box(&text).await;
        assert_eq!(
            target
                .secret("sample_secret")
                .await
                .unwrap()
                .as_ref()
                .map(Secret::expose),
            None,
            "and nothing put one on the box it was restored onto"
        );
    }

    #[tokio::test]
    async fn no_session_travels() {
        let source = furnished().await;
        let admin = source.user_by_username("admin").await.unwrap().unwrap();
        let table = wslib_appliance_store::SESSIONS_TABLE;
        wslib_appliance_store::sqlx::query(&format!(
            "INSERT INTO {table} VALUES ('d0not1eakhash', ?1, ?2, ?2, ?2, ?2)"
        ))
        .bind(&admin.user.id)
        .bind(wslib_appliance_store::stamp(wslib_appliance_store::now()))
        .execute(source.pool())
        .await
        .unwrap();
        let text = sealed(&source).await;
        assert!(!text.contains("d0not1eakhash"), "not in the file at all");

        let target = restored_onto_a_fresh_box(&text).await;
        let rows: i64 =
            wslib_appliance_store::sqlx::query_scalar(&format!("SELECT count(*) FROM {table}"))
                .fetch_one(target.pool())
                .await
                .unwrap();
        assert_eq!(
            rows, 0,
            "and nothing put one on the box it was restored onto"
        );
    }

    #[tokio::test]
    async fn a_snapshot_cannot_be_written_out_except_through_the_seal() {
        // `serde_json::to_string(&snapshot)` does not compile.
        let store = furnished().await;
        let snapshot = Snapshot::capture(&store).await.expect("capture");
        let text = snapshot.seal(&passphrase(), &provenance()).expect("seal");
        assert_eq!(
            Bundle::open(&text, &passphrase(), 1)
                .expect("open")
                .header()
                .contains
                .accounts,
            2,
            "the way out is through the seal, and it still says what it holds"
        );
    }

    #[tokio::test]
    async fn a_bundle_reaches_a_log_line_as_counts() {
        let store = furnished().await;
        let mut snapshot = naming(&store, "devices").await;
        snapshot
            .put("devices", &[serde_json::json!({"password": "hunter2"})])
            .expect("put");
        let text = snapshot.seal(&passphrase(), &provenance()).expect("seal");
        let bundle = Bundle::open(&text, &passphrase(), 1).expect("open");

        for rendered in [format!("{snapshot:?}"), format!("{bundle:?}")] {
            assert!(!rendered.contains("fake$hash"), "{rendered}");
            assert!(!rendered.contains("hunter2"), "{rendered}");
            assert!(rendered.contains("accounts: 2"), "{rendered}");
            assert!(rendered.contains("\"devices\": 1"), "{rendered}");
        }
    }

    #[tokio::test]
    async fn a_products_own_section_goes_in_and_comes_back_out() {
        #[derive(Debug, PartialEq, Serialize, Deserialize)]
        struct Device {
            id: u32,
            label: String,
        }

        let devices = vec![
            Device {
                id: 1,
                label: "rack A".to_string(),
            },
            Device {
                id: 2,
                label: "rack B".to_string(),
            },
        ];
        let bundle = bundle_with("devices", &devices).await;

        assert_eq!(
            bundle.take::<Vec<Device>>("devices").unwrap(),
            Some(devices)
        );
        assert_eq!(
            bundle.header().contains.app.get("devices"),
            Some(&2),
            "and the plaintext header counts it, so a picker can say what is inside"
        );
    }

    #[tokio::test]
    async fn a_section_name_that_is_not_a_name_is_refused() {
        let store = Store::open_in_memory(None).await.expect("store");
        let mut snapshot = naming(&store, "device_readings-2").await;
        for bad in ["", "user@example.com", "a name", "../etc"] {
            assert!(snapshot.put(bad, &1).is_err(), "{bad:?}");
        }
        assert!(snapshot.put("device_readings-2", &1).is_ok());
    }

    #[tokio::test]
    async fn a_section_outside_the_takes_names_is_refused() {
        let store = Store::open_in_memory(None).await.expect("store");
        let mut snapshot = naming(&store, "gauges").await;
        assert!(matches!(
            snapshot.put("dials", &1),
            Err(BackupError::Internal(_))
        ));
        assert!(snapshot.body.app.is_empty());
    }

    #[tokio::test]
    async fn a_section_this_build_does_not_know_about_is_carried_rather_than_dropped() {
        let bundle = bundle_with("from-the-future", &serde_json::json!({"shape": "unknown"})).await;
        assert_eq!(
            bundle.take::<serde_json::Value>("from-the-future").unwrap(),
            Some(serde_json::json!({"shape": "unknown"}))
        );
    }

    #[tokio::test]
    async fn a_section_the_bundle_does_not_carry_is_absent_rather_than_an_error() {
        let store = Store::open_in_memory(None).await.expect("store");
        let bundle = Bundle::open(&sealed(&store).await, &passphrase(), 1).expect("open");
        assert_eq!(bundle.take::<Vec<u32>>("devices").unwrap(), None);
    }

    #[tokio::test]
    async fn a_section_of_another_shape_is_damaged_and_the_message_carries_none_of_it() {
        let bundle = bundle_with("devices", &serde_json::json!([{"secret": "hunter2"}])).await;
        let err = bundle.take::<Vec<u32>>("devices").unwrap_err();
        assert_eq!(
            err.to_string(),
            "this backup is damaged: the \"devices\" section did not parse"
        );
    }

    #[tokio::test]
    async fn the_audit_log_is_not_carried() {
        let source = furnished().await;
        source
            .record_audit(&wslib_appliance_types::AuditRecord {
                at: Utc::now(),
                level: "INFO".to_string(),
                actor: "admin".to_string(),
                actor_id: None,
                target: "test".to_string(),
                message: "did a thing".to_string(),
                fields: vec![],
            })
            .await
            .expect("audit");

        let text = sealed(&source).await;
        let (_, plaintext) =
            envelope::open(&text, passphrase().expose(), 1, Ceiling::General).expect("open");

        assert!(!String::from_utf8_lossy(&plaintext).contains("did a thing"));
        let target = restored_onto_a_fresh_box(&text).await;
        assert!(target.audit(10, None).await.unwrap().items.is_empty());
    }

    #[tokio::test]
    async fn the_asserted_roles_are_the_boxs_own_neither_carried_nor_replaced() {
        let asserted = |store: Store, id: &'static str| async move {
            store
                .asserted_role("ingress", id, id, None, Some(Role::Admin))
                .await
                .expect("asserted");
            store
        };
        let source = asserted(furnished().await, "from-the-old-box").await;
        let text = sealed(&source).await;
        let (_, plaintext) =
            envelope::open(&text, passphrase().expose(), 1, Ceiling::General).expect("open");
        assert!(!String::from_utf8_lossy(&plaintext).contains("from-the-old-box"));

        let target = asserted(Store::open_in_memory(None).await.unwrap(), "on-this-box").await;
        let bundle = Bundle::open(&text, &passphrase(), 1).expect("open");
        let mut tx = target.begin().await.expect("begin");
        bundle
            .restore_platform(&target, &mut tx, &everything())
            .await
            .expect("restore");
        tx.commit().await.expect("commit");
        let kept = target.asserted_callers("ingress").await.unwrap();
        assert_eq!(
            kept.iter().map(|c| c.id.as_str()).collect::<Vec<_>>(),
            ["on-this-box"]
        );
    }

    #[tokio::test]
    async fn a_bundle_says_whether_it_would_leave_anybody_able_to_sign_in() {
        let source = furnished().await;
        let bundle = Bundle::open(&sealed(&source).await, &passphrase(), 1).expect("open");
        assert!(bundle.has_enabled_admin());

        let empty = Store::open_in_memory(None).await.expect("store");
        let bundle = Bundle::open(&sealed(&empty).await, &passphrase(), 1).expect("open");
        assert!(
            !bundle.has_enabled_admin(),
            "restoring this over HTTPS would lock the browser out for good"
        );
        assert!(!bundle.carries_enabled_host_admin());

        empty
            .create_user("owner", "$argon2id$v=19$fake$hash", Role::HostAdmin)
            .await
            .expect("create");
        let bundle = Bundle::open(&sealed(&empty).await, &passphrase(), 1).expect("open");
        assert!(
            bundle.has_enabled_admin(),
            "a host admin is an administrator"
        );
        assert_eq!(bundle.host_admins(), (true, true));
        assert!(bundle.carries_enabled_host_admin());
    }

    #[tokio::test]
    async fn the_app_roles_travel_with_the_accounts_and_an_older_bundle_carries_none() {
        let source = furnished().await;
        let viewer = source.user_by_username("viewer").await.unwrap().unwrap();
        source
            .set_app_role(&viewer.user.id, "widgets", Some(Role::Operator))
            .await
            .unwrap();
        let target = restored_onto_a_fresh_box(&sealed(&source).await).await;
        assert_eq!(
            target.app_roles().await.unwrap(),
            source.app_roles().await.unwrap()
        );

        let mut older = serde_json::to_value(Body::default()).unwrap();
        older.as_object_mut().unwrap().remove("app_roles");
        let older: Body = serde_json::from_value(older).unwrap();
        assert!(older.app_roles.is_empty());
    }

    /// `username`'s TOTP, two recovery codes and a passkey, each named by
    /// `credential`.
    async fn second_factors_for(store: &Store, username: &str, credential: u8) -> String {
        let id = store
            .user_by_username(username)
            .await
            .unwrap()
            .unwrap()
            .user
            .id;
        let key = Secret::new(format!("key {credential}"));
        store.enrol_totp(&id, &key).await.unwrap();
        store
            .confirm_totp(&id, &key, 100, &[code(credential, 0), code(credential, 1)])
            .await
            .unwrap();
        let passkey = store
            .add_passkey(
                &id,
                wslib_appliance_store::NewPasskey {
                    credential_id: vec![credential; 16],
                    public_key: vec![0xa5, 1, 2],
                    sign_count: 7,
                    name: "laptop".to_string(),
                    rp_id: "widget-01.local".to_string(),
                },
            )
            .await
            .unwrap();
        store.use_passkey(&passkey.id, 8).await.unwrap();
        id
    }

    fn code(credential: u8, n: u8) -> String {
        format!("{credential:02x}{n:02x}").repeat(16)
    }

    /// The account's TOTP key, recovery-code count and passkeys.
    async fn factors_of(store: &Store, id: &str) -> (Option<String>, u64, Vec<Passkey>) {
        (
            store
                .totp(id)
                .await
                .unwrap()
                .map(|t| t.secret.expose().to_string()),
            store.recovery_codes_left(id).await.unwrap(),
            store.passkeys(id).await.unwrap(),
        )
    }

    #[tokio::test]
    async fn a_required_enrolment_travels_with_the_account() {
        let source = furnished().await;
        let id = second_factors_for(&source, "admin", 1).await;
        source.require_totp(&id).await.unwrap();
        let fresh = restored_onto_a_fresh_box(&sealed(&source).await).await;
        assert!(fresh.totp_required(&id).await.unwrap());
        assert!(fresh.totp(&id).await.unwrap().is_none());
        assert_eq!(fresh.passkeys(&id).await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn the_second_factors_travel_with_the_accounts() {
        let source = furnished().await;
        let id = second_factors_for(&source, "admin", 1).await;
        let fresh = restored_onto_a_fresh_box(&sealed(&source).await).await;

        let totp = fresh.totp(&id).await.unwrap().unwrap();
        assert!(totp.confirmed);
        assert_eq!(totp.last_step, Some(100));
        assert!(fresh.use_recovery_code(&id, &code(1, 1)).await.unwrap());
        assert_eq!(
            factors_of(&fresh, &id).await,
            (
                Some("key 1".to_string()),
                1,
                source.passkeys(&id).await.unwrap()
            ),
            "the counter, the times and the host travelled"
        );
    }

    #[tokio::test]
    async fn a_restore_replaces_a_carried_accounts_factors_and_clears_the_rest() {
        let source = furnished().await;
        let id = second_factors_for(&source, "admin", 1).await;
        let text = sealed(&source).await;
        let target = restored_onto_a_fresh_box(&text).await;
        target.clear_totp(&id).await.unwrap();
        let carried = target.passkeys(&id).await.unwrap().remove(0);
        target.remove_passkey(&id, &carried.id).await.unwrap();
        second_factors_for(&target, "admin", 2).await;
        let viewer = second_factors_for(&target, "viewer", 3).await;

        let bundle = Bundle::open(&text, &passphrase(), 1).expect("open");
        let mut tx = target.begin().await.unwrap();
        bundle
            .restore_platform(&target, &mut tx, &everything())
            .await
            .unwrap();
        tx.commit().await.unwrap();

        assert_eq!(
            factors_of(&target, &id).await,
            factors_of(&source, &id).await,
            "the same account, its factors the bundle's"
        );
        assert!(!target.use_recovery_code(&id, &code(2, 0)).await.unwrap());
        assert_eq!(factors_of(&target, &viewer).await, (None, 0, Vec::new()));
    }

    #[tokio::test]
    async fn two_passkeys_sharing_an_id_or_a_credential_are_a_hand_edited_file() {
        let source = furnished().await;
        second_factors_for(&source, "admin", 1).await;
        second_factors_for(&source, "viewer", 2).await;
        let body = Snapshot::capture(&source).await.unwrap().body;
        let [admin, viewer] = [0, 1].map(|n| body.users[n].passkeys[0].clone());
        assert!(body.check().is_ok());

        for twin in [
            StoredPasskey {
                id: "another".to_string(),
                ..admin.clone()
            },
            StoredPasskey {
                id: admin.id.clone(),
                ..viewer
            },
        ] {
            let mut edited = body.clone();
            edited.users[1].passkeys = vec![twin];
            assert!(matches!(edited.check(), Err(BackupError::Malformed(_))));
        }
    }

    #[tokio::test]
    async fn two_accounts_sharing_an_id_are_a_hand_edited_file() {
        let mut body = Snapshot::capture(&furnished().await).await.unwrap().body;
        body.users[1].user.id = body.users[0].user.id.clone();
        assert!(matches!(body.check(), Err(BackupError::Malformed(_))));
    }

    #[tokio::test]
    async fn a_recovery_code_hash_that_is_not_one_is_a_hand_edited_file() {
        let source = furnished().await;
        second_factors_for(&source, "admin", 1).await;
        let body = Snapshot::capture(&source).await.unwrap().body;
        for bad in ["AA".repeat(32), "aa".repeat(31), "zz".repeat(32)] {
            let mut edited = body.clone();
            edited.users[0].recovery_codes.push(bad);
            assert!(matches!(edited.check(), Err(BackupError::Malformed(_))));
        }
    }

    #[tokio::test]
    async fn a_restore_is_one_transaction_with_the_products_own_writes() {
        let source = furnished().await;
        let text = sealed(&source).await;

        let target = Store::open_in_memory(None).await.expect("store");
        target
            .create_user("local", "$argon2id$v=19$fake$local", Role::Admin)
            .await
            .expect("create");

        let bundle = Bundle::open(&text, &passphrase(), 1).expect("open");
        let mut tx = target.begin().await.expect("begin");
        bundle
            .restore_platform(&target, &mut tx, &everything())
            .await
            .expect("restore");
        drop(tx); // the product's own write failed, so nothing commits

        let users = target.users().await.expect("users");
        assert_eq!(users.len(), 1);
        assert_eq!(users[0].username, "local");
    }

    #[tokio::test]
    async fn restoring_only_the_settings_leaves_this_boxs_accounts_and_pins_alone() {
        let text = sealed(&furnished().await).await;
        let target = restored_onto_a_used_box(
            &text,
            Chosen {
                settings: true,
                ..Default::default()
            },
        )
        .await;

        assert_eq!(
            target.setting("branding.app_name").await.unwrap(),
            Some("Widget Monitor".to_string()),
            "the chosen section is the bundle's"
        );
        assert_eq!(
            target.users().await.expect("users").len(),
            3,
            "the third account this box made is still here"
        );
        assert_eq!(
            target.trusted_certs().await.expect("pins").len(),
            2,
            "and so is the pin the bundle does not carry"
        );
    }

    #[tokio::test]
    async fn restoring_no_platform_section_writes_nothing() {
        let text = sealed(&furnished().await).await;
        let target = restored_onto_a_used_box(&text, Chosen::default()).await;
        assert_eq!(
            target.setting("branding.app_name").await.unwrap(),
            Some("Something Else".to_string())
        );
        assert_eq!(target.users().await.expect("users").len(), 3);
    }

    #[tokio::test]
    async fn restoring_the_accounts_alone_still_signs_everybody_out() {
        // The used box's cutoff is 1970, so a stamp is unmistakable.
        let text = sealed(&furnished().await).await;
        let target = restored_onto_a_used_box(
            &text,
            Chosen {
                accounts: true,
                ..Default::default()
            },
        )
        .await;
        let after = target
            .user_by_username("admin")
            .await
            .unwrap()
            .unwrap()
            .sessions_valid_from;
        assert!(
            after.timestamp() > 0,
            "stamped now, not left alone: {after}"
        );
        assert_eq!(
            target.users().await.expect("users").len(),
            2,
            "the accounts are the bundle's now"
        );
        assert_eq!(
            target.setting("branding.app_name").await.unwrap(),
            Some("Something Else".to_string()),
            "and the settings were left alone"
        );
    }

    #[tokio::test]
    async fn the_serving_pair_round_trips_beside_the_products_own_sections() {
        let source = furnished().await;
        let mut snapshot = naming(&source, "serving_certificate").await;

        snapshot
            .put("serving_certificate", &["the product's own rows"])
            .expect("a product's namespace is its own");

        let pair = ServingPair {
            cert_pem: "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n".to_string(),
            key_pem: Secret::new("-----BEGIN PRIVATE KEY-----\nMIIB\n-----END PRIVATE KEY-----\n"),
        };
        snapshot.put_serving_pair(pair.clone());
        let text = snapshot.seal(&passphrase(), &provenance()).expect("seal");

        let bundle = Bundle::open(&text, &passphrase(), 1).expect("open");
        assert!(
            bundle.header().contains.serving_certificate,
            "the header says the file holds one, so a restore screen can say so"
        );
        assert_eq!(
            bundle.header().contains.app["serving_certificate"],
            1,
            "and the product's own section of that name is untouched beside it"
        );

        let carried = bundle.serving_pair().expect("carried");
        assert_eq!(carried.cert_pem, pair.cert_pem);
        assert_eq!(carried.key_pem.expose(), pair.key_pem.expose());
    }

    #[tokio::test]
    async fn a_bundle_without_a_serving_pair_says_so_rather_than_erroring() {
        let text = sealed(&furnished().await).await;
        let bundle = Bundle::open(&text, &passphrase(), 1).expect("open");

        assert!(!bundle.header().contains.serving_certificate);
        assert!(bundle.serving_pair().is_none());
    }

    #[tokio::test]
    async fn the_counts_a_picker_shows_come_from_the_body_not_the_header() {
        let source = furnished().await;
        let mut envelope: serde_json::Value = serde_json::from_str(&sealed(&source).await).unwrap();
        envelope["header"]["contains"]["accounts"] = serde_json::json!(999);

        let bundle = Bundle::open(&envelope.to_string(), &passphrase(), 1).expect("open");
        assert_eq!(bundle.header().contains.accounts, 2);
    }

    #[tokio::test]
    async fn a_passphrase_too_short_to_protect_a_file_that_leaves_the_box_is_refused() {
        let store = Store::open_in_memory(None).await.expect("store");
        let snapshot = Snapshot::capture(&store).await.expect("capture");
        let short = Secret::new("a".repeat(MIN_PASSPHRASE_LEN - 1));

        assert!(matches!(
            snapshot.seal(&short, &provenance()),
            Err(BackupError::Passphrase(_))
        ));
    }
}
