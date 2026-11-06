//! Backups on a backend with no accounts, such as `wslib-appliance-service`'s, and
//! the application half a console captures and restores over an app's hooks,
//! or its caller takes and restores through the proxied routes.

use std::path::Path;

use axum::Router;
use wslib_appliance_core::backend::local_mount;
use wslib_appliance_core::{ApplianceState, BackupHooks, CancellationToken, LocalMount, Mount};

use crate::Sections;
use crate::routes::Engine;

/// The backup routes and the schedule on a backend with no accounts, and the
/// hooks and the proxied routes behind a console, over a product's [`Sections`].
///
/// Every route of [`routes()`](Self::routes) is [`Admin`](wslib_appliance_core::Admin)
/// over a control endpoint, with no password asked; a backend that resolves
/// callers to accounts refuses to build with them. A bundle carries, and a
/// restore applies, only the application half: the product's sections and the
/// outbound trust. There is no first-run restore and no factory reset.
///
/// The routes are a [`LocalMount`], which an appliance cannot mount:
///
/// ```compile_fail
/// # fn on(server: wslib_appliance_server::Server, backups: wslib_appliance_backup::LocalBackups<()>) {
/// server.api(backups.routes());
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct LocalBackups<S>(Engine<S, ()>);

impl<S: Sections> LocalBackups<S> {
    /// `name` is the product's system name, which the files are called by, and
    /// `version` its build's; the files go under `<state_dir>/backups`.
    pub fn new(name: &str, version: &str, state_dir: &Path, sections: S) -> Self {
        Self(Engine::local(name, version, state_dir, sections))
    }

    /// Every route, for `Service::local_api`.
    pub fn routes(&self) -> LocalMount {
        local_mount(self.0.routes(Router::new()))
    }

    /// The application half, unsealed, for `Server::backup_hooks`.
    pub fn hooks(&self) -> BackupHooks {
        crate::hooks::mount(self.0.clone())
    }

    /// The application half for `Server::api` behind a console, at
    /// [`SessionAdmin`](wslib_appliance_core::SessionAdmin) with the console's
    /// `reauth=` as the proof; one take or restore runs at a time, counting the
    /// hooks', and another is refused.
    pub fn proxied_routes(&self) -> Mount {
        self.0.proxied_routes()
    }

    /// Take a scheduled backup whenever one is due, until `stop` fires; until
    /// it has started, the schedule stays off.
    pub async fn run_schedule(self, app: ApplianceState, stop: CancellationToken) {
        self.0.run_schedule(app, stop).await;
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use axum::http::StatusCode;
    use serde_json::json;
    use tempfile::TempDir;
    use wslib_appliance_core::backend::{Callers, LogsRung, no_tls};
    use wslib_appliance_core::testing::assert_sentences;
    use wslib_appliance_core::{
        AboveAdmin, ApiError, Backend, Built, Chassis, ControlRouter, Principal, ResolveCaller,
        ServeError,
    };
    use wslib_appliance_core::{Logs, logs};
    use wslib_appliance_server::testing::{Req, body_json, body_text};
    use wslib_appliance_store::Store;
    use wslib_appliance_types::{Branding, Role, TrustedCa};

    use super::*;
    use crate::routes::tests::{
        ACCOUNT, Named, PASSPHRASE, PASSWORD, Reporting, account, backups, over_accounts, warnings,
    };

    /// `wslib-appliance-service`'s shape: no resolver and no pair.
    struct Service<S> {
        https: Router,
        control: ControlRouter,
        logs: Logs,
        state: ApplianceState,
        backups: LocalBackups<S>,
        dir: TempDir,
    }

    async fn service<S: Sections>(sections: S) -> Service<S> {
        let dir = TempDir::new().expect("a directory");
        let store = Store::open_in_memory(None).await.expect("store");
        let backups = LocalBackups::new("widget-monitor", "0.1.0-test", dir.path(), sections);
        let logs = logs(&[]);
        let built = chassis(store, &backups, &logs, Callers::nobody())
            .await
            .expect("the chassis builds");
        tokio::task::yield_now().await;
        Service {
            https: built.https,
            control: built.control,
            logs,
            state: built.state,
            backups,
            dir,
        }
    }

    /// The chassis `serve_local` builds, telling callers apart by `callers`.
    async fn chassis<S: Sections>(
        store: Store,
        backups: &LocalBackups<S>,
        logs: &Logs,
        callers: Callers,
    ) -> Result<Built, ServeError> {
        let schedule = backups.clone();
        Chassis::new(store, Branding::unbranded(), "0.0.0", logs.clone())
            .local_api(backups.routes())
            .task(move |state, stop| schedule.run_schedule(state, stop))
            .build(Backend {
                callers,
                logs: LogsRung::Admin,
                tls: Arc::new(no_tls()),
                listening: None,
                onboarding: false,
                names_the_box: false,
                above_admin: AboveAdmin::Absent,
                routes: Vec::new(),
                control_routes: Vec::new(),
            })
            .await
    }

    impl<S> Service<S> {
        /// Over an Admin-ceiling endpoint.
        fn admin(&self, method: &'static str, path: &str) -> Req {
            Req::new(self.https.clone(), method, path)
                .harnessed(self.control.clone(), self.logs.clone())
                .local()
        }

        fn store(&self) -> &Store {
            &self.state.store
        }
    }

    fn authority() -> TrustedCa {
        let at = wslib_appliance_store::now();
        TrustedCa {
            sha256: "bb22".to_string(),
            subject: "CN=Widget Root".to_string(),
            not_before: at,
            not_after: at,
            added_at: at,
            added_by: "admin".to_string(),
            pem: "-----BEGIN CERTIFICATE-----\nbb22\n-----END CERTIFICATE-----\n".to_string(),
        }
    }

    fn times_left_out(report: &serde_json::Value) -> usize {
        warnings(report)
            .iter()
            .filter(|w| w.contains("left out here"))
            .count()
    }

    async fn take(local: &Service<Reporting>) -> String {
        let taken = local
            .admin("POST", "/api/backup")
            .json(json!({ "passphrase": PASSPHRASE }))
            .send()
            .await;
        assert_eq!(taken.status(), StatusCode::OK);
        body_text(taken).await
    }

    #[tokio::test]
    async fn an_admin_endpoint_takes_and_restores_the_application_half_with_no_password() {
        let local = service(Reporting::default()).await;
        local.store().trust_ca(&authority()).await.unwrap();
        local
            .store()
            .set_setting("branding.app_name", "Desktop")
            .await
            .unwrap();
        let bundle = take(&local).await;
        let file: serde_json::Value = serde_json::from_str(&bundle).unwrap();
        assert_eq!(
            file["header"]["contains"],
            json!({
                "accounts": 0, "settings": 0, "trusted_certs": 0, "trusted_cas": 1,
                "serving_certificate": false, "ssh_keys": 0, "host": false,
                "app": { "gauges": 1 }
            }),
            "the application half and nothing else"
        );

        local.store().distrust_ca("bb22").await.unwrap();
        let restored = local
            .admin("POST", "/api/backup/restore")
            .json(json!({
                "passphrase": PASSPHRASE, "bundle": bundle,
                "sections": { "trusted_cas": true, "app": ["gauges"] }
            }))
            .send()
            .await;
        assert_eq!(restored.status(), StatusCode::OK);
        let report = body_json(restored).await;
        assert_eq!(report["applied"]["trusted_cas"], true);
        assert_eq!(report["applied"]["app"], json!(["gauges"]));
        assert_eq!(times_left_out(&report), 0, "{report}");
        assert_eq!(local.store().trusted_cas().await.unwrap().len(), 1);
        let row = &local.store().audit(10, None).await.unwrap().items[0];
        assert_eq!(
            (row.actor.as_str(), row.message.as_str()),
            ("control-socket", "restored a backup")
        );
    }

    #[tokio::test]
    async fn a_request_with_no_local_authority_is_refused_and_there_is_no_reset_or_first_run_restore()
     {
        let local = service(()).await;
        for (method, path) in [
            ("POST", "/api/backup"),
            ("POST", "/api/backup/inspect"),
            ("POST", "/api/backup/restore"),
            ("GET", "/api/backup/schedule"),
            ("PUT", "/api/backup/schedule"),
            ("DELETE", "/api/backup/schedule/passphrase"),
            ("GET", "/api/backup/files/x.json"),
            ("DELETE", "/api/backup/files/x.json"),
        ] {
            let response = Req::new(local.https.clone(), method, path)
                .json(json!({}))
                .send()
                .await;
            assert_eq!(
                response.status(),
                StatusCode::UNAUTHORIZED,
                "{method} {path}"
            );
        }
        for path in [
            "/api/onboarding/inspect",
            "/api/onboarding/restore",
            "/api/factory-reset",
        ] {
            let response = local.admin("POST", path).json(json!({})).send().await;
            assert_eq!(response.status(), StatusCode::NOT_FOUND, "{path}");
        }
    }

    struct Nobody;

    impl ResolveCaller for Nobody {
        async fn resolve(
            &self,
            _: &axum::http::request::Parts,
        ) -> Result<Option<Principal>, ApiError> {
            Ok(None)
        }
    }

    #[tokio::test]
    async fn a_backend_with_a_resolver_refuses_to_build_with_these_routes() {
        let dir = TempDir::new().expect("a directory");
        let backups = LocalBackups::new("widget-monitor", "0.1.0-test", dir.path(), ());
        let store = Store::open_in_memory(None).await.expect("store");
        let refused = chassis(store, &backups, &logs(&[]), Callers::resolved_by(Nobody)).await;
        assert!(
            matches!(refused, Err(ServeError::LocalRoutesWithResolver)),
            "an account resolved over the network would reach them"
        );
    }

    #[tokio::test]
    async fn an_appliances_bundle_restores_only_its_application_half_and_says_so() {
        let builder = over_accounts().await;
        let appliance = backups(&builder, Reporting::default());
        let pi = builder.api(appliance.routes(Router::new())).build().await;
        let admin = account(&pi, "admin", Role::Admin).await;
        pi.store().trust_ca(&authority()).await.unwrap();
        pi.store()
            .set_setting("branding.app_name", "Pi")
            .await
            .unwrap();
        let bundle = crate::routes::tests::take(&pi, &admin).await;
        let carried: serde_json::Value = serde_json::from_str(&bundle).unwrap();
        assert_eq!(
            carried["header"]["contains"]["serving_certificate"], true,
            "{carried}"
        );

        let local = service(Reporting::default()).await;
        local
            .store()
            .set_setting("branding.app_name", "Desktop")
            .await
            .unwrap();
        local
            .store()
            .create_user("viewer", "not a hash", Role::Viewer)
            .await
            .unwrap();
        let accounts = local.store().users().await.unwrap();

        let seen = body_json(
            local
                .admin("POST", "/api/backup/inspect")
                .json(json!({ "passphrase": PASSPHRASE, "bundle": bundle }))
                .send()
                .await,
        )
        .await;
        assert_eq!(times_left_out(&seen), 1, "{seen}");
        assert!(
            !seen["warnings"]
                .to_string()
                .contains("no enabled administrator"),
            "{seen}"
        );
        assert_sentences(warnings(&seen));

        let restored = local
            .admin("POST", "/api/backup/restore")
            .json(json!({
                "passphrase": PASSPHRASE, "bundle": bundle,
                "sections": {
                    "accounts": true, "settings": true, "trusted_cas": true,
                    "serving_certificate": true, "ssh_keys": true, "host": true,
                    "app": ["gauges"]
                }
            }))
            .send()
            .await;
        assert_eq!(restored.status(), StatusCode::OK);
        let report = body_json(restored).await;
        assert_eq!(
            report["applied"],
            json!({
                "accounts": false, "settings": false, "trusted_certs": false,
                "trusted_cas": true, "serving_certificate": false, "ssh_keys": false,
                "host": false, "app": ["gauges"]
            })
        );
        assert_eq!(report["signed_out"], false);
        assert_eq!(times_left_out(&report), 1, "{report}");
        assert_sentences(warnings(&report));
        assert_eq!(local.store().users().await.unwrap(), accounts);
        assert_eq!(
            local
                .store()
                .setting("branding.app_name")
                .await
                .unwrap()
                .as_deref(),
            Some("Desktop")
        );
        assert_eq!(local.store().trusted_cas().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn another_products_bundle_is_said_not_to_restore_here() {
        let builder = over_accounts().await;
        let appliance = backups(&builder, Named(&["dials"], &["dials"]));
        let pi = builder.api(appliance.routes(Router::new())).build().await;
        let admin = account(&pi, "admin", Role::Admin).await;
        let bundle = crate::routes::tests::take(&pi, &admin).await;

        let local = service(Reporting::default()).await;
        let seen = body_json(
            local
                .admin("POST", "/api/backup/inspect")
                .json(json!({ "passphrase": PASSPHRASE, "bundle": bundle }))
                .send()
                .await,
        )
        .await;
        assert!(
            warnings(&seen).contains(
                &"This backup carries another app's sections and none of this one's, so it \
                  will not restore here."
            ),
            "{seen}"
        );
    }

    #[tokio::test]
    async fn a_bundle_a_local_backend_took_restores_on_an_appliance() {
        let local = service(Reporting::default()).await;
        local.store().trust_ca(&authority()).await.unwrap();
        let bundle = take(&local).await;

        let builder = over_accounts().await;
        let appliance = backups(&builder, Reporting::default());
        let pi = builder.api(appliance.routes(Router::new())).build().await;
        let admin = account(&pi, "admin", Role::Admin).await;
        let restored = pi
            .post("/api/backup/restore")
            .header(ACCOUNT, &admin)
            .json(json!({
                "passphrase": PASSPHRASE, "bundle": bundle, "password": PASSWORD,
                "sections": { "trusted_cas": true, "app": ["gauges"] }
            }))
            .send()
            .await;
        assert_eq!(restored.status(), StatusCode::OK);
        let report = body_json(restored).await;
        assert_eq!(report["applied"]["trusted_cas"], true);
        assert_eq!(report["applied"]["app"], json!(["gauges"]));
        assert_eq!(pi.store().trusted_cas().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn a_bundle_with_no_accounts_at_first_run_is_sent_to_settings_after_the_first_account() {
        let local = service(Reporting::default()).await;
        let bundle = take(&local).await;

        let builder = over_accounts().await;
        let appliance = backups(&builder, Reporting::default());
        let pi = builder.api(appliance.routes(Router::new())).build().await;
        let refused = pi
            .post("/api/onboarding/restore")
            .json(json!({ "passphrase": PASSPHRASE, "bundle": bundle }))
            .send()
            .await;
        assert_eq!(refused.status(), StatusCode::CONFLICT);
        let why = body_json(refused).await["error"].to_string();
        assert!(
            why.contains("make the first account") && why.contains("from Settings"),
            "{why}"
        );
    }

    #[tokio::test]
    async fn the_schedule_takes_its_passphrase_with_no_password_and_writes_into_the_state_directory()
     {
        let local = service(()).await;
        let switched = local
            .admin("PUT", "/api/backup/schedule")
            .json(json!({
                "schedule": { "enabled": true, "every_hours": 1, "keep": 2 },
                "passphrase": PASSPHRASE
            }))
            .send()
            .await;
        assert_eq!(switched.status(), StatusCode::OK);

        local.backups.0.check(&local.state).await.expect("check");
        let written: Vec<_> = std::fs::read_dir(local.dir.path().join("backups"))
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .collect();
        assert_eq!(written.len(), 1, "{written:?}");
        let view = body_json(local.admin("GET", "/api/backup/schedule").send().await).await;
        assert_eq!(view["state"]["file"], written[0].as_str());
        let sealed = local
            .admin("GET", &format!("/api/backup/files/{}", written[0]))
            .send()
            .await;
        let opened = crate::Bundle::open(
            &body_text(sealed).await,
            &wslib_secret::Secret::new(PASSPHRASE),
            0,
        )
        .unwrap();
        assert_eq!(opened.header().contains.settings, 0);
    }
}
