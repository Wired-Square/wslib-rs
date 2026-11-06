//! Backups on a backend with accounts that serves its own sign-in, such as
//! `wslib-appliance-https`'s.

use std::path::Path;

use axum::Router;
use wslib_appliance_core::{ApplianceState, CancellationToken, Mount};

use crate::Sections;
use crate::routes::Engine;

/// The backup routes and the schedule on a backend whose callers are its own
/// accounts, over a product's [`Sections`].
///
/// Every route of [`routes()`](Self::routes) but the first-run inspect and
/// restore is [`SessionAdmin`](wslib_appliance_core::SessionAdmin), and a
/// take, a restore and a new schedule passphrase want the caller's own proof
/// again, as `prove_caller` asks it. A bundle carries the accounts, the
/// settings and the serving pair beside the application half, and a box with
/// no accounts may restore one in place of making its first.
#[derive(Debug, Clone)]
pub struct SessionBackups<S>(Engine<S, ()>);

impl<S: Sections> SessionBackups<S> {
    /// `name` is the product's system name, which the files are called by, and
    /// `version` its build's; the files go under `<state_dir>/backups`.
    pub fn new(name: &str, version: &str, state_dir: &Path, sections: S) -> Self {
        Self(Engine::session(name, version, state_dir, (), sections))
    }

    /// Every route, the first-run inspect and restore among them, for `Server::api`.
    pub fn routes(&self) -> Mount {
        self.0.routes(Router::new())
    }

    /// Take a scheduled backup whenever one is due, until `stop` fires; until
    /// it has started, the schedule stays off.
    pub async fn run_schedule(self, app: ApplianceState, stop: CancellationToken) {
        self.0.run_schedule(app, stop).await;
    }
}

#[cfg(test)]
mod tests {
    use axum::http::StatusCode;
    use serde_json::json;
    use wslib_appliance_https::testing::Harness;
    use wslib_appliance_server::testing::body_text;
    use wslib_appliance_types::Role;

    use super::*;
    use crate::routes::tests::PASSPHRASE;

    async fn served() -> Harness {
        let builder = Harness::builder();
        let backups = SessionBackups::new("widget-monitor", "0.1.0-test", builder.dir(), ());
        builder.api(backups.routes()).build().await
    }

    #[tokio::test]
    async fn only_a_signed_in_admin_with_the_password_takes_a_backup() {
        let app = served().await;
        let take = |password: &str| {
            app.post("/api/backup")
                .json(json!({ "passphrase": PASSPHRASE, "password": password }))
        };
        let operator = app.signed_in("operator", Role::Operator).await;
        let admin = app.admin("admin").await;

        let nobody = take(Harness::PASSWORD).send().await;
        assert_eq!(nobody.status(), StatusCode::UNAUTHORIZED);
        let operator = take(Harness::PASSWORD).cookie(&operator).send().await;
        assert_eq!(operator.status(), StatusCode::FORBIDDEN);
        let control_socket = take(Harness::PASSWORD).local().send().await;
        assert_eq!(control_socket.status(), StatusCode::FORBIDDEN);
        let wrong = take("not it").cookie(&admin).send().await;
        assert_eq!(wrong.status(), StatusCode::FORBIDDEN);

        let taken = take(Harness::PASSWORD).cookie(&admin).send().await;
        assert_eq!(taken.status(), StatusCode::OK);
        assert!(body_text(taken).await.contains("\"header\""));
    }

    #[tokio::test]
    async fn the_first_run_inspect_and_restore_are_served() {
        let app = served().await;
        for path in ["/api/onboarding/inspect", "/api/onboarding/restore"] {
            let refused = app
                .post(path)
                .json(json!({ "passphrase": PASSPHRASE, "bundle": "not a bundle" }))
                .send()
                .await;
            assert_ne!(refused.status(), StatusCode::NOT_FOUND, "{path}");
        }
    }
}
