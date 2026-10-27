//! What the daemon has said since it started: the ring, then a `log` event per record.
//!
//! **`SessionAdmin`, unlike the audit log's `Admin`**: the scrollback is the
//! journal group's to read, not the control socket's. A backend that grants it to
//! its socket's group on purpose mounts it at [`Admin`].

use std::convert::Infallible;
use std::sync::Arc;

use axum::extract::{FromRequestParts, State};
use axum::response::sse::{Event, Sse};
use axum::routing::get;
use axum::{Json, Router};
use futures_util::Stream;
use wslib_telemetry::{LogRecord, LogSnapshot};

use crate::extract::{Admin, SessionAdmin};
use crate::feed::{feed, sse};
use crate::state::ApplianceState;

#[derive(Clone, Copy, Debug)]
pub enum LogsRung {
    SessionAdmin,
    Admin,
}

pub(crate) fn routes(rung: LogsRung) -> Router<ApplianceState> {
    match rung {
        LogsRung::SessionAdmin => at::<SessionAdmin>(),
        LogsRung::Admin => at::<Admin>(),
    }
}

fn at<R>() -> Router<ApplianceState>
where
    R: FromRequestParts<ApplianceState> + Send + 'static,
{
    Router::new()
        .route("/logs", get(snapshot::<R>))
        .route("/logs/events", get(events::<R>))
}

/// Unfiltered: the browser filters.
async fn snapshot<R>(_: R, State(app): State<ApplianceState>) -> Json<LogSnapshot> {
    Json(app.logs.ring().snapshot())
}

async fn events<R>(
    _: R,
    State(app): State<ApplianceState>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    sse(
        feed::<_, Arc<LogRecord>>(app.logs.ring().subscribe(), "log"),
        app.shutdown(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::probe::Probe;
    use crate::testing::{captured, first_frame};
    use axum::http::StatusCode;
    use wslib_appliance_types::Role;

    #[tokio::test]
    async fn mounted_at_admin_it_is_an_admin_sockets_and_nobody_elses() {
        let probe = Probe::callerless(LogsRung::Admin).await;
        let token = probe.admin_token().await;
        for path in ["/api/logs", "/api/logs/events"] {
            for ceiling in Role::LADDER {
                let expected = if ceiling.allows(Role::Admin) {
                    StatusCode::OK
                } else {
                    StatusCode::FORBIDDEN
                };
                for response in probe.local(ceiling, path).await {
                    assert_eq!(response.status(), expected, "{ceiling} socket, {path}");
                }
            }
            assert_eq!(
                probe.https(path, Some(&token)).await.status(),
                StatusCode::UNAUTHORIZED,
                "{path}"
            );
        }
    }

    #[tokio::test]
    async fn mounted_at_session_admin_it_is_refused_to_every_socket() {
        let probe = Probe::new().await;
        for ceiling in Role::LADDER {
            for response in probe.local(ceiling, "/api/logs").await {
                assert_eq!(response.status(), StatusCode::FORBIDDEN, "{ceiling} socket");
            }
        }
    }

    /// 600 sent into a feed of 512: the gap in `seq` tells the client.
    #[tokio::test]
    async fn a_client_that_fell_behind_resumes_at_the_oldest_record_still_held() {
        let logs = crate::logs(&[]);
        let rx = logs.ring().subscribe();
        captured(&logs, || {
            for i in 0..600 {
                tracing::info!(i, "tick");
            }
        });

        let frame = first_frame(Sse::new(feed::<_, Arc<LogRecord>>(rx, "log"))).await;
        assert!(
            frame.starts_with("event: log\ndata: {\"seq\":89,"),
            "{frame}"
        );
    }
}
