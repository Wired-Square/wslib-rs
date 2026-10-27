//! The `/api` routes of a backend that signs its own callers in. Every route
//! names its access; the public ones (`POST`/`DELETE /api/session`, `GET
//! /api/onboarding`, and core's sign-in steps) say why at the handler.

use axum::Router;
use wslib_appliance_core::Mount;

pub(crate) mod onboarding;
pub(crate) mod session;
pub(crate) mod users;

/// The routes for both listeners, and those for the socket alone.
pub(crate) fn api(users: bool) -> (Vec<Mount>, Vec<Mount>) {
    let routes = Router::new()
        .merge(onboarding::routes())
        .merge(session::routes());
    match users {
        true => (vec![Mount::from(routes.merge(users::routes()))], Vec::new()),
        false => (
            vec![Mount::from(routes)],
            vec![Mount::from(users::routes())],
        ),
    }
}
