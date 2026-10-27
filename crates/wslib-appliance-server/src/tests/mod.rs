//! `wslib-appliance-core`'s behaviour that only an assembled appliance can
//! show, driven through the harness.

mod audit;
mod chassis;
mod extract;
mod hooks;
mod ingress;
#[cfg(unix)]
mod proxied;
mod reauth;
mod routes;

pub(crate) fn admin() -> wslib_appliance_types::console::ConsoleIdentity {
    crate::testing::console("admin", wslib_appliance_types::Role::Admin)
}

pub(crate) const WITHIN: std::time::Duration = std::time::Duration::from_secs(5);
