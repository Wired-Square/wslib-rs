//! Its own binary, so no other test has installed a provider first.

use wslib_appliance_auth::{AuthError, Awaiting, PendingSignIns};

#[test]
fn a_sign_in_begun_with_no_provider_installed_is_an_error() {
    let begun = PendingSignIns::default().begin("u1", "$argon2id$v=19$the-hash", Awaiting::Code);
    assert!(matches!(begun, Err(AuthError::NoProvider)), "{begun:?}");
}
