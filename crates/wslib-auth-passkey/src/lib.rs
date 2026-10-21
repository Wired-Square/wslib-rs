//! Passkeys: the WebAuthn registration (§7.1) and authentication (§7.2)
//! ceremonies. `none` attestation only; ES256 and EdDSA keys; the user
//! verified (a PIN or a biometric) every time. The caller keeps the passkeys.
//!
//! **The RP ID is the host the browser reached the server by**, so a passkey
//! signs in on the name it was made on and no other. WebAuthn will not run on
//! an IP address, which [`RelyingParty::for_host`] refuses, nor behind a
//! certificate the browser does not trust, which the server cannot see: the
//! browser refuses that itself, with a `SecurityError`.
//!
//! A refusal names the check that failed, for the log; show users a fixed
//! message.
//!
//! Without the default `ceremonies` feature only the JSON types are left, on
//! serde alone, for a crate that carries the types without the crypto.

#[cfg(feature = "ceremonies")]
pub use ceremonies::{
    Assertion, Ceremonies, HostError, NewPasskey, Refused, RelyingParty, StoredPasskey,
    claimed_user_id, sign_count_moved,
};
pub use json::{
    AssertionCredential, AssertionResponse, AttestationResponse, AuthenticatorSelection,
    CreationOptions, CredentialDescriptor, CredentialParameters, RegistrationCredential,
    RelyingPartyEntity, RequestOptions, UserEntity,
};

#[cfg(feature = "ceremonies")]
mod cbor;
#[cfg(feature = "ceremonies")]
mod ceremonies;
#[cfg(feature = "ceremonies")]
mod challenges;
#[cfg(feature = "ceremonies")]
mod cose;
#[cfg(feature = "ceremonies")]
mod data;
mod json;
#[cfg(all(feature = "ceremonies", any(test, feature = "testing")))]
pub mod testing;
#[cfg(all(test, feature = "ceremonies"))]
mod tests;
