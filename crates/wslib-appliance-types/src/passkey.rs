//! Passkeys: the WebAuthn ceremony's options and credentials in the JSON forms
//! `PublicKeyCredential` parses and writes, and an account's passkeys as
//! listed, without their credential IDs.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// The longest a passkey's name may be.
pub const MAX_PASSKEY_NAME_LEN: usize = 64;

pub use wslib_auth_passkey::{
    AssertionCredential, AssertionResponse, AttestationResponse, AuthenticatorSelection,
    CreationOptions, CredentialDescriptor, CredentialParameters, RegistrationCredential,
    RelyingPartyEntity, RequestOptions, UserEntity,
};

/// A new passkey and the name to keep it under: `POST /api/session/passkeys`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts", ts(export))]
pub struct PasskeyRegistration {
    pub name: String,
    pub credential: RegistrationCredential,
}

/// `PUT /api/session/passkeys/{id}/name`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts", ts(export))]
pub struct PasskeyRename {
    pub name: String,
}

/// One of an account's passkeys.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts", ts(export))]
pub struct PasskeyView {
    pub id: String,
    pub name: String,
    /// The host it was made on, the only one it signs in on.
    pub host: String,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
}

/// How many passkeys were made on one host, and so sign in only there.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts", ts(export))]
pub struct PasskeyHost {
    pub host: String,
    pub passkeys: u32,
}

#[cfg(all(test, feature = "ts"))]
mod tests {
    use ts_rs::TS;

    #[test]
    fn the_ceremony_options_nothing_here_names_are_exported_too() {
        super::CreationOptions::export_all().expect("export");
        super::RequestOptions::export_all().expect("export");
    }
}
