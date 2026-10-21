//! The options a ceremony begins with and the credential the browser answers
//! with, in the JSON forms `PublicKeyCredential`'s `parseCreationOptionsFromJSON`,
//! `parseRequestOptionsFromJSON` and `toJSON` use, every byte string base64url.

use serde::{Deserialize, Serialize};

/// What `navigator.credentials.create()` is given to make a passkey.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub struct CreationOptions {
    pub challenge: String,
    pub rp: RelyingPartyEntity,
    pub user: UserEntity,
    pub pub_key_cred_params: Vec<CredentialParameters>,
    /// Milliseconds.
    pub timeout: u32,
    pub exclude_credentials: Vec<CredentialDescriptor>,
    pub authenticator_selection: AuthenticatorSelection,
    pub attestation: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub struct RelyingPartyEntity {
    /// The host the passkey is bound to, the only one it signs in on.
    pub id: String,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub struct UserEntity {
    pub id: String,
    pub name: String,
    pub display_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub struct CredentialParameters {
    #[serde(rename = "type")]
    pub kind: String,
    /// A COSE algorithm: -7 for ES256, -8 for EdDSA.
    pub alg: i32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub struct CredentialDescriptor {
    #[serde(rename = "type")]
    pub kind: String,
    pub id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub struct AuthenticatorSelection {
    pub resident_key: String,
    pub require_resident_key: bool,
    pub user_verification: String,
}

/// What `navigator.credentials.get()` is given to sign in or to prove the
/// account again; `allowCredentials` is empty for a sign-in, where the passkey
/// names its account.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub struct RequestOptions {
    pub challenge: String,
    pub rp_id: String,
    /// Milliseconds.
    pub timeout: u32,
    pub allow_credentials: Vec<CredentialDescriptor>,
    pub user_verification: String,
}

/// The new credential, as its `toJSON()` serialises it.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub struct RegistrationCredential {
    pub id: String,
    pub raw_id: String,
    #[serde(rename = "type")]
    pub kind: String,
    pub response: AttestationResponse,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub struct AttestationResponse {
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: String,
    pub attestation_object: String,
}

/// A passkey's answer to a challenge, as its `toJSON()` serialises it.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub struct AssertionCredential {
    pub id: String,
    pub raw_id: String,
    #[serde(rename = "type")]
    pub kind: String,
    pub response: AssertionResponse,
}

/// Both credentials print their type alone: every other field carries, or
/// encodes, the credential's id.
macro_rules! debug_as_kind {
    ($($credential:ty),*) => {$(
        impl std::fmt::Debug for $credential {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.debug_struct(stringify!($credential))
                    .field("kind", &self.kind)
                    .finish_non_exhaustive()
            }
        }
    )*};
}

debug_as_kind!(RegistrationCredential, AssertionCredential);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub struct AssertionResponse {
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: String,
    pub authenticator_data: String,
    pub signature: String,
    /// The account's id as the passkey holds it; required for a sign-in.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts", ts(optional))]
    pub user_handle: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_browsers_json_reads_with_its_own_spelling_and_extra_fields() {
        let assertion: AssertionCredential = serde_json::from_str(
            r#"{"id":"AQ","rawId":"AQ","type":"public-key","authenticatorAttachment":"platform",
                "clientExtensionResults":{},
                "response":{"clientDataJSON":"e30","authenticatorData":"AA","signature":"AA",
                            "userHandle":null}}"#,
        )
        .expect("parses");
        assert_eq!(assertion.response.user_handle, None);
        assert_eq!(assertion.response.client_data_json, "e30");
        let written = serde_json::to_string(&assertion).unwrap();
        assert!(
            !written.contains("userHandle"),
            "omitted, as toJSON() does: {written}"
        );

        let registration: RegistrationCredential = serde_json::from_str(
            r#"{"id":"AQ","rawId":"AQ","type":"public-key","clientExtensionResults":{},
                "response":{"clientDataJSON":"e30","attestationObject":"oA","transports":["internal"]}}"#,
        )
        .expect("parses");
        assert_eq!(registration.response.attestation_object, "oA");
    }

    #[test]
    fn a_credential_prints_no_part_that_carries_its_id() {
        let assertion = AssertionCredential {
            id: "Y3JlZGVudGlhbA".into(),
            raw_id: "Y3JlZGVudGlhbA".into(),
            kind: "public-key".into(),
            response: AssertionResponse {
                client_data_json: "e30".into(),
                authenticator_data: "AA".into(),
                signature: "c2lnbmF0dXJl".into(),
                user_handle: Some("dXNlcg".into()),
            },
        };
        let registration = RegistrationCredential {
            id: "Y3JlZGVudGlhbA".into(),
            raw_id: "Y3JlZGVudGlhbA".into(),
            kind: "public-key".into(),
            response: AttestationResponse {
                client_data_json: "e30".into(),
                attestation_object: "b2JqZWN0".into(),
            },
        };
        let rendered = format!("{assertion:?} {registration:?}");
        assert!(rendered.contains("public-key"), "{rendered}");
        for part in ["Y3JlZGVudGlhbA", "c2lnbmF0dXJl", "dXNlcg", "b2JqZWN0"] {
            assert!(!rendered.contains(part), "leaked: {rendered}");
        }
    }

    #[test]
    fn options_are_written_in_the_browsers_spelling() {
        let options = RequestOptions {
            challenge: "AA".into(),
            rp_id: "box.local".into(),
            timeout: 300_000,
            allow_credentials: vec![CredentialDescriptor {
                kind: "public-key".into(),
                id: "AQ".into(),
            }],
            user_verification: "required".into(),
        };
        assert_eq!(
            serde_json::to_string(&options).unwrap(),
            r#"{"challenge":"AA","rpId":"box.local","timeout":300000,"allowCredentials":[{"type":"public-key","id":"AQ"}],"userVerification":"required"}"#
        );
    }
}
