//! What a client sends to create or change an account, one body per route.
//! Each but `EnabledChange` carries `proof`, the acting administrator's own.

use serde::{Deserialize, Serialize};
use wslib_secret::Secret;

use crate::Role;
use crate::totp::FactorProof;

/// Create an account, with a password somebody else chose.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts", ts(export))]
pub struct NewUser {
    pub username: String,
    #[cfg_attr(feature = "ts", ts(as = "String"))]
    pub password: Secret,
    pub role: Role,
    #[serde(default)]
    #[cfg_attr(feature = "ts", ts(as = "Option<FactorProof>", optional))]
    pub proof: FactorProof,
}

/// Move an account along the ladder.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts", ts(export))]
pub struct RoleChange {
    pub role: Role,
    #[serde(default)]
    #[cfg_attr(feature = "ts", ts(as = "Option<FactorProof>", optional))]
    pub proof: FactorProof,
}

/// Turn an account off without deleting it, or back on.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts", ts(export))]
pub struct EnabledChange {
    pub enabled: bool,
}

/// Reset somebody else's password, and clear their second factors; never the caller's.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts", ts(export))]
pub struct PasswordReset {
    #[cfg_attr(feature = "ts", ts(as = "String"))]
    pub password: Secret,
    #[serde(default)]
    #[cfg_attr(feature = "ts", ts(as = "Option<FactorProof>", optional))]
    pub proof: FactorProof,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn neither_body_that_carries_a_password_can_print_one() {
        let rendered = format!(
            "{:?} {:?}",
            NewUser {
                username: "operator".into(),
                password: "correct horse battery".into(),
                role: Role::Operator,
                proof: FactorProof::default(),
            },
            PasswordReset {
                password: "a much longer passphrase".into(),
                proof: FactorProof {
                    password: Some("correct horse staple".into()),
                    ..FactorProof::default()
                },
            }
        );
        assert!(rendered.contains("operator"), "{rendered}");
        assert!(rendered.contains("Operator"), "{rendered}");
        assert!(!rendered.contains("horse"), "leaked: {rendered}");
        assert!(!rendered.contains("passphrase"), "leaked: {rendered}");
    }

    #[test]
    fn a_client_can_write_what_the_daemon_reads() {
        let json =
            r#"{"username":"operator","password":"correct horse battery","role":"operator"}"#;
        let body: NewUser = serde_json::from_str(json).expect("the wire form");
        assert_eq!(body.role, Role::Operator);
        let written = serde_json::to_string(&body).unwrap();
        assert!(written.starts_with(json.trim_end_matches('}')), "{written}");
    }
}
