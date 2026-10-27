//! Who the caller is, and what a client sends about its own credential. Every
//! password or code is a [`Secret`], and no request body carries an account id.

use serde::{Deserialize, Serialize};
use wslib_secret::Secret;

use crate::passkey::AssertionCredential;
use crate::totp::FactorProof;
use crate::{Role, User};

/// What `GET /api/session` answers; only an account has `enabled`, and only a
/// local caller `local`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts", ts(export))]
#[serde(untagged)]
#[non_exhaustive]
pub enum Caller {
    Account(User),
    Local(LocalIdentity),
    /// One of the console's accounts, as its `Appliance-Identity` header names
    /// it; `role` is the one that applies in this app.
    Console {
        /// The console's permanent id for the account.
        id: String,
        username: String,
        role: Role,
    },
}

/// A control endpoint's caller: nobody's account, holding the endpoint's ceiling.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts", ts(export))]
#[non_exhaustive]
pub struct LocalIdentity {
    /// The audit actor: `control-socket:` and the account that connected, by name,
    /// `uid=<n>`, `sid=<SID>,non-ascii-name=<name>` or `sid=<SID>`, or
    /// `control-socket` when the peer's credentials were unavailable.
    pub username: String,
    pub role: Role,
    #[cfg_attr(feature = "ts", ts(type = "true"))]
    local: AlwaysTrue,
}

impl LocalIdentity {
    pub fn new(username: impl Into<String>, role: Role) -> Self {
        Self {
            username: username.into(),
            role,
            local: AlwaysTrue,
        }
    }
}

/// `true` on the wire, and nothing else reads as one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct AlwaysTrue;

impl Serialize for AlwaysTrue {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bool(true)
    }
}

impl<'de> Deserialize<'de> for AlwaysTrue {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        if bool::deserialize(deserializer)? {
            Ok(Self)
        } else {
            Err(serde::de::Error::custom("`local` must be true"))
        }
    }
}

/// What `GET /api/onboarding` answers, unauthenticated: whether the browser may
/// make the first account.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts", ts(export))]
pub struct Onboarding {
    pub needed: bool,
}

/// The first account, the administrator: `POST /api/onboarding`, refused once
/// any account exists.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts", ts(export, rename = "FirstAccountBody"))]
pub struct FirstAccount {
    pub username: String,
    #[cfg_attr(feature = "ts", ts(as = "String"))]
    pub password: Secret,
}

/// A sign-in attempt; `SignInBody` in TypeScript, where `SignIn` is the form.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts", ts(export, rename = "SignInBody"))]
pub struct SignIn {
    pub username: String,
    #[cfg_attr(feature = "ts", ts(as = "String"))]
    pub password: Secret,
}

/// What `POST /api/session` answers, 202, when a second step comes before any
/// session; `pending` names the waiting sign-in for five minutes.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts", ts(export))]
#[serde(tag = "next", rename_all = "snake_case")]
pub enum SecondStep {
    /// TOTP is on: a code at `POST /api/session/code`.
    Code {
        #[cfg_attr(feature = "ts", ts(as = "String"))]
        pending: Secret,
    },
    /// An administrator requires a TOTP key: `POST /api/session/enrolment`.
    Enrol {
        #[cfg_attr(feature = "ts", ts(as = "String"))]
        pending: Secret,
    },
}

/// A sign-in waiting for its TOTP enrolment: `POST /api/session/enrolment`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts", ts(export))]
pub struct PendingEnrolment {
    #[cfg_attr(feature = "ts", ts(as = "String"))]
    pub pending: Secret,
}

/// The first code of a sign-in's enrolment, and the browser's clock in Unix milliseconds.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts", ts(export))]
pub struct EnrolmentConfirm {
    #[cfg_attr(feature = "ts", ts(as = "String"))]
    pub pending: Secret,
    #[cfg_attr(feature = "ts", ts(as = "String"))]
    pub code: Secret,
    #[cfg_attr(feature = "ts", ts(type = "number"))]
    pub browser_time: u64,
}

/// What confirming a sign-in's enrolment answers, with the session: the
/// account, and its recovery codes, shown this once.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts", ts(export))]
pub struct Enrolled {
    pub user: User,
    pub recovery_codes: crate::totp::RecoveryCodes,
}

/// The second step of a sign-in: a TOTP code, or a recovery code in its place.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts", ts(export))]
pub struct SignInCode {
    #[cfg_attr(feature = "ts", ts(as = "String"))]
    pub pending: Secret,
    #[cfg_attr(feature = "ts", ts(as = "String"))]
    pub code: Secret,
    /// `code` is a recovery code.
    #[serde(default)]
    #[cfg_attr(feature = "ts", ts(as = "Option<bool>", optional))]
    pub recovery: bool,
    /// The browser's clock as a TOTP code was read, in Unix milliseconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts", ts(type = "number", optional))]
    pub browser_time: Option<u64>,
}

/// A signed-in caller's proof again: the password, or a passkey's answer to
/// a challenge from `POST /api/session/reauthentication/options`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts", ts(export))]
pub struct Reauthentication {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts", ts(as = "Option<String>", optional))]
    pub password: Option<Secret>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts", ts(optional))]
    pub passkey: Option<AssertionCredential>,
}

/// How somebody proved who they were, as the audit names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts", ts(export))]
pub enum SignInMethod {
    #[serde(rename = "password")]
    Password,
    #[serde(rename = "password+totp")]
    PasswordTotp,
    #[serde(rename = "passkey")]
    Passkey,
    #[serde(rename = "recovery-code")]
    RecoveryCode,
}

impl SignInMethod {
    /// The serde spelling, for an audit field.
    pub fn as_str(self) -> &'static str {
        match self {
            SignInMethod::Password => "password",
            SignInMethod::PasswordTotp => "password+totp",
            SignInMethod::Passkey => "passkey",
            SignInMethod::RecoveryCode => "recovery-code",
        }
    }
}

/// Change your own password, proving you know the current one.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts", ts(export))]
pub struct PasswordChange {
    #[cfg_attr(feature = "ts", ts(as = "String"))]
    pub current_password: Secret,
    #[cfg_attr(feature = "ts", ts(as = "String"))]
    pub new_password: Secret,
    /// A second factor while the account's TOTP is on, else empty; its
    /// `password` is never read.
    #[serde(flatten)]
    #[cfg_attr(feature = "ts", ts(flatten))]
    pub proof: FactorProof,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_body_can_print_a_password() {
        let rendered = format!(
            "{:?} {:?} {:?}",
            SignIn {
                username: "admin".into(),
                password: "correct horse battery".into(),
            },
            PasswordChange {
                current_password: "correct horse battery".into(),
                new_password: "a much longer passphrase".into(),
                proof: FactorProof::default(),
            },
            FirstAccount {
                username: "admin".into(),
                password: "the very first one".into(),
            }
        );
        assert!(rendered.contains("admin"), "{rendered}");
        assert!(!rendered.contains("horse"), "leaked: {rendered}");
        assert!(!rendered.contains("passphrase"), "leaked: {rendered}");
        assert!(!rendered.contains("very first"), "leaked: {rendered}");
    }

    #[test]
    fn a_sign_in_that_mistypes_its_password_is_refused_without_quoting_it() {
        let err = serde_json::from_str::<SignIn>(r#"{"username":"admin","password":987654321}"#)
            .unwrap_err()
            .to_string();
        assert!(err.contains("a secret must be a string"), "{err}");
        assert!(!err.contains("987654321"), "leaked: {err}");
    }

    #[test]
    fn a_second_step_names_what_comes_next() {
        let code = SecondStep::Code {
            pending: "p".into(),
        };
        assert_eq!(
            serde_json::to_string(&code).unwrap(),
            r#"{"next":"code","pending":"p"}"#
        );
        let enrol: SecondStep = serde_json::from_str(r#"{"next":"enrol","pending":"p"}"#).unwrap();
        assert!(matches!(enrol, SecondStep::Enrol { .. }));
    }

    #[test]
    fn no_second_step_can_print_its_code_or_pending_sign_in() {
        let rendered = format!(
            "{:?} {:?} {:?}",
            SecondStep::Enrol {
                pending: "pending-token".into(),
            },
            SignInCode {
                pending: "pending-token".into(),
                code: "123456".into(),
                recovery: false,
                browser_time: Some(0),
            },
            Reauthentication {
                password: Some("correct horse battery".into()),
                passkey: None,
            },
        );
        for secret in ["pending-token", "123456", "horse"] {
            assert!(!rendered.contains(secret), "leaked: {rendered}");
        }
    }

    #[test]
    fn a_client_can_write_what_the_daemon_reads() {
        let json = r#"{"current_password":"the old one","new_password":"the new one"}"#;
        let body: PasswordChange = serde_json::from_str(json).expect("the wire form");
        assert_eq!(body.current_password.expose(), "the old one");
        assert_eq!(serde_json::to_string(&body).unwrap(), json);
    }

    #[test]
    fn a_sign_in_method_is_spelled_as_the_audit_names_it() {
        for (method, spelt) in [
            (SignInMethod::Password, "password"),
            (SignInMethod::PasswordTotp, "password+totp"),
            (SignInMethod::Passkey, "passkey"),
            (SignInMethod::RecoveryCode, "recovery-code"),
        ] {
            let json = serde_json::to_string(&method).unwrap();
            assert_eq!(json, format!("\"{spelt}\""));
            assert_eq!(method.as_str(), spelt);
            assert_eq!(serde_json::from_str::<SignInMethod>(&json).unwrap(), method);
        }
    }

    #[test]
    fn a_caller_is_local_only_when_it_says_local_true() {
        let local = LocalIdentity::new("control-socket:operator", Role::Operator);
        let json = serde_json::to_string(&Caller::Local(local.clone())).unwrap();
        assert_eq!(
            json,
            r#"{"username":"control-socket:operator","role":"operator","local":true}"#
        );
        assert_eq!(
            serde_json::from_str::<Caller>(&json).unwrap(),
            Caller::Local(local)
        );
        let denied = json.replace("true", "false");
        assert!(serde_json::from_str::<Caller>(&denied).is_err(), "{denied}");
    }

    #[test]
    fn each_caller_reads_back_as_itself() {
        let console = Caller::Console {
            id: "4f1c".to_string(),
            username: "operator".to_string(),
            role: Role::Operator,
        };
        let account = Caller::Account(User {
            id: "u1".to_string(),
            username: "admin".to_string(),
            role: Role::Admin,
            enabled: true,
            created_at: chrono::DateTime::UNIX_EPOCH,
            last_login_at: None,
        });
        let local = Caller::Local(LocalIdentity::new("control-socket", Role::Admin));
        for caller in [console, account, local] {
            let json = serde_json::to_string(&caller).unwrap();
            assert_eq!(
                serde_json::from_str::<Caller>(&json).unwrap(),
                caller,
                "{json}"
            );
        }
    }
}
