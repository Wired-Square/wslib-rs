//! What an account sends and is handed when it turns TOTP on or off, and why a
//! code went unchecked.

use serde::{Deserialize, Serialize};
use wslib_secret::Secret;

use crate::passkey::AssertionCredential;

/// A TOTP key waiting for its first code.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts", ts(export))]
pub struct TotpEnrolment {
    /// The `otpauth://` URI, for a QR code.
    #[cfg_attr(feature = "ts", ts(as = "String"))]
    pub uri: Secret,
    /// The key in base32, for typing into an authenticator app.
    #[cfg_attr(feature = "ts", ts(as = "String"))]
    pub secret: Secret,
}

/// Recovery codes, shown this once: each signs in once in place of a TOTP code.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts", ts(export))]
pub struct RecoveryCodes {
    #[cfg_attr(feature = "ts", ts(as = "Vec<String>"))]
    pub codes: Vec<Secret>,
}

/// The first code from a waiting enrolment, and the browser's clock in Unix milliseconds.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts", ts(export))]
pub struct TotpConfirm {
    #[cfg_attr(feature = "ts", ts(as = "String"))]
    pub code: Secret,
    #[cfg_attr(feature = "ts", ts(type = "number"))]
    pub browser_time: u64,
}

/// The proof a change to an account's second factors takes: while its TOTP is
/// on, a code or a passkey, never the password alone; otherwise the password or
/// a passkey.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts", ts(export))]
pub struct FactorProof {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts", ts(as = "Option<String>", optional))]
    pub code: Option<Secret>,
    /// `code` is a recovery code.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    #[cfg_attr(feature = "ts", ts(as = "Option<bool>", optional))]
    pub recovery: bool,
    /// The browser's clock as a TOTP code was read, in Unix milliseconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts", ts(type = "number", optional))]
    pub browser_time: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts", ts(as = "Option<String>", optional))]
    pub password: Option<Secret>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts", ts(optional))]
    pub passkey: Option<AssertionCredential>,
}

/// Whether an account's TOTP is on, and how many recovery codes it has left.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts", ts(export))]
pub struct TotpView {
    pub on: bool,
    pub recovery_codes_left: u32,
}

pub use wslib_auth_totp::ClockSkew;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nothing_handed_over_prints_a_key_or_a_code() {
        let rendered = format!(
            "{:?} {:?}",
            TotpEnrolment {
                uri: "otpauth://totp/Box:admin?secret=JBSWY3DPEHPK3PXP".into(),
                secret: "JBSWY3DPEHPK3PXP".into(),
            },
            RecoveryCodes {
                codes: vec!["ABCD-EFGH-IJKL-MNOP".into()],
            }
        );
        assert!(!rendered.contains("JBSWY3DP"), "leaked: {rendered}");
        assert!(!rendered.contains("ABCD"), "leaked: {rendered}");
    }
}
