//! The certificate this appliance serves, as a browser sees it: the leaf alone.
//! A chain pasted under it is kept and served, but never described here.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use wslib_secret::Secret;

/// The longest PEM this appliance will read, in bytes.
pub const MAX_PEM_LEN: usize = 256 * 1024;

/// One certificate, as it describes itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts", ts(export))]
pub struct CertificateView {
    /// The subject distinguished name, RFC 4514, as `CN=widget-01`.
    pub subject: String,

    /// The issuer distinguished name, in the same form.
    pub issuer: String,

    /// Every subjectAltName: DNS names as written, IP addresses canonicalised.
    pub sans: Vec<String>,

    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,

    /// Lowercase hex SHA-256 of the DER, as [`TrustedCert`](crate::TrustedCert) spells it.
    pub sha256: String,

    /// The public key in words, as `ECDSA P-256`, or its algorithm's OID.
    pub key: String,

    pub self_signed: bool,
}

/// A certificate, and warnings about it that are never a refusal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts", ts(export))]
pub struct CertificateReport {
    pub certificate: CertificateView,
    pub warnings: Vec<String>,
}

/// The pair itself, as a backup carries it; never a route's body, so never exported.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServingPair {
    pub cert_pem: String,
    pub key_pem: Secret,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_pair_cannot_print_its_key() {
        let pair = ServingPair {
            cert_pem: "-----BEGIN CERTIFICATE-----".to_string(),
            key_pem: Secret::new("-----BEGIN PRIVATE KEY-----d0not1eak"),
        };
        assert!(!format!("{pair:?}").contains("d0not1eak"));
    }
}
