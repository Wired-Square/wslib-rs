//! What an appliance trusts for the connections it makes: hosts by fingerprint,
//! and authorities by certificate. Both are additive to the operating system's
//! store.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::tls::CertificateView;

/// One host, and the certificate somebody confirmed for it; only the
/// fingerprint is checked, the rest is what they were shown.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts", ts(export))]
pub struct TrustedCert {
    /// A lowercase DNS name or a canonical IP literal, never a port; one pin per host.
    pub host: String,

    /// Lowercase hex SHA-256 of the leaf certificate's DER.
    pub sha256: String,

    pub subject: String,
    pub issuer: String,
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
    pub added_at: DateTime<Utc>,
    pub added_by: String,
}

/// An authority this appliance trusts for the connections it makes;
/// `not_after` is for the screen, never the handshake.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts", ts(export))]
pub struct TrustedCa {
    /// Lowercase hex SHA-256 of the DER, which a `DELETE` takes.
    pub sha256: String,
    pub subject: String,
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
    pub added_at: DateTime<Utc>,
    pub added_by: String,

    /// The certificate itself, as one PEM section.
    pub pem: String,
}

/// The body `POST /api/tls/cas` and `POST /api/tls/cas/inspect` take.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts", ts(export))]
pub struct CaCertificate {
    pub cert_pem: String,
}

/// The body `POST /api/tls/pins/inspect` takes: a URL, `host` or `host:port`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts", ts(export))]
pub struct InspectPeer {
    pub url: String,
}

/// The body `POST /api/tls/pins` takes; refused unless the host presents `expect_sha256`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts", ts(export))]
pub struct PinPeer {
    pub url: String,
    pub expect_sha256: String,
}

/// What a host presented, and the name it would be pinned under.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts", ts(export))]
pub struct Peer {
    /// In [`TrustedCert::host`]'s spelling.
    pub host: String,
    /// Where it was dialled; never part of the pin.
    pub port: u16,
    pub certificate: CertificateView,
}
