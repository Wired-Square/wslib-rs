use std::collections::HashMap;
use std::net::IpAddr;

use rustls_pki_types::{CertificateDer, TrustAnchor};
use wslib_crypto::Fingerprint;
use wslib_crypto_x509::chain::{ChainError, trust_anchor};

/// What to trust when dialling out: the OS's roots, authorities, and pins by host.
#[derive(Clone, Debug, Default)]
pub struct Trust {
    pub(crate) os_roots: bool,
    pub(crate) anchors: Vec<TrustAnchor<'static>>,
    pub(crate) pins: HashMap<String, Fingerprint>,
}

impl Trust {
    /// The operating system's roots; [`Trust::default`] is nothing at all.
    pub fn os_roots() -> Self {
        Self {
            os_roots: true,
            ..Self::default()
        }
    }

    /// Trusts what `certificate`, an authority's, signs.
    pub fn anchor(&mut self, certificate: &CertificateDer<'_>) -> Result<(), AnchorError> {
        let view = wslib_crypto_x509::inspect(certificate)?;
        if !view.ca {
            return Err(AnchorError::NotAnAuthority {
                fingerprint: view.fingerprint,
            });
        }
        self.anchors.push(trust_anchor(certificate)?);
        Ok(())
    }

    /// Trusts exactly the certificate with `fingerprint` for `host`, replacing any earlier pin.
    pub fn pin(&mut self, host: &str, fingerprint: Fingerprint) {
        self.pins.insert(normalise_host(host), fingerprint);
    }
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum AnchorError {
    #[error("not a readable certificate: {0}")]
    Unreadable(#[from] wslib_crypto_x509::Error),
    /// A leaf would otherwise anchor itself and trust the one host presenting it.
    #[error("certificate {fingerprint} is not an authority's: it has no CA:TRUE")]
    NotAnAuthority { fingerprint: Fingerprint },
    #[error("not usable as a trust anchor: {0}")]
    Unusable(#[from] ChainError),
}

/// The one spelling of a host a pin is keyed by, so a pin and the name rustls
/// dialled agree: an address in canonical form, a name in lowercase without a
/// trailing dot.
pub fn normalise_host(host: &str) -> String {
    let host = host.trim();
    let host = host
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
        .unwrap_or(host);
    match host.parse::<IpAddr>() {
        Ok(ip) => ip.to_string(),
        Err(_) => host.trim_end_matches('.').to_ascii_lowercase(),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use rustls_pki_types::ServerName;

    use super::*;
    use crate::testing::{Authority, self_signed};

    #[test]
    fn a_pin_is_spelled_the_way_rustls_dials_it() {
        for host in [
            "10.0.50.198",
            "[fe80::1]",
            "[FE80::0001]",
            "widget.example.com",
            "Widget.Example.Com.",
        ] {
            let unbracketed = host.trim_start_matches('[').trim_end_matches(']');
            let name = ServerName::try_from(unbracketed).expect("a name rustls accepts");
            assert_eq!(
                normalise_host(host),
                normalise_host(&name.to_str()),
                "{host}"
            );
        }
        assert_eq!(normalise_host(" [FE80::0001] "), "fe80::1");
        assert_eq!(normalise_host("Widget.Local."), "widget.local");
    }

    #[test]
    fn only_an_authority_anchors() {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut trust = Trust::default();
        trust
            .anchor(&Authority::new(provider.clone(), "Widget Root").certificate)
            .expect("an authority");

        let leaf = &self_signed(provider, &["127.0.0.1"]).chain[0];
        assert!(matches!(
            trust.anchor(leaf),
            Err(AnchorError::NotAnAuthority { fingerprint }) if fingerprint == Fingerprint::of(leaf)
        ));
        assert!(matches!(
            trust.anchor(&CertificateDer::from(vec![0x30, 0x00])),
            Err(AnchorError::Unreadable(_))
        ));
        assert_eq!(trust.anchors.len(), 1);
    }
}
