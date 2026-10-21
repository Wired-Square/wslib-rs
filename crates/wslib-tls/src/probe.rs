use std::net::Ipv6Addr;
use std::sync::{Arc, PoisonError};
use std::time::Duration;

use http::uri::Authority;
use rustls_pki_types::{CertificateDer, ServerName};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use crate::outbound::{Judge, Recorder};
use crate::{Outbound, normalise_host};

const PROBE_TIMEOUT: Duration = Duration::from_secs(5);

/// What a host presented to [`Outbound::inspect`].
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct Presented {
    /// As [`normalise_host`] spells it, so it can be pinned as is.
    pub host: String,
    pub port: u16,
    pub end_entity: CertificateDer<'static>,
    pub intermediates: Vec<CertificateDer<'static>>,
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ProbeError {
    #[error("{scheme}:// is not https://, so there is no certificate to look at")]
    NotHttps { scheme: String },
    #[error("{target:?} does not name a host")]
    NoHost { target: String },
    #[error("{authority} does not end in a port number")]
    BadPort { authority: String },
    #[error("{host} is not a name a TLS client can dial")]
    NotAServerName { host: String },
    #[error("{host}:{port} presented no certificate: nothing answered within {} seconds", PROBE_TIMEOUT.as_secs())]
    TimedOut { host: String, port: u16 },
    #[error("{host}:{port} presented no certificate: {source}")]
    Failed {
        host: String,
        port: u16,
        source: std::io::Error,
    },
    #[error("{host}:{port} completed a handshake without presenting a certificate")]
    NoCertificate { host: String, port: u16 },
}

impl Outbound {
    /// Connects to `target` and returns the chain it presents, trusting nothing.
    ///
    /// `target` is an `https://` URL or a host with or without a port, 443 by
    /// default. The look before a pin: it proves nothing about who holds the
    /// key, which the operator confirms out of band. A server that presents a
    /// certificate and then refuses the client has still shown it. Offers ALPN
    /// `h2` and `http/1.1`, as a browser would.
    pub async fn inspect(&self, target: &str) -> Result<Presented, ProbeError> {
        let (host, port) = parse_target(target)?;
        let name = ServerName::try_from(host.clone())
            .map_err(|_| ProbeError::NotAServerName { host: host.clone() })?;

        let seen = Recorder::default();
        let mut config = self.config(Judge::Recording(seen.clone()));
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        let connector = TlsConnector::from(Arc::new(config));
        let attempt = async {
            let tcp = TcpStream::connect((host.as_str(), port)).await?;
            connector.connect(name, tcp).await
        };
        let outcome = tokio::time::timeout(PROBE_TIMEOUT, attempt).await;

        let chain = seen.lock().unwrap_or_else(PoisonError::into_inner).take();
        match (chain, outcome) {
            (Some((end_entity, intermediates)), _) => Ok(Presented {
                host,
                port,
                end_entity,
                intermediates,
            }),
            (None, Err(_)) => Err(ProbeError::TimedOut { host, port }),
            (None, Ok(Err(source))) => Err(ProbeError::Failed { host, port, source }),
            (None, Ok(Ok(_))) => Err(ProbeError::NoCertificate { host, port }),
        }
    }
}

fn parse_target(target: &str) -> Result<(String, u16), ProbeError> {
    let target = target.trim();
    let rest = match target.split_once("://") {
        Some((scheme, rest)) if scheme.eq_ignore_ascii_case("https") => rest,
        Some((scheme, _)) => {
            return Err(ProbeError::NotHttps {
                scheme: scheme.to_string(),
            });
        }
        None => target,
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    // A bare IPv6 address is what somebody pastes; an authority brackets it.
    let authority: Authority = match authority.parse::<Ipv6Addr>() {
        Ok(ip) => format!("[{ip}]"),
        Err(_) => authority.to_string(),
    }
    .parse()
    .map_err(|_| ProbeError::NoHost {
        target: target.to_string(),
    })?;
    let port = match authority.port_u16() {
        Some(port) => port,
        // `Authority` reads a port it cannot parse as none at all.
        None if authority
            .as_str()
            .rsplit_once(':')
            .is_some_and(|(_, tail)| !tail.contains([']', '@'])) =>
        {
            return Err(ProbeError::BadPort {
                authority: authority.to_string(),
            });
        }
        None => 443,
    };
    Ok((normalise_host(authority.host()), port))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_target_is_a_url_or_a_host_with_or_without_a_port() {
        let ok = |t: &str| parse_target(t).expect(t);
        assert_eq!(ok("https://10.0.50.198"), ("10.0.50.198".into(), 443));
        assert_eq!(ok("HTTPS://10.0.50.198"), ("10.0.50.198".into(), 443));
        assert_eq!(ok("fe80::1"), ("fe80::1".into(), 443));
        assert_eq!(
            ok("https://Widget.Local:8443/api/x?y#z"),
            ("widget.local".into(), 8443)
        );
        assert_eq!(
            ok("https://user:pw@[FE80::0001]:8443/"),
            ("fe80::1".into(), 8443)
        );
        assert_eq!(ok("[fe80::1]"), ("fe80::1".into(), 443));
        assert_eq!(ok(" widget.local:8443 "), ("widget.local".into(), 8443));

        assert!(matches!(
            parse_target("http://widget.local/"),
            Err(ProbeError::NotHttps { scheme }) if scheme == "http"
        ));
        assert!(matches!(
            parse_target("host:x"),
            Err(ProbeError::BadPort { .. })
        ));
        for bad in ["https://", "https://[::1", "", "a b"] {
            assert!(
                matches!(parse_target(bad), Err(ProbeError::NoHost { .. })),
                "{bad}"
            );
        }
    }
}
