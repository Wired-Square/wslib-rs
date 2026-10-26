use std::net::{IpAddr, Ipv6Addr};

use crate::code::{NotACode, PairingCode};
use crate::pin::{NotAPin, SpkiSha256};

/// `<scheme>://host:port#pin=<SPKI SHA-256>&code=<code>`, its `Debug` redacting the code.
#[derive(Clone, Debug)]
pub struct PairingUri {
    scheme: String,
    host: String,
    port: u16,
    pin: SpkiSha256,
    code: PairingCode,
}

impl PairingUri {
    /// `host` is a DNS name, or an IPv4 or IPv6 address without brackets.
    pub fn new(
        scheme: &str,
        host: &str,
        port: u16,
        pin: SpkiSha256,
        code: PairingCode,
    ) -> Result<Self, UriError> {
        if !is_scheme(scheme) {
            return Err(UriError::Scheme(scheme.into()));
        }
        if !is_host(host) {
            return Err(UriError::Host(host.into()));
        }
        if port == 0 {
            return Err(UriError::Port("0".into()));
        }
        Ok(Self {
            scheme: scheme.to_ascii_lowercase(),
            host: host.into(),
            port,
            pin,
            code,
        })
    }

    /// Reads `text` as a URI of `scheme`, in any case.
    pub fn parse(scheme: &str, text: &str) -> Result<Self, UriError> {
        let not_scheme = || UriError::Scheme(scheme.into());
        let (given, rest) = text.trim().split_once("://").ok_or_else(not_scheme)?;
        if !given.eq_ignore_ascii_case(scheme) {
            return Err(not_scheme());
        }
        let (authority, fragment) = rest.split_once('#').ok_or(UriError::Missing("pin"))?;
        let (host, port) = split_authority(authority)?;
        if !port.bytes().all(|b| b.is_ascii_digit()) {
            return Err(UriError::Port(port.into()));
        }
        let port = port.parse().map_err(|_| UriError::Port(port.into()))?;

        let (mut pin, mut code) = (None, None);
        for pair in fragment.split('&') {
            let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
            let slot = match key {
                "pin" => &mut pin,
                "code" => &mut code,
                _ => return Err(UriError::UnknownKey(key.into())),
            };
            if slot.replace(value).is_some() {
                return Err(UriError::DuplicateKey(key.into()));
            }
        }
        let pin = pin.ok_or(UriError::Missing("pin"))?;
        let code = code.ok_or(UriError::Missing("code"))?;
        Self::new(scheme, host, port, pin.parse()?, code.parse()?)
    }

    /// The URI in full, code and all, for the person who is to pair.
    pub fn expose(&self) -> String {
        let Self {
            scheme,
            host,
            port,
            pin,
            code,
        } = self;
        let host = match host.parse::<Ipv6Addr>() {
            Ok(_) => format!("[{host}]"),
            Err(_) => host.clone(),
        };
        format!("{scheme}://{host}:{port}#pin={pin}&code={}", code.expose())
    }

    pub fn scheme(&self) -> &str {
        &self.scheme
    }

    /// Without brackets, as a socket address or TLS server name takes it.
    pub fn host(&self) -> &str {
        &self.host
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn pin(&self) -> SpkiSha256 {
        self.pin
    }

    pub fn code(&self) -> &PairingCode {
        &self.code
    }
}

fn split_authority(authority: &str) -> Result<(&str, &str), UriError> {
    let not_authority = || UriError::Host(authority.into());
    match authority.strip_prefix('[') {
        Some(bracketed) => {
            let (host, port) = bracketed.split_once("]:").ok_or_else(not_authority)?;
            host.parse::<Ipv6Addr>().map_err(|_| not_authority())?;
            Ok((host, port))
        }
        None => {
            let (host, port) = authority.split_once(':').ok_or_else(not_authority)?;
            if port.contains(':') {
                return Err(not_authority());
            }
            Ok((host, port))
        }
    }
}

fn is_scheme(scheme: &str) -> bool {
    let mut chars = scheme.chars();
    chars.next().is_some_and(|c| c.is_ascii_alphabetic())
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
}

fn is_host(host: &str) -> bool {
    host.parse::<IpAddr>().is_ok() || is_dns_name(host)
}

/// An all-digit last label is refused, as a name ending so reads as a mistyped IPv4 address.
fn is_dns_name(name: &str) -> bool {
    let label = |label: &str| {
        (1..=63).contains(&label.len())
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    };
    name.len() <= 253
        && name.split('.').all(label)
        && !name
            .rsplit('.')
            .next()
            .is_some_and(|last| last.bytes().all(|b| b.is_ascii_digit()))
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum UriError {
    #[error("not a {0}:// URI")]
    Scheme(String),
    #[error("not a DNS name, an IPv4 address or a bracketed IPv6 address with a port: {0}")]
    Host(String),
    #[error("not a port: {0}")]
    Port(String),
    #[error("unknown key in the fragment: {0}")]
    UnknownKey(String),
    #[error("{0} given twice in the fragment")]
    DuplicateKey(String),
    #[error("no {0} in the fragment")]
    Missing(&'static str),
    #[error(transparent)]
    Pin(#[from] NotAPin),
    #[error(transparent)]
    Code(#[from] NotACode),
}
