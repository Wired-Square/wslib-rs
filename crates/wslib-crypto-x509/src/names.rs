use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;

use rustls_pki_types::DnsName;

use crate::Error;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum SubjectAltName {
    Dns(String),
    Ip(IpAddr),
    Email(String),
    Uri(String),
}

impl SubjectAltName {
    /// Whether this name matches `host`, as a `Host` header or URL spells it.
    ///
    /// Case is ignored, a bracketed IPv6 literal is unbracketed, and a wildcard
    /// covers exactly one label and never an address.
    pub fn covers(&self, host: &str) -> bool {
        let host = host
            .strip_prefix('[')
            .and_then(|rest| rest.strip_suffix(']'))
            .unwrap_or(host);
        let address = host.parse::<IpAddr>().ok();
        match self {
            Self::Ip(ip) => address == Some(*ip),
            Self::Dns(name) => {
                let (name, host) = (name.to_ascii_lowercase(), host.to_ascii_lowercase());
                if name == host {
                    return true;
                }
                let Some(parent) = name.strip_prefix("*.") else {
                    return false;
                };
                address.is_none() && host.split_once('.').is_some_and(|(_, rest)| rest == parent)
            }
            Self::Email(_) | Self::Uri(_) => false,
        }
    }

    /// A DNS name or an address: what a client matches a host against.
    pub fn is_host(&self) -> bool {
        matches!(self, Self::Dns(_) | Self::Ip(_))
    }
}

impl fmt::Display for SubjectAltName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Dns(v) | Self::Email(v) | Self::Uri(v) => f.write_str(v),
            Self::Ip(ip) => write!(f, "{ip}"),
        }
    }
}

/// Classifies as an address, then an email (with `@`), then a URI
/// (`scheme://…` or `urn:…`), then a DNS name, refusing what none of them is.
impl FromStr for SubjectAltName {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Error> {
        let v = s.trim();
        let invalid = |reason| Error::Name {
            name: v.to_string(),
            reason,
        };
        if v.is_empty() {
            return Err(invalid("empty"));
        }
        if let Ok(ip) = v.parse::<IpAddr>() {
            return Ok(Self::Ip(ip));
        }
        if let Some((local, domain)) = v.split_once('@') {
            if local.is_empty() || !local.bytes().all(|b| b.is_ascii_graphic() && b != b'@') {
                return Err(invalid("not a valid email address"));
            }
            if !is_dns_name(domain, false) {
                return Err(invalid("the email's domain is not a valid hostname"));
            }
            return Ok(Self::Email(v.to_string()));
        }
        if is_uri(v) {
            return Ok(Self::Uri(v.to_string()));
        }
        if is_dns_name(v, true) {
            return Ok(Self::Dns(v.to_string()));
        }
        Err(invalid("not a hostname, IP address, email or URI"))
    }
}

/// Requiring `://` (or `urn:`) keeps `host:port` from reading as a URI.
fn is_uri(v: &str) -> bool {
    let rest = match v.split_once("://") {
        Some((scheme, rest)) => {
            let mut chars = scheme.chars();
            let valid_scheme = chars.next().is_some_and(|c| c.is_ascii_alphabetic())
                && chars.all(|c| c.is_ascii_alphanumeric() || "+-.".contains(c));
            if !valid_scheme {
                return false;
            }
            rest
        }
        None if v.len() > 4 && v.as_bytes()[..4].eq_ignore_ascii_case(b"urn:") => &v[4..],
        None => return false,
    };
    !rest.is_empty() && v.bytes().all(|b| b.is_ascii_graphic())
}

/// What rustls accepts as a server name, with a wildcard only as the whole first label.
pub(crate) fn is_dns_name(v: &str, allow_wildcard: bool) -> bool {
    let name = match v.strip_prefix("*.") {
        Some(rest) if allow_wildcard => rest,
        _ => v,
    };
    DnsName::try_from(name).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dns(name: &str) -> SubjectAltName {
        SubjectAltName::Dns(name.to_string())
    }

    #[test]
    fn classifies_valid_input() {
        for (input, expected) in [
            ("www.example.com", dns("www.example.com")),
            ("*.example.com", dns("*.example.com")),
            ("localhost", dns("localhost")),
            ("_dmarc.example.com", dns("_dmarc.example.com")),
            ("*.my_host.internal", dns("*.my_host.internal")),
            ("example.com.", dns("example.com.")),
            (
                "ops@mail_relay.example.com",
                SubjectAltName::Email("ops@mail_relay.example.com".into()),
            ),
            ("10.0.0.5", SubjectAltName::Ip("10.0.0.5".parse().unwrap())),
            (
                "2001:db8::1",
                SubjectAltName::Ip("2001:db8::1".parse().unwrap()),
            ),
            (
                "ops@example.com",
                SubjectAltName::Email("ops@example.com".into()),
            ),
            (
                "spiffe://prod/web",
                SubjectAltName::Uri("spiffe://prod/web".into()),
            ),
            (
                "https://example.com/id",
                SubjectAltName::Uri("https://example.com/id".into()),
            ),
            (
                "urn:uuid:6e8bc430-9c3a-11d9-9669-0800200c9a66",
                SubjectAltName::Uri("urn:uuid:6e8bc430-9c3a-11d9-9669-0800200c9a66".into()),
            ),
        ] {
            assert_eq!(
                input.parse::<SubjectAltName>().unwrap(),
                expected,
                "{input}"
            );
        }
    }

    #[test]
    fn rejects_invalid_input() {
        for input in [
            "",
            "   ",
            "10.0.0.300",
            "1.2.3",
            "a@b@c",
            "@example.com",
            "user@bad domain",
            "user@*.example.com",
            "-bad.example.com",
            "bad-.example.com",
            "foo..com",
            "no-scheme/path",
            "example.com:443",
            "https://",
            "has space.com",
            "*.*.example.com",
            "www.*.example.com",
            "010.0.0.1",
            "::1]/x[",
            "abcé",
            "urn€",
        ] {
            assert!(
                input.parse::<SubjectAltName>().is_err(),
                "{input:?} should be rejected"
            );
        }
    }

    #[test]
    fn a_63_character_label_is_the_limit() {
        assert!(is_dns_name(&"a".repeat(63), false));
        assert!(!is_dns_name(&"a".repeat(64), false));
    }

    #[test]
    fn a_wildcard_covers_one_label_and_never_an_address_literal() {
        assert!(dns("*.widgets.internal").covers("a.widgets.internal"));
        assert!(!dns("*.widgets.internal").covers("a.b.widgets.internal"));
        assert!(!dns("*.widgets.internal").covers("widgets.internal"));
        assert!(!dns("*.1.168.192").covers("10.1.168.192"));
        assert!(!dns("*").covers("192.168.1.10"));
        assert!(dns("Widget-01.Local").covers("widget-01.local"));
        let ip = |s: &str| SubjectAltName::Ip(s.parse().unwrap());
        assert!(ip("192.168.1.10").covers("192.168.1.10"));
        assert!(ip("::1").covers("[::1]"));
        assert!(ip("2001:db8::1").covers("[2001:DB8::1]"));
        assert!(!dns("*.1").covers("[::1]"));
        assert!(!SubjectAltName::Email("a@widget-01.local".into()).covers("widget-01.local"));
    }
}
