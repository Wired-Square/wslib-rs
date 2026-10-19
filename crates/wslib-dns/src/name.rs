use std::fmt;
use std::net::IpAddr;

const MAX_NAME_LEN: usize = 253;
const MAX_LABEL_LEN: usize = 63;

/// Lowercases ASCII, trims surrounding whitespace and drops a trailing dot. The
/// root stays `.`, so a null MX's exchange survives.
pub fn normalise(name: &str) -> String {
    let name = name.trim();
    if name == "." {
        return ".".into();
    }
    name.strip_suffix('.').unwrap_or(name).to_ascii_lowercase()
}

/// Why a name is not a valid hostname.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case", tag = "code"))]
#[non_exhaustive]
pub enum HostnameError {
    Empty,
    TooLong {
        len: usize,
    },
    EmptyLabel {
        index: usize,
    },
    LabelTooLong {
        index: usize,
        len: usize,
    },
    InvalidCharacter {
        index: usize,
        character: char,
    },
    HyphenAtLabelEdge {
        index: usize,
    },
    /// RFC 1123 §2.1: an all-numeric top label would read as an address.
    NumericTopLabel,
}

impl fmt::Display for HostnameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("name is empty"),
            Self::TooLong { len } => write!(f, "name is {len} octets, over {MAX_NAME_LEN}"),
            Self::EmptyLabel { index } => write!(f, "label {index} is empty"),
            Self::LabelTooLong { index, len } => {
                write!(f, "label {index} is {len} octets, over {MAX_LABEL_LEN}")
            }
            Self::InvalidCharacter { index, character } => {
                write!(f, "label {index} contains {character:?}")
            }
            Self::HyphenAtLabelEdge { index } => {
                write!(f, "label {index} starts or ends with a hyphen")
            }
            Self::NumericTopLabel => f.write_str("top-level label is all digits"),
        }
    }
}

impl std::error::Error for HostnameError {}

/// Checks a host name against RFC 1035 and RFC 1123: letters, digits and
/// hyphens. One trailing dot is allowed.
pub fn validate_hostname(name: &str) -> Result<(), HostnameError> {
    validate(name, false)
}

/// As [`validate_hostname`], but labels may also contain `_`, as service names
/// such as `_dmarc.example.com` and `s1._domainkey.example.com` do.
pub fn validate_service_name(name: &str) -> Result<(), HostnameError> {
    validate(name, true)
}

fn validate(name: &str, allow_underscore: bool) -> Result<(), HostnameError> {
    let name = name.strip_suffix('.').unwrap_or(name);
    if name.is_empty() {
        return Err(HostnameError::Empty);
    }
    if name.len() > MAX_NAME_LEN {
        return Err(HostnameError::TooLong { len: name.len() });
    }
    let labels: Vec<&str> = name.split('.').collect();
    for (index, label) in labels.iter().enumerate() {
        if label.is_empty() {
            return Err(HostnameError::EmptyLabel { index });
        }
        if label.len() > MAX_LABEL_LEN {
            return Err(HostnameError::LabelTooLong {
                index,
                len: label.len(),
            });
        }
        if let Some(character) = label
            .chars()
            .find(|&c| !(c.is_ascii_alphanumeric() || c == '-' || (allow_underscore && c == '_')))
        {
            return Err(HostnameError::InvalidCharacter { index, character });
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(HostnameError::HyphenAtLabelEdge { index });
        }
    }
    if labels.len() > 1
        && labels
            .last()
            .is_some_and(|top| top.bytes().all(|b| b.is_ascii_digit()))
    {
        return Err(HostnameError::NumericTopLabel);
    }
    Ok(())
}

/// A name that IDNA processing (UTS #46) rejected.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IdnaError(String);

impl fmt::Display for IdnaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?} is not a valid internationalised name", self.0)
    }
}

impl std::error::Error for IdnaError {}

/// The normalised A-label form of a name, converting any U-labels:
/// `bücher.example` becomes `xn--bcher-kva.example`.
pub fn to_ascii(name: &str) -> Result<String, IdnaError> {
    let name = normalise(name);
    idna::domain_to_ascii(&name).map_err(|_| IdnaError(name))
}

/// The U-label form of a name, for display. Labels that fail to decode are
/// left as they were.
pub fn to_unicode(name: &str) -> String {
    idna::domain_to_unicode(&normalise(name)).0
}

/// The public suffix of a name per the Public Suffix List, ICANN and private
/// sections both: `com.au` for `mail.example.com.au`. A TLD missing from the
/// list counts as a suffix, per the list's default rule.
pub fn public_suffix(name: &str) -> Option<String> {
    let name = normalise(name);
    let suffix = psl::suffix(name.as_bytes())?;
    std::str::from_utf8(suffix.as_bytes())
        .ok()
        .map(str::to_owned)
}

/// The registrable domain, DMARC's organisational domain (RFC 7489 §3.2): the
/// public suffix plus one label. `None` when the name is itself a suffix.
pub fn registrable_domain(name: &str) -> Option<String> {
    let name = normalise(name);
    let domain = psl::domain(name.as_bytes())?;
    std::str::from_utf8(domain.as_bytes())
        .ok()
        .map(str::to_owned)
}

/// The name a PTR query for `ip` asks about, under `in-addr.arpa` or
/// `ip6.arpa`.
pub fn reverse_name(ip: IpAddr) -> String {
    let suffix = match ip {
        IpAddr::V4(_) => "in-addr.arpa",
        IpAddr::V6(_) => "ip6.arpa",
    };
    format!("{}.{suffix}", reversed_labels(ip))
}

/// The address's labels in reverse, as DNSBL and PTR names put them: octets
/// for IPv4, nibbles for IPv6.
pub fn reversed_labels(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => {
            let [a, b, c, d] = v4.octets();
            format!("{d}.{c}.{b}.{a}")
        }
        IpAddr::V6(v6) => v6
            .octets()
            .iter()
            .rev()
            .flat_map(|byte| [byte & 0x0f, byte >> 4])
            .map(|nibble| format!("{nibble:x}"))
            .collect::<Vec<_>>()
            .join("."),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalise_lowercases_and_drops_the_trailing_dot_but_keeps_the_root() {
        assert_eq!(normalise(" Mail.Example.COM. "), "mail.example.com");
        assert_eq!(normalise("."), ".");
        assert_eq!(normalise("example.com"), "example.com");
    }

    #[test]
    fn hostnames_follow_rfc_1123() {
        for ok in [
            "example.com",
            "a.b.c",
            "0-abc.example",
            "sub-domain.example.co.uk",
            "example.com.",
            "localhost",
        ] {
            assert_eq!(validate_hostname(ok), Ok(()), "{ok}");
        }
        assert_eq!(validate_hostname(""), Err(HostnameError::Empty));
        assert_eq!(validate_hostname("."), Err(HostnameError::Empty));
        assert_eq!(
            validate_hostname(".leading"),
            Err(HostnameError::EmptyLabel { index: 0 })
        );
        assert_eq!(
            validate_hostname("double..dot"),
            Err(HostnameError::EmptyLabel { index: 1 })
        );
        assert_eq!(
            validate_hostname("-hyphen.com"),
            Err(HostnameError::HyphenAtLabelEdge { index: 0 })
        );
        assert_eq!(
            validate_hostname("a.hyphen-.com"),
            Err(HostnameError::HyphenAtLabelEdge { index: 1 })
        );
        assert_eq!(
            validate_hostname("name:8080.example"),
            Err(HostnameError::InvalidCharacter {
                index: 0,
                character: ':'
            })
        );
        assert_eq!(
            validate_hostname("bücher.example"),
            Err(HostnameError::InvalidCharacter {
                index: 0,
                character: 'ü'
            })
        );
        assert_eq!(
            validate_hostname("192.0.2.1"),
            Err(HostnameError::NumericTopLabel)
        );
        assert_eq!(
            validate_hostname(&"a".repeat(254)),
            Err(HostnameError::TooLong { len: 254 })
        );
        assert_eq!(
            validate_hostname(&format!("{}.example", "a".repeat(64))),
            Err(HostnameError::LabelTooLong { index: 0, len: 64 })
        );
    }

    #[test]
    fn underscores_are_allowed_only_in_service_names() {
        assert_eq!(validate_service_name("_dmarc.example.com"), Ok(()));
        assert_eq!(validate_service_name("s1._domainkey.example.com"), Ok(()));
        assert_eq!(
            validate_hostname("_dmarc.example.com"),
            Err(HostnameError::InvalidCharacter {
                index: 0,
                character: '_'
            })
        );
    }

    #[test]
    fn idna_converts_u_labels_both_ways() {
        assert_eq!(to_ascii("Bücher.Example").unwrap(), "xn--bcher-kva.example");
        assert_eq!(to_ascii("example.com").unwrap(), "example.com");
        assert_eq!(to_unicode("xn--bcher-kva.example"), "bücher.example");
        assert!(to_ascii("xn--a.example").is_err());
    }

    #[test]
    fn registrable_domain_follows_the_public_suffix_list() {
        assert_eq!(
            registrable_domain("mail.example.com.au").as_deref(),
            Some("example.com.au")
        );
        assert_eq!(
            registrable_domain("a.b.example.co.uk").as_deref(),
            Some("example.co.uk")
        );
        assert_eq!(
            registrable_domain("Example.COM.").as_deref(),
            Some("example.com")
        );
        assert_eq!(registrable_domain("com.au"), None);
        assert_eq!(
            public_suffix("mail.example.com.au").as_deref(),
            Some("com.au")
        );
    }

    #[test]
    fn private_suffixes_count_as_suffixes() {
        assert_eq!(
            public_suffix("example.github.io").as_deref(),
            Some("github.io")
        );
        assert_eq!(
            registrable_domain("www.example.github.io").as_deref(),
            Some("example.github.io")
        );
    }

    #[test]
    fn reverse_names_use_octets_for_v4_and_nibbles_for_v6() {
        assert_eq!(
            reverse_name("192.0.2.10".parse().unwrap()),
            "10.2.0.192.in-addr.arpa"
        );
        assert_eq!(
            reverse_name("2001:db8::1".parse().unwrap()),
            "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa"
        );
    }
}
