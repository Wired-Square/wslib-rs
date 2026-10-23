use std::fmt;
use std::str::FromStr;

/// The rule a refused name broke.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Invalid {
    ServiceType,
    Subtype,
    InstanceEmpty,
    /// Longer than 63 bytes.
    InstanceTooLong,
    ControlCharacter,
    TxtKey,
    /// Longer than 255 bytes, `key=value` together.
    TxtTooLong,
    HostName,
}

impl fmt::Display for Invalid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::ServiceType => {
                "a service type is _name._tcp or _name._udp, the name 1 to 15 letters, digits \
                 and single hyphens, with a letter and no hyphen at either end"
            }
            Self::Subtype => {
                "a subtype is _name._sub. and a service type, the name at most 63 bytes"
            }
            Self::InstanceEmpty => "an instance name is required",
            Self::InstanceTooLong => "an instance name may be at most 63 bytes",
            Self::ControlCharacter => "a name may not contain control characters",
            Self::TxtKey => "a TXT key is printable ASCII other than '=', at least one character",
            Self::TxtTooLong => "a TXT entry may be at most 255 bytes",
            Self::HostName => {
                "a host name is one label of 1 to 63 letters, digits and hyphens, with no \
                 hyphen at either end"
            }
        })
    }
}

impl std::error::Error for Invalid {}

const MAX_LABEL: usize = 63;
const MAX_TXT: usize = 255;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Protocol {
    Tcp,
    Udp,
}

/// A DNS-SD service type such as `_http._tcp`, read with or without `.local.`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ServiceType {
    name: String,
    protocol: Protocol,
}

impl ServiceType {
    /// The service name without its underscore, lower case.
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn protocol(&self) -> Protocol {
        self.protocol
    }

    #[cfg(feature = "in-process")]
    pub(crate) fn fqdn(&self) -> String {
        format!("{self}.local.")
    }
}

impl FromStr for ServiceType {
    type Err = Invalid;

    fn from_str(s: &str) -> Result<Self, Invalid> {
        let s = without_local(s);
        let (name, protocol) = s.rsplit_once('.').ok_or(Invalid::ServiceType)?;
        let protocol = match protocol.to_ascii_lowercase().as_str() {
            "_tcp" => Protocol::Tcp,
            "_udp" => Protocol::Udp,
            _ => return Err(Invalid::ServiceType),
        };
        let name = name.strip_prefix('_').ok_or(Invalid::ServiceType)?;
        let shaped = (1..=15).contains(&name.len())
            && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
            && name.bytes().any(|b| b.is_ascii_alphabetic())
            && !name.starts_with('-')
            && !name.ends_with('-')
            && !name.contains("--");
        if !shaped {
            return Err(Invalid::ServiceType);
        }
        Ok(Self {
            name: name.to_ascii_lowercase(),
            protocol,
        })
    }
}

impl fmt::Display for ServiceType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let protocol = match self.protocol {
            Protocol::Tcp => "tcp",
            Protocol::Udp => "udp",
        };
        write!(f, "_{}._{protocol}", self.name)
    }
}

/// A subtype such as `_printer._sub._http._tcp`, browsed for on its own.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Subtype {
    name: String,
    kind: ServiceType,
}

impl Subtype {
    /// The subtype's name without its underscore.
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn kind(&self) -> &ServiceType {
        &self.kind
    }
}

impl FromStr for Subtype {
    type Err = Invalid;

    fn from_str(s: &str) -> Result<Self, Invalid> {
        let at = s
            .to_ascii_lowercase()
            .find("._sub.")
            .ok_or(Invalid::Subtype)?;
        let (label, kind) = (&s[..at], &s[at + "._sub.".len()..]);
        let name = label.strip_prefix('_').ok_or(Invalid::Subtype)?;
        if name.is_empty() || label.len() > MAX_LABEL || name.contains('.') {
            return Err(Invalid::Subtype);
        }
        if name.chars().any(char::is_control) {
            return Err(Invalid::ControlCharacter);
        }
        Ok(Self {
            name: name.to_string(),
            kind: kind.parse()?,
        })
    }
}

impl fmt::Display for Subtype {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "_{}._sub.{}", self.name, self.kind)
    }
}

/// A service instance's name, the label people read in a browser: any UTF-8,
/// compared without regard to ASCII case as DNS compares it (RFC 6762 §16).
#[derive(Debug, Clone)]
pub struct InstanceName(String);

impl InstanceName {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn folded(&self) -> impl Iterator<Item = u8> + '_ {
        self.0.bytes().map(|b| b.to_ascii_lowercase())
    }
}

impl PartialEq for InstanceName {
    fn eq(&self, other: &Self) -> bool {
        self.0.eq_ignore_ascii_case(&other.0)
    }
}

impl Eq for InstanceName {}

impl std::hash::Hash for InstanceName {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.folded().for_each(|b| state.write_u8(b));
        state.write_u8(0xff);
    }
}

impl PartialOrd for InstanceName {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for InstanceName {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.folded().cmp(other.folded())
    }
}

impl FromStr for InstanceName {
    type Err = Invalid;

    fn from_str(s: &str) -> Result<Self, Invalid> {
        if s.is_empty() {
            return Err(Invalid::InstanceEmpty);
        }
        if s.len() > MAX_LABEL {
            return Err(Invalid::InstanceTooLong);
        }
        if s.chars().any(char::is_control) {
            return Err(Invalid::ControlCharacter);
        }
        Ok(Self(s.to_string()))
    }
}

impl fmt::Display for InstanceName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// One TXT entry, `key=value`; a bare `key` reads as an empty value.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Txt {
    key: String,
    value: String,
}

impl Txt {
    pub fn new(key: &str, value: &str) -> Result<Self, Invalid> {
        if key.is_empty() || !key.bytes().all(|b| (0x20..=0x7e).contains(&b) && b != b'=') {
            return Err(Invalid::TxtKey);
        }
        if key.len() + 1 + value.len() > MAX_TXT {
            return Err(Invalid::TxtTooLong);
        }
        Ok(Self {
            key: key.to_string(),
            value: value.to_string(),
        })
    }

    /// Entries from `(key, value)` pairs, such as `Txt::pairs([("product", "widget")])`.
    pub fn pairs<K: AsRef<str>, V: AsRef<str>>(
        pairs: impl IntoIterator<Item = (K, V)>,
    ) -> Result<Vec<Self>, Invalid> {
        pairs
            .into_iter()
            .map(|(k, v)| Self::new(k.as_ref(), v.as_ref()))
            .collect()
    }

    pub fn key(&self) -> &str {
        &self.key
    }

    pub fn value(&self) -> &str {
        &self.value
    }
}

impl FromStr for Txt {
    type Err = Invalid;

    fn from_str(s: &str) -> Result<Self, Invalid> {
        let (key, value) = s.split_once('=').unwrap_or((s, ""));
        Self::new(key, value)
    }
}

impl fmt::Display for Txt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}={}", self.key, self.value)
    }
}

/// A `.local` host name, one label, read with or without `.local`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct HostName(String);

impl HostName {
    /// The label alone.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// `<label>.local`.
    pub fn fqdn(&self) -> String {
        format!("{}.local", self.0)
    }

    /// The closest host name to `raw`: other characters become hyphens, cut
    /// to 63 bytes; `None` when nothing is left.
    #[cfg(feature = "in-process")]
    pub(crate) fn nearest(raw: &str) -> Option<Self> {
        let mapped: String = raw
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
            .take(MAX_LABEL)
            .collect();
        mapped.trim_matches('-').parse().ok()
    }
}

impl FromStr for HostName {
    type Err = Invalid;

    fn from_str(s: &str) -> Result<Self, Invalid> {
        let label = without_local(s);
        let shaped = (1..=MAX_LABEL).contains(&label.len())
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            && !label.starts_with('-')
            && !label.ends_with('-');
        if !shaped {
            return Err(Invalid::HostName);
        }
        Ok(Self(label.to_string()))
    }
}

impl fmt::Display for HostName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

fn without_local(s: &str) -> &str {
    let s = s.strip_suffix('.').unwrap_or(s);
    match s.len().checked_sub(".local".len()) {
        Some(at) if s.is_char_boundary(at) && s[at..].eq_ignore_ascii_case(".local") => &s[..at],
        _ => s,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_service_type_reads_with_or_without_local_and_prints_without() {
        for raw in [
            "_http._tcp",
            "_http._tcp.local",
            "_http._tcp.local.",
            "_HTTP._TCP.LOCAL.",
        ] {
            let kind: ServiceType = raw.parse().unwrap();
            assert_eq!(kind.to_string(), "_http._tcp", "{raw}");
        }
        assert_eq!(
            "_mcumgr._udp".parse::<ServiceType>().unwrap().protocol(),
            Protocol::Udp
        );
        assert_eq!(
            "_abcdefghijklmno._udp"
                .parse::<ServiceType>()
                .unwrap()
                .name(),
            "abcdefghijklmno"
        );
    }

    #[test]
    fn a_service_name_follows_rfc_6335() {
        for bad in [
            "",
            "_http",
            "http._tcp",
            "_http._sctp",
            "_._tcp",
            "_abcdefghijklmnop._tcp",
            "_-http._tcp",
            "_http-._tcp",
            "_ht--tp._tcp",
            "_1234._tcp",
            "_ht_tp._tcp",
            "_http.x._tcp",
        ] {
            assert_eq!(
                bad.parse::<ServiceType>(),
                Err(Invalid::ServiceType),
                "{bad:?}"
            );
        }
        assert!("_esphomelib._tcp".parse::<ServiceType>().is_ok());
        assert!("_wiredtest-node._tcp".parse::<ServiceType>().is_ok());
        assert!("_3d-print._tcp".parse::<ServiceType>().is_ok());
    }

    #[test]
    fn a_subtype_names_its_type() {
        let sub: Subtype = "_widget._sub._https._tcp.local.".parse().unwrap();
        assert_eq!(sub.name(), "widget");
        assert_eq!(sub.kind().to_string(), "_https._tcp");
        assert_eq!(sub.to_string(), "_widget._sub._https._tcp");
        for bad in [
            "_https._tcp",
            "widget._sub._https._tcp",
            "_._sub._https._tcp",
            "_a.b._sub._https._tcp",
        ] {
            assert_eq!(bad.parse::<Subtype>(), Err(Invalid::Subtype), "{bad:?}");
        }
        assert_eq!(
            "_w._sub._https".parse::<Subtype>(),
            Err(Invalid::ServiceType)
        );
    }

    #[test]
    fn an_instance_name_is_readable_utf8_of_at_most_63_bytes() {
        assert_eq!(
            "Pumpe für Halle 3"
                .parse::<InstanceName>()
                .unwrap()
                .as_str(),
            "Pumpe für Halle 3"
        );
        assert!("a.b (2)".parse::<InstanceName>().is_ok());
        assert!("é".repeat(31).parse::<InstanceName>().is_ok());
        assert_eq!(
            "é".repeat(32).parse::<InstanceName>(),
            Err(Invalid::InstanceTooLong)
        );
        assert_eq!("".parse::<InstanceName>(), Err(Invalid::InstanceEmpty));
        assert_eq!(
            "line\nbreak".parse::<InstanceName>(),
            Err(Invalid::ControlCharacter)
        );
    }

    #[test]
    fn an_instance_name_compares_without_ascii_case_and_keeps_its_spelling() {
        let widget: InstanceName = "Widget Ä".parse().unwrap();
        let lower: InstanceName = "widget Ä".parse().unwrap();
        assert_eq!(widget, lower);
        assert_ne!(widget, "widget ä".parse().unwrap(), "only ASCII folds");
        assert_eq!(widget.cmp(&lower), std::cmp::Ordering::Equal);
        assert_eq!(
            std::collections::HashSet::from([widget.clone(), lower]).len(),
            1
        );
        assert_eq!(widget.to_string(), "Widget Ä");
    }

    #[test]
    fn txt_entries_come_from_pairs() {
        let txt = Txt::pairs([("product", "widget"), ("v", "1")]).unwrap();
        assert_eq!(
            txt,
            ["product=widget".parse().unwrap(), "v=1".parse().unwrap()]
        );
        assert_eq!(Txt::pairs([("", "x")]), Err(Invalid::TxtKey));
    }

    #[test]
    fn a_txt_entry_is_a_printable_key_and_255_bytes_in_all() {
        let txt: Txt = "product=widget=1".parse().unwrap();
        assert_eq!((txt.key(), txt.value()), ("product", "widget=1"));
        assert_eq!(txt.to_string(), "product=widget=1");
        assert_eq!("flag".parse::<Txt>().unwrap().value(), "");
        assert!(Txt::new("k", &"v".repeat(253)).is_ok());
        assert_eq!(Txt::new("k", &"v".repeat(254)), Err(Invalid::TxtTooLong));
        for key in ["", "ké", "a\tb"] {
            assert_eq!(Txt::new(key, "v"), Err(Invalid::TxtKey), "{key:?}");
        }
        assert_eq!("=v".parse::<Txt>(), Err(Invalid::TxtKey));
    }

    #[test]
    fn a_host_name_is_one_label_read_with_or_without_local() {
        for raw in ["widget", "widget.local", "widget.local."] {
            assert_eq!(
                raw.parse::<HostName>().unwrap().fqdn(),
                "widget.local",
                "{raw}"
            );
        }
        for bad in ["", "-widget", "widget-", "wid_get", "a.b", &"x".repeat(64)] {
            assert_eq!(bad.parse::<HostName>(), Err(Invalid::HostName), "{bad:?}");
        }
    }

    #[cfg(feature = "in-process")]
    #[test]
    fn the_nearest_host_name_replaces_what_a_label_cannot_hold() {
        assert_eq!(
            HostName::nearest("Alex's MacBook").unwrap().as_str(),
            "Alex-s-MacBook"
        );
        assert_eq!(
            HostName::nearest(&"x".repeat(70)).unwrap().as_str().len(),
            63
        );
        assert_eq!(HostName::nearest("__"), None);
    }
}
