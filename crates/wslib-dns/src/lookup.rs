use std::fmt;

/// The outcome of one DNS query.
pub type Lookup<T> = Result<Answer<T>, LookupError>;

/// The records a query returned, never empty, and the smallest TTL among them.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub struct Answer<T> {
    pub records: Vec<T>,
    pub ttl: Option<u32>,
    /// The name the records belong to, when the queried name is an alias for
    /// it: the end of the CNAME chain the answer came with.
    pub canonical_name: Option<String>,
    /// How DNSSEC validation judged the records; set only by a validating
    /// resolver.
    pub dnssec: Option<DnssecStatus>,
}

/// A validating resolver's verdict on an RRset (RFC 4035 §4.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum DnssecStatus {
    /// The signatures failed, or records the chain says exist are missing.
    Bogus,
    /// The resolver couldn't get the DNSSEC records to decide.
    Indeterminate,
    /// The zone isn't signed: there is provably no chain of trust.
    Insecure,
    /// Signed, with a chain of trust to the root.
    Secure,
}

impl<T> Answer<T> {
    /// An answer with no TTL or alias, as a test or a synthesised result has.
    pub fn new(records: Vec<T>) -> Self {
        Self {
            records,
            ttl: None,
            canonical_name: None,
            dnssec: None,
        }
    }

    pub fn map<U>(self, f: impl FnMut(T) -> U) -> Answer<U> {
        Answer {
            records: self.records.into_iter().map(f).collect(),
            ttl: self.ttl,
            canonical_name: self.canonical_name,
            dnssec: self.dnssec,
        }
    }
}

/// Why a query returned no records.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[non_exhaustive]
pub enum LookupError {
    /// The name does not exist.
    #[cfg_attr(feature = "serde", serde(rename = "nxdomain"))]
    NxDomain,
    /// The name exists but has no records of the queried type.
    #[cfg_attr(feature = "serde", serde(rename = "nodata"))]
    NoData,
    #[cfg_attr(feature = "serde", serde(rename = "servfail"))]
    ServFail,
    Refused,
    Timeout,
    /// Never sent: the caller's deadline or query budget had run out.
    NotSent,
    /// DNSSEC validation failed: the answer can't be trusted, whatever it
    /// said.
    Bogus,
    /// A failure the backend could not classify, in its own words.
    Other(String),
}

impl LookupError {
    /// The name or the record is absent: an answer, not a failure to get one.
    pub fn is_absent(&self) -> bool {
        matches!(self, Self::NxDomain | Self::NoData)
    }
}

impl fmt::Display for LookupError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NxDomain => f.write_str("name does not exist (NXDOMAIN)"),
            Self::NoData => f.write_str("no records of that type (NODATA)"),
            Self::ServFail => f.write_str("server failure (SERVFAIL)"),
            Self::Refused => f.write_str("query refused (REFUSED)"),
            Self::Timeout => f.write_str("query timed out"),
            Self::NotSent => f.write_str("query not sent: deadline or query budget exhausted"),
            Self::Bogus => f.write_str("DNSSEC validation failed (bogus)"),
            Self::Other(message) => f.write_str(message),
        }
    }
}

impl std::error::Error for LookupError {}

/// The record types the [`Resolver`](crate::Resolver) queries.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "UPPERCASE"))]
#[non_exhaustive]
pub enum RecordType {
    A,
    Aaaa,
    Cname,
    Mx,
    Ns,
    Ds,
    Ptr,
    Tlsa,
    Txt,
}

impl fmt::Display for RecordType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::A => "A",
            Self::Aaaa => "AAAA",
            Self::Cname => "CNAME",
            Self::Mx => "MX",
            Self::Ns => "NS",
            Self::Ds => "DS",
            Self::Ptr => "PTR",
            Self::Tlsa => "TLSA",
            Self::Txt => "TXT",
        })
    }
}

/// One TXT record, as the character-strings it was published in.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Txt {
    pub strings: Vec<Vec<u8>>,
}

impl Txt {
    pub fn new(strings: Vec<Vec<u8>>) -> Self {
        Self { strings }
    }

    /// The strings concatenated with no separator and no escaping (RFC 7208
    /// §3.3), with invalid UTF-8 replaced.
    pub fn joined(&self) -> String {
        String::from_utf8_lossy(&self.strings.concat()).into_owned()
    }
}

impl From<&str> for Txt {
    fn from(text: &str) -> Self {
        Self::new(vec![text.as_bytes().to_vec()])
    }
}

/// One DS record (RFC 4034 §5): the parent's pointer to a signed child zone.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Ds {
    pub key_tag: u16,
    pub algorithm: u8,
    pub digest_type: u8,
    pub digest: Vec<u8>,
}

/// One TLSA record (RFC 6698), as its four fields; meaning is the caller's.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Tlsa {
    pub usage: u8,
    pub selector: u8,
    pub matching: u8,
    pub data: Vec<u8>,
}

/// One MX record. A null MX (RFC 7505) has the exchange `.`.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Mx {
    pub preference: u16,
    pub exchange: String,
}

impl Mx {
    pub fn new(preference: u16, exchange: &str) -> Self {
        Self {
            preference,
            exchange: crate::normalise(exchange),
        }
    }
}

#[cfg(all(test, feature = "serde"))]
mod tests {
    use super::*;

    #[test]
    fn serialised_names_are_the_contract() {
        let names: Vec<String> = [
            LookupError::NxDomain,
            LookupError::NoData,
            LookupError::ServFail,
            LookupError::Refused,
            LookupError::Timeout,
            LookupError::NotSent,
            LookupError::Bogus,
        ]
        .iter()
        .map(|error| serde_json::to_string(error).unwrap())
        .collect();
        assert_eq!(
            names,
            [
                r#""nxdomain""#,
                r#""nodata""#,
                r#""servfail""#,
                r#""refused""#,
                r#""timeout""#,
                r#""not_sent""#,
                r#""bogus""#
            ]
        );
        assert_eq!(
            serde_json::to_string(&LookupError::Other("x".into())).unwrap(),
            r#"{"other":"x"}"#
        );
        assert_eq!(
            serde_json::to_string(&RecordType::Aaaa).unwrap(),
            r#""AAAA""#
        );
    }
}
