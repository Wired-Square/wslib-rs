use std::fmt;

/// The outcome of one DNS query.
pub type Lookup<T> = Result<Answer<T>, LookupError>;

/// The records a query returned, never empty, and the smallest TTL among them.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Answer<T> {
    pub records: Vec<T>,
    pub ttl: Option<u32>,
}

impl<T> Answer<T> {
    /// An answer with no TTL, as a test or a synthesised result has.
    pub fn new(records: Vec<T>) -> Self {
        Self { records, ttl: None }
    }

    pub fn map<U>(self, f: impl FnMut(T) -> U) -> Answer<U> {
        Answer {
            records: self.records.into_iter().map(f).collect(),
            ttl: self.ttl,
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
    Ptr,
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
            Self::Ptr => "PTR",
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
                r#""timeout""#
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
