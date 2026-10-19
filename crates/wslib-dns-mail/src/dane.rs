//! DANE TLSA records for SMTP (RFC 6698, RFC 7672).

use wslib_dns::Tlsa;

/// A TLSA record's fields given meaning, and what's wrong with them.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct DaneRecord {
    pub usage: TlsaUsage,
    pub selector: TlsaSelector,
    pub matching: TlsaMatching,
    pub data: Vec<u8>,
    pub faults: Vec<DaneFault>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum TlsaUsage {
    /// `0`, PKIX-TA: a CA, also checked against the system's roots.
    PkixTa,
    /// `1`, PKIX-EE: the server's certificate, also PKIX-checked.
    PkixEe,
    /// `2`, DANE-TA: a trust anchor of the domain's own.
    DaneTa,
    /// `3`, DANE-EE: the server's certificate or key itself.
    DaneEe,
    Unknown(u8),
}

impl TlsaUsage {
    /// RFC 7672 §3.1.3: SMTP clients don't do PKIX, so usages 0 and 1 don't
    /// work for SMTP and shouldn't be published for it.
    pub fn is_pkix(self) -> bool {
        matches!(self, Self::PkixTa | Self::PkixEe)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum TlsaSelector {
    /// `0`: the whole certificate.
    Certificate,
    /// `1`: the SubjectPublicKeyInfo.
    PublicKey,
    Unknown(u8),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum TlsaMatching {
    /// `0`: the selected data in full.
    Full,
    Sha256,
    Sha512,
    Unknown(u8),
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case", tag = "kind"))]
#[non_exhaustive]
pub enum DaneFault {
    UnknownUsage {
        value: u8,
    },
    UnknownSelector {
        value: u8,
    },
    UnknownMatching {
        value: u8,
    },
    /// A digest of the wrong length for its matching type.
    DigestLength {
        expected: usize,
        actual: usize,
    },
    NoData,
}

pub fn parse_tlsa(record: &Tlsa) -> DaneRecord {
    let mut faults = Vec::new();
    let usage = match record.usage {
        0 => TlsaUsage::PkixTa,
        1 => TlsaUsage::PkixEe,
        2 => TlsaUsage::DaneTa,
        3 => TlsaUsage::DaneEe,
        value => {
            faults.push(DaneFault::UnknownUsage { value });
            TlsaUsage::Unknown(value)
        }
    };
    let selector = match record.selector {
        0 => TlsaSelector::Certificate,
        1 => TlsaSelector::PublicKey,
        value => {
            faults.push(DaneFault::UnknownSelector { value });
            TlsaSelector::Unknown(value)
        }
    };
    let matching = match record.matching {
        0 => TlsaMatching::Full,
        1 => TlsaMatching::Sha256,
        2 => TlsaMatching::Sha512,
        value => {
            faults.push(DaneFault::UnknownMatching { value });
            TlsaMatching::Unknown(value)
        }
    };
    let expected = match matching {
        TlsaMatching::Sha256 => Some(32),
        TlsaMatching::Sha512 => Some(64),
        _ => None,
    };
    if record.data.is_empty() {
        faults.push(DaneFault::NoData);
    } else if let Some(expected) = expected.filter(|&expected| expected != record.data.len()) {
        faults.push(DaneFault::DigestLength {
            expected,
            actual: record.data.len(),
        });
    }
    DaneRecord {
        usage,
        selector,
        matching,
        data: record.data.clone(),
        faults,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tlsa(usage: u8, selector: u8, matching: u8, data: Vec<u8>) -> Tlsa {
        Tlsa {
            usage,
            selector,
            matching,
            data,
        }
    }

    #[test]
    fn the_usual_dane_ee_spki_sha256_record() {
        let record = parse_tlsa(&tlsa(3, 1, 1, vec![0xab; 32]));
        assert_eq!(
            (record.usage, record.selector, record.matching),
            (
                TlsaUsage::DaneEe,
                TlsaSelector::PublicKey,
                TlsaMatching::Sha256
            )
        );
        assert!(record.faults.is_empty());
        assert!(!record.usage.is_pkix());
        assert!(parse_tlsa(&tlsa(1, 0, 0, vec![1, 2, 3])).usage.is_pkix());
    }

    #[test]
    fn unknown_values_and_bad_digests_are_faults() {
        assert_eq!(
            parse_tlsa(&tlsa(4, 2, 3, vec![1])).faults,
            [
                DaneFault::UnknownUsage { value: 4 },
                DaneFault::UnknownSelector { value: 2 },
                DaneFault::UnknownMatching { value: 3 }
            ]
        );
        assert_eq!(
            parse_tlsa(&tlsa(3, 1, 2, vec![0; 32])).faults,
            [DaneFault::DigestLength {
                expected: 64,
                actual: 32
            }]
        );
        assert_eq!(
            parse_tlsa(&tlsa(3, 1, 1, Vec::new())).faults,
            [DaneFault::NoData]
        );
    }
}
