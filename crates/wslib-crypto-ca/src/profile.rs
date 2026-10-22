use std::net::IpAddr;

use const_oid::ObjectIdentifier;
use const_oid::db::rfc5280::{
    ANY_EXTENDED_KEY_USAGE, ID_AD_CA_ISSUERS, ID_CE_AUTHORITY_KEY_IDENTIFIER,
    ID_CE_BASIC_CONSTRAINTS, ID_CE_CRL_DISTRIBUTION_POINTS, ID_CE_EXT_KEY_USAGE, ID_CE_KEY_USAGE,
    ID_CE_SUBJECT_KEY_IDENTIFIER, ID_KP_CLIENT_AUTH, ID_KP_CODE_SIGNING, ID_KP_EMAIL_PROTECTION,
    ID_KP_OCSP_SIGNING, ID_KP_SERVER_AUTH, ID_KP_TIME_STAMPING, ID_PE_AUTHORITY_INFO_ACCESS,
};
use rcgen::CustomExtension;
use wslib_crypto_x509::{ExtendedKeyUsage, KeyUsage, SubjectAltName};

use crate::Error;
use crate::der::{self, SEQUENCE, extension, tlv};

/// An extension's value and whether it is marked critical.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Extension<T> {
    pub value: T,
    pub critical: bool,
}

impl<T> Extension<T> {
    pub fn critical(value: T) -> Self {
        Self {
            value,
            critical: true,
        }
    }

    pub fn non_critical(value: T) -> Self {
        Self {
            value,
            critical: false,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BasicConstraints {
    /// `CA:FALSE`, stated.
    EndEntity,
    Authority {
        path_length: Option<u8>,
    },
}

/// Which subject alternative names a certificate carries.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum SanPolicy {
    #[default]
    Omit,
    /// The request's names.
    Requested,
    /// The common name (an address when it parses as one, else a DNS name), then the request's names not already there.
    CommonNameAndRequested,
}

/// What an issued certificate says beyond its subject, key and key identifiers.
///
/// The caller builds one per kind of certificate, starting from
/// `Profile::default()`, which carries no extensions at all.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Profile {
    pub basic_constraints: Option<Extension<BasicConstraints>>,
    pub key_usage: Option<Extension<Vec<KeyUsage>>>,
    pub extended_key_usage: Option<Extension<Vec<ExtendedKeyUsage>>>,
    pub names: SanPolicy,
    /// CRL distribution point URLs, all in one distribution point.
    pub crl_distribution_points: Vec<String>,
    /// Authority information access URLs for the issuer's certificate.
    pub ca_issuers: Vec<String>,
}

impl Profile {
    pub(crate) fn is_authority(&self) -> bool {
        matches!(
            self.basic_constraints,
            Some(Extension {
                value: BasicConstraints::Authority { .. },
                ..
            })
        )
    }

    /// The extensions in the order OpenSSL writes them, so that its text and a diff of two certificates line up.
    pub(crate) fn extensions(
        &self,
        subject_key_identifier: &[u8],
        authority_key_identifier: &[u8],
        subject: &Requested<'_>,
    ) -> Result<Vec<CustomExtension>, Error> {
        let mut out = vec![
            extension(
                ID_CE_SUBJECT_KEY_IDENTIFIER,
                false,
                tlv(0x04, subject_key_identifier),
            ),
            extension(
                ID_CE_AUTHORITY_KEY_IDENTIFIER,
                false,
                tlv(SEQUENCE, &tlv(0x80, authority_key_identifier)),
            ),
        ];
        if let Some(Extension { value, critical }) = &self.basic_constraints {
            out.push(extension(
                ID_CE_BASIC_CONSTRAINTS,
                *critical,
                basic_constraints(*value),
            ));
        }
        if let Some(Extension { value, critical }) = &self.key_usage {
            out.push(extension(ID_CE_KEY_USAGE, *critical, key_usage(value)?));
        }
        if let Some(Extension { value, critical }) = &self.extended_key_usage {
            out.push(extension(
                ID_CE_EXT_KEY_USAGE,
                *critical,
                extended_key_usage(value)?,
            ));
        }
        let names = self.names(subject);
        if !names.is_empty() {
            // RFC 5280 4.2.1.6: critical when the subject is empty.
            out.push(der::subject_alt_name(&names, subject.name_is_empty)?);
        }
        if !self.crl_distribution_points.is_empty() {
            let full_name = self
                .crl_distribution_points
                .iter()
                .map(|url| uri(url))
                .collect::<Result<Vec<_>, _>>()?
                .concat();
            let point = tlv(SEQUENCE, &tlv(0xa0, &tlv(0xa0, &full_name)));
            out.push(extension(
                ID_CE_CRL_DISTRIBUTION_POINTS,
                false,
                tlv(SEQUENCE, &point),
            ));
        }
        if !self.ca_issuers.is_empty() {
            let descriptions = self
                .ca_issuers
                .iter()
                .map(|url| {
                    Ok(tlv(
                        SEQUENCE,
                        &[der::oid(ID_AD_CA_ISSUERS), uri(url)?].concat(),
                    ))
                })
                .collect::<Result<Vec<_>, Error>>()?;
            out.push(extension(
                ID_PE_AUTHORITY_INFO_ACCESS,
                false,
                tlv(SEQUENCE, &descriptions.concat()),
            ));
        }
        Ok(out)
    }

    fn names(&self, subject: &Requested<'_>) -> Vec<SubjectAltName> {
        let common_name = subject
            .common_name
            .filter(|_| self.names == SanPolicy::CommonNameAndRequested)
            .map(|name| match name.parse::<IpAddr>() {
                Ok(ip) => SubjectAltName::Ip(ip),
                Err(_) => SubjectAltName::Dns(name.to_string()),
            });
        let requested = match self.names {
            SanPolicy::Omit => &[][..],
            _ => subject.names,
        };
        let mut names: Vec<SubjectAltName> = common_name.into_iter().collect();
        for name in requested {
            if !names.contains(name) {
                names.push(name.clone());
            }
        }
        names
    }
}

/// What the subject brings to its certificate's extensions.
pub(crate) struct Requested<'a> {
    pub common_name: Option<&'a str>,
    pub names: &'a [SubjectAltName],
    pub name_is_empty: bool,
}

fn basic_constraints(value: BasicConstraints) -> Vec<u8> {
    let content = match value {
        BasicConstraints::EndEntity => Vec::new(),
        BasicConstraints::Authority { path_length } => {
            let mut content = tlv(0x01, &[0xff]);
            if let Some(length) = path_length {
                let integer = if length & 0x80 == 0 {
                    vec![length]
                } else {
                    vec![0, length]
                };
                content.extend(tlv(0x02, &integer));
            }
            content
        }
    };
    tlv(SEQUENCE, &content)
}

/// A DER BIT STRING with bit 0 for digital signature, trailing zero bits dropped.
fn key_usage(usages: &[KeyUsage]) -> Result<Vec<u8>, Error> {
    let bits = usages
        .iter()
        .fold(0u16, |bits, usage| bits | 0x8000 >> key_usage_bit(*usage));
    if bits == 0 {
        return Err(Error::EmptyExtension("key usage"));
    }
    let used = 16 - bits.trailing_zeros() as usize;
    let octets = used.div_ceil(8);
    let unused = (octets * 8 - used) as u8;
    Ok(tlv(
        0x03,
        &[&[unused][..], &bits.to_be_bytes()[..octets]].concat(),
    ))
}

fn key_usage_bit(usage: KeyUsage) -> u16 {
    match usage {
        KeyUsage::DigitalSignature => 0,
        KeyUsage::NonRepudiation => 1,
        KeyUsage::KeyEncipherment => 2,
        KeyUsage::DataEncipherment => 3,
        KeyUsage::KeyAgreement => 4,
        KeyUsage::KeyCertSign => 5,
        KeyUsage::CrlSign => 6,
        KeyUsage::EncipherOnly => 7,
        KeyUsage::DecipherOnly => 8,
    }
}

fn extended_key_usage(usages: &[ExtendedKeyUsage]) -> Result<Vec<u8>, Error> {
    if usages.is_empty() {
        return Err(Error::EmptyExtension("extended key usage"));
    }
    let oids = usages
        .iter()
        .map(|usage| purpose(usage).map(der::oid))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(tlv(SEQUENCE, &oids.concat()))
}

fn purpose(usage: &ExtendedKeyUsage) -> Result<ObjectIdentifier, Error> {
    Ok(match usage {
        ExtendedKeyUsage::Any => ANY_EXTENDED_KEY_USAGE,
        ExtendedKeyUsage::ServerAuth => ID_KP_SERVER_AUTH,
        ExtendedKeyUsage::ClientAuth => ID_KP_CLIENT_AUTH,
        ExtendedKeyUsage::CodeSigning => ID_KP_CODE_SIGNING,
        ExtendedKeyUsage::EmailProtection => ID_KP_EMAIL_PROTECTION,
        ExtendedKeyUsage::TimeStamping => ID_KP_TIME_STAMPING,
        ExtendedKeyUsage::OcspSigning => ID_KP_OCSP_SIGNING,
        ExtendedKeyUsage::Other(dotted) => {
            ObjectIdentifier::new(dotted).map_err(|_| Error::Name {
                name: dotted.clone(),
                reason: "not a dotted OID",
            })?
        }
    })
}

fn uri(url: &str) -> Result<Vec<u8>, Error> {
    der::general_name(&SubjectAltName::Uri(url.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_usage_bits_are_as_short_as_der_wants() {
        let encoded = |usages: &[KeyUsage]| key_usage(usages).unwrap();
        assert_eq!(encoded(&[KeyUsage::DigitalSignature]), [3, 2, 7, 0x80]);
        assert_eq!(
            encoded(&[KeyUsage::DigitalSignature, KeyUsage::KeyEncipherment]),
            [3, 2, 5, 0xa0]
        );
        assert_eq!(
            encoded(&[KeyUsage::KeyCertSign, KeyUsage::CrlSign]),
            [3, 2, 1, 0x06]
        );
        assert_eq!(encoded(&[KeyUsage::DecipherOnly]), [3, 3, 7, 0, 0x80]);
        assert!(key_usage(&[]).is_err());
    }

    #[test]
    fn a_path_length_is_a_positive_integer() {
        let encoded = |path_length| basic_constraints(BasicConstraints::Authority { path_length });
        assert_eq!(encoded(None), [0x30, 3, 1, 1, 0xff]);
        assert_eq!(encoded(Some(0)), [0x30, 6, 1, 1, 0xff, 2, 1, 0]);
        assert_eq!(encoded(Some(200)), [0x30, 7, 1, 1, 0xff, 2, 2, 0, 200]);
        assert_eq!(basic_constraints(BasicConstraints::EndEntity), [0x30, 0]);
    }

    #[test]
    fn the_common_name_leads_the_requested_names_once() {
        let requested: Vec<SubjectAltName> = ["www.example.com", "host.example.com"]
            .iter()
            .map(|name| name.parse().unwrap())
            .collect();
        let subject = |common_name| Requested {
            common_name: Some(common_name),
            names: &requested,
            name_is_empty: false,
        };
        let names = |policy, common_name| {
            Profile {
                names: policy,
                ..Profile::default()
            }
            .names(&subject(common_name))
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
        };
        assert_eq!(
            names(SanPolicy::CommonNameAndRequested, "host.example.com"),
            ["host.example.com", "www.example.com"]
        );
        assert_eq!(
            names(SanPolicy::CommonNameAndRequested, "192.168.1.20"),
            ["192.168.1.20", "www.example.com", "host.example.com"]
        );
        assert_eq!(
            names(SanPolicy::Requested, "host.example.com"),
            ["www.example.com", "host.example.com"]
        );
        assert!(names(SanPolicy::Omit, "host.example.com").is_empty());
    }
}
