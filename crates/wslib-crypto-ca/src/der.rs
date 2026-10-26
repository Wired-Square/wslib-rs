//! rcgen lays out each structure and encodes the parts it models; names and
//! keys are then copied in byte for byte and the result signed, since rcgen's
//! own name type cannot hold a repeated attribute or a multi-valued RDN.

use const_oid::ObjectIdentifier;
use rcgen::{CustomExtension, PublicKeyData, SignatureAlgorithm, SigningKey};
use wslib_crypto::Signer;
use wslib_crypto_x509::SubjectAltName;
use x509_parser::asn1_rs::{Any, FromDer};

use crate::Error;

pub(crate) const SEQUENCE: u8 = 0x30;

pub(crate) fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let len = content.len();
    if len < 0x80 {
        out.push(len as u8);
    } else {
        let bytes = len.to_be_bytes();
        let significant = &bytes[bytes.iter().take_while(|&&b| b == 0).count()..];
        out.push(0x80 | significant.len() as u8);
        out.extend_from_slice(significant);
    }
    out.extend_from_slice(content);
    out
}

pub(crate) fn oid(oid: ObjectIdentifier) -> Vec<u8> {
    tlv(0x06, oid.as_bytes())
}

/// The whole TLVs inside the SEQUENCE that `der` is.
pub(crate) fn elements(der: &[u8]) -> Result<Vec<&[u8]>, Error> {
    let malformed = || Error::Malformed("not a DER SEQUENCE".into());
    let (rest, outer) = Any::from_der(der).map_err(|_| malformed())?;
    if !rest.is_empty() || outer.tag() != x509_parser::asn1_rs::Tag::Sequence {
        return Err(malformed());
    }
    let mut remaining = outer.data;
    let mut out = Vec::new();
    while !remaining.is_empty() {
        let (after, _) = Any::from_der(remaining).map_err(|_| malformed())?;
        out.push(&remaining[..remaining.len() - after.len()]);
        remaining = after;
    }
    Ok(out)
}

/// What x509-parser read, provided it read every byte.
pub(crate) fn whole<T>(parsed: x509_parser::error::X509Result<'_, T>) -> Result<T, Error> {
    match parsed {
        Ok(([], value)) => Ok(value),
        Ok(_) => Err(Error::Malformed("trailing bytes".into())),
        Err(e) => Err(Error::Malformed(e.to_string())),
    }
}

pub(crate) fn extension(id: ObjectIdentifier, critical: bool, value: Vec<u8>) -> CustomExtension {
    let arcs: Vec<u64> = id.arcs().map(u64::from).collect();
    let mut extension = CustomExtension::from_oid_content(&arcs, value);
    extension.set_criticality(critical);
    extension
}

pub(crate) fn subject_alt_name(
    names: &[SubjectAltName],
    critical: bool,
) -> Result<CustomExtension, Error> {
    let general_names = names
        .iter()
        .map(general_name)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(extension(
        const_oid::db::rfc5280::ID_CE_SUBJECT_ALT_NAME,
        critical,
        tlv(SEQUENCE, &general_names.concat()),
    ))
}

pub(crate) fn general_name(name: &SubjectAltName) -> Result<Vec<u8>, Error> {
    let ia5 = |tag, value: &str| {
        if value.is_ascii() {
            Ok(tlv(tag, value.as_bytes()))
        } else {
            Err(Error::Name {
                name: value.to_string(),
                reason: "not ASCII",
            })
        }
    };
    match name {
        SubjectAltName::Email(email) => ia5(0x81, email),
        SubjectAltName::Dns(dns) => ia5(0x82, dns),
        SubjectAltName::Uri(uri) => ia5(0x86, uri),
        SubjectAltName::Ip(std::net::IpAddr::V4(ip)) => Ok(tlv(0x87, &ip.octets())),
        SubjectAltName::Ip(std::net::IpAddr::V6(ip)) => Ok(tlv(0x87, &ip.octets())),
    }
}

/// The signer's algorithm and public key for rcgen to lay out with, signing nothing.
pub(crate) struct Draft<'a>(pub &'a Signer);

impl PublicKeyData for Draft<'_> {
    fn der_bytes(&self) -> &[u8] {
        self.0.der_bytes()
    }

    fn algorithm(&self) -> &'static SignatureAlgorithm {
        PublicKeyData::algorithm(self.0)
    }
}

impl SigningKey for Draft<'_> {
    fn sign(&self, _: &[u8]) -> Result<Vec<u8>, rcgen::Error> {
        Ok(Vec::new())
    }
}

/// Replaces fields of `draft`'s signed part by position, then signs it with `signer`.
pub(crate) fn signed(
    signer: &Signer,
    draft: &[u8],
    fields: &[(usize, &[u8])],
) -> Result<Vec<u8>, Error> {
    let [body, algorithm, _] = elements(draft)?[..] else {
        return Err(Error::Encode(
            "rcgen's draft has an unexpected shape".into(),
        ));
    };
    let mut parts = elements(body)?;
    for &(position, field) in fields {
        parts[position] = field;
    }
    let body = tlv(SEQUENCE, &parts.concat());
    let signature = signer.sign(&body).map_err(encode)?;
    let signature = tlv(0x03, &[&[0][..], &signature].concat());
    Ok(tlv(SEQUENCE, &[&body[..], algorithm, &signature].concat()))
}

pub(crate) fn encode(e: rcgen::Error) -> Error {
    Error::Encode(e.to_string())
}

pub(crate) fn malformed(e: wslib_crypto_x509::Error) -> Error {
    Error::Malformed(e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn long_lengths_take_the_fewest_octets() {
        assert_eq!(tlv(0x04, &[7; 3])[..2], [0x04, 3]);
        assert_eq!(tlv(0x04, &[7; 0x80])[..3], [0x04, 0x81, 0x80]);
        assert_eq!(tlv(0x04, &[7; 0x1234])[..4], [0x04, 0x82, 0x12, 0x34]);
    }

    #[test]
    fn elements_are_whole_tlvs() {
        let der = tlv(SEQUENCE, &[tlv(0x02, &[1]), tlv(0x04, &[0; 200])].concat());
        let parts = elements(&der).unwrap();
        assert_eq!(parts, [&tlv(0x02, &[1])[..], &tlv(0x04, &[0; 200])[..]]);
        assert!(elements(&der[..der.len() - 1]).is_err());
        assert!(elements(&tlv(0x31, &[])).is_err());
    }
}
