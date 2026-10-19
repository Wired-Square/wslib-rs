//! DKIM key records (RFC 6376 §3.6.1, RFC 8301, RFC 8463).

mod key;

use crate::text::{first_of_each, tag_list, unwrap, version_value_fault};
use crate::{FaultCode, Parsed, SyntaxFault, Tag};

/// The tags of a DKIM key record. Tag names are case-sensitive (§3.2).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct DkimKeyRecord {
    pub tags: Vec<Tag>,
    /// `h=`: the hash algorithms the key may be used with.
    pub hash_algorithms: Option<Vec<String>>,
    /// `k=`, as written.
    pub key_type: Option<KeyType>,
    pub notes: Option<String>,
    /// `p=`, decoded; empty when the key is revoked.
    pub public_key: Option<Vec<u8>>,
    /// The modulus length of an RSA key.
    pub rsa_bits: Option<u32>,
    /// `s=`: the service types the key is for.
    pub service_types: Option<Vec<String>>,
    /// `t=`: the flags this crate knows; others are ignored.
    pub flags: Vec<KeyFlag>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum KeyType {
    #[default]
    Rsa,
    Ed25519,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum KeyFlag {
    /// `y`: the domain is testing DKIM.
    Testing,
    /// `s`: the `i=` domain must equal `d=`, not be a subdomain of it.
    Strict,
}

impl DkimKeyRecord {
    pub fn effective_key_type(&self) -> KeyType {
        self.key_type.unwrap_or_default()
    }

    /// An empty `p=`: the key has been revoked.
    pub fn is_revoked(&self) -> bool {
        self.public_key.as_ref().is_some_and(Vec::is_empty)
    }

    pub fn is_testing(&self) -> bool {
        self.flags.contains(&KeyFlag::Testing)
    }
}

impl Parsed<DkimKeyRecord> {
    /// A verifier ignores unknown tags; any other fault makes the whole
    /// record invalid (§3.2, §3.6.1).
    pub fn is_usable(&self) -> bool {
        self.faults.iter().all(|fault| fault.code.is_advisory())
    }
}

pub fn parse(input: &str) -> Parsed<DkimKeyRecord> {
    let (_, text) = unwrap(input);
    let mut faults = Vec::new();
    let all = tag_list(input, text, &mut faults);
    let mut record = DkimKeyRecord {
        tags: all.iter().map(|tag| tag.written(false)).collect(),
        ..DkimKeyRecord::default()
    };
    if let Some(index) = all.iter().position(|tag| tag.name == "v") {
        if index != 0 {
            faults.push(SyntaxFault::named(
                FaultCode::VersionNotFirst,
                all[index].span.clone(),
                "v",
            ));
        }
        faults.extend(version_value_fault(&all[index], "DKIM1"));
    }
    let tags = first_of_each(all, |a, b| a == b, &mut faults);
    let mut key_data = None;
    for tag in &tags {
        let list = || {
            tag.value
                .split(':')
                .map(|item| item.trim().to_owned())
                .collect::<Vec<_>>()
        };
        match tag.name {
            "v" => {}
            "h" => record.hash_algorithms = Some(list()),
            "k" => match tag.value.to_ascii_lowercase().as_str() {
                "rsa" => record.key_type = Some(KeyType::Rsa),
                "ed25519" => record.key_type = Some(KeyType::Ed25519),
                _ => faults.push(SyntaxFault::named(
                    FaultCode::UnknownKeyType,
                    tag.value_span.clone(),
                    "k",
                )),
            },
            "n" => record.notes = Some(tag.value.to_owned()),
            "p" => key_data = Some(tag),
            "s" => record.service_types = Some(list()),
            "t" => {
                record.flags = list()
                    .iter()
                    .filter_map(|flag| match flag.as_str() {
                        "y" => Some(KeyFlag::Testing),
                        "s" => Some(KeyFlag::Strict),
                        _ => None,
                    })
                    .collect();
            }
            name => faults.push(SyntaxFault::named(
                FaultCode::UnknownTag,
                tag.span.clone(),
                name,
            )),
        }
    }
    match key_data {
        None => faults.push(crate::text::missing(input, "p")),
        Some(tag) => match key::decode_base64(tag.value) {
            None => faults.push(SyntaxFault::named(
                FaultCode::InvalidBase64,
                tag.value_span.clone(),
                "p",
            )),
            Some(bytes) => {
                let unknown_type = faults
                    .iter()
                    .any(|fault| fault.code == FaultCode::UnknownKeyType);
                if !bytes.is_empty() && !unknown_type {
                    let valid = match record.effective_key_type() {
                        KeyType::Rsa => key::rsa_modulus_bits(&bytes)
                            .inspect(|&bits| record.rsa_bits = Some(bits))
                            .is_some(),
                        KeyType::Ed25519 => bytes.len() == 32,
                    };
                    if !valid {
                        faults.push(SyntaxFault::named(
                            FaultCode::InvalidKey,
                            tag.value_span.clone(),
                            "p",
                        ));
                    }
                }
                record.public_key = Some(bytes);
            }
        },
    }
    faults.sort_by_key(|fault| fault.span.start);
    Parsed { record, faults }
}

#[cfg(test)]
mod tests;
