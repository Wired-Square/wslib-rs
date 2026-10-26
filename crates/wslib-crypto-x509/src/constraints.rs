use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;

use x509_parser::asn1_rs::{Any, Class, FromDer, Tag};

use crate::Error;
use crate::inspect::hex;
use crate::names::is_dns_name;

/// RFC 5280 4.2.1.10 name constraints: a name must fall in a permitted subtree, when there are any of its kind, and in no excluded one.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NameConstraints {
    pub permitted: Vec<NameSubtree>,
    pub excluded: Vec<NameSubtree>,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum NameSubtree {
    /// The name and every name below it; with a leading dot, only the names below it.
    Dns(String),
    Ip(IpSubtree),
    /// A subtree of another kind, or with a minimum or maximum, as its whole GeneralSubtree DER.
    Other(Vec<u8>),
}

/// A network: an address with no bits set past its prefix.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct IpSubtree {
    address: IpAddr,
    prefix_length: u8,
}

impl IpSubtree {
    /// Refuses a prefix longer than the address, or host bits set past it.
    pub fn new(address: IpAddr, prefix_length: u8) -> Result<Self, Error> {
        let invalid = |reason| Error::Name {
            name: format!("{address}/{prefix_length}"),
            reason,
        };
        if prefix_length > width(address) {
            return Err(invalid("the prefix is longer than the address"));
        }
        if bits(address) & !mask(width(address), prefix_length) != 0 {
            return Err(invalid("host bits are set past the prefix"));
        }
        Ok(Self {
            address,
            prefix_length,
        })
    }

    pub fn address(&self) -> IpAddr {
        self.address
    }

    pub fn prefix_length(&self) -> u8 {
        self.prefix_length
    }

    /// The address then its mask, as an iPAddress subtree carries them.
    pub fn octets(&self) -> Vec<u8> {
        let mask = mask(width(self.address), self.prefix_length);
        match self.address {
            IpAddr::V4(address) => [address.octets(), (mask as u32).to_be_bytes()].concat(),
            IpAddr::V6(address) => [address.octets(), mask.to_be_bytes()].concat(),
        }
    }

    fn from_octets(octets: &[u8]) -> Option<Self> {
        let (address, mask_bits) = match octets.len() {
            8 => (
                IpAddr::from(<[u8; 4]>::try_from(&octets[..4]).ok()?),
                u128::from(u32::from_be_bytes(octets[4..].try_into().ok()?)),
            ),
            32 => (
                IpAddr::from(<[u8; 16]>::try_from(&octets[..16]).ok()?),
                u128::from_be_bytes(octets[16..].try_into().ok()?),
            ),
            _ => return None,
        };
        let width = width(address);
        let prefix_length = (mask_bits << (128 - u32::from(width))).leading_ones() as u8;
        if mask_bits != mask(width, prefix_length) {
            return None;
        }
        Self::new(address, prefix_length).ok()
    }
}

fn width(address: IpAddr) -> u8 {
    if address.is_ipv4() { 32 } else { 128 }
}

fn bits(address: IpAddr) -> u128 {
    match address {
        IpAddr::V4(address) => u128::from(u32::from(address)),
        IpAddr::V6(address) => u128::from(address),
    }
}

fn mask(width: u8, prefix_length: u8) -> u128 {
    let ones = u128::MAX
        .checked_shl(128 - u32::from(prefix_length))
        .unwrap_or(0);
    ones >> (128 - width)
}

impl fmt::Display for IpSubtree {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.address, self.prefix_length)
    }
}

/// A DNS subtree as its name, an address one as `10.0.0.0/8`, and another as `#` and its DER in hex.
impl fmt::Display for NameSubtree {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Dns(name) => f.write_str(name),
            Self::Ip(network) => network.fmt(f),
            Self::Other(der) => write!(f, "#{}", hex(der)),
        }
    }
}

/// An address and prefix length, as `10.0.0.0/8` or `fd00::/8`, or else a DNS name with an optional leading dot.
impl FromStr for NameSubtree {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Error> {
        let v = s.trim();
        let invalid = |reason| Error::Name {
            name: v.to_string(),
            reason,
        };
        if let Some((address, prefix_length)) = v.split_once('/') {
            let address = address
                .parse()
                .map_err(|_| invalid("not an address before the prefix length"))?;
            let prefix_length = prefix_length
                .parse()
                .map_err(|_| invalid("not a prefix length"))?;
            return IpSubtree::new(address, prefix_length).map(Self::Ip);
        }
        if is_dns_name(v.strip_prefix('.').unwrap_or(v), false) {
            Ok(Self::Dns(v.to_string()))
        } else {
            Err(invalid("not a DNS name or an address with a prefix length"))
        }
    }
}

pub(crate) fn read(value: &[u8]) -> Option<NameConstraints> {
    let [(outer, _)] = &tlvs(value)?[..] else {
        return None;
    };
    if outer.tag() != Tag::Sequence {
        return None;
    }
    let mut constraints = NameConstraints::default();
    for (part, _) in tlvs(outer.data)? {
        let subtrees = match (part.class(), part.tag()) {
            (Class::ContextSpecific, Tag(0)) => &mut constraints.permitted,
            (Class::ContextSpecific, Tag(1)) => &mut constraints.excluded,
            _ => return None,
        };
        for (subtree, der) in tlvs(part.data)? {
            if subtree.tag() != Tag::Sequence {
                return None;
            }
            subtrees.push(match &tlvs(subtree.data)?[..] {
                [(base, _)] => base_of(base).unwrap_or_else(|| NameSubtree::Other(der.to_vec())),
                _ => NameSubtree::Other(der.to_vec()),
            });
        }
    }
    Some(constraints)
}

fn base_of(base: &Any<'_>) -> Option<NameSubtree> {
    if base.class() != Class::ContextSpecific || base.header.is_constructed() {
        return None;
    }
    match base.tag() {
        Tag(2) if base.data.is_ascii() => Some(NameSubtree::Dns(
            String::from_utf8(base.data.to_vec()).ok()?,
        )),
        Tag(7) => IpSubtree::from_octets(base.data).map(NameSubtree::Ip),
        _ => None,
    }
}

/// Each TLV in `der` with its whole encoding.
fn tlvs(mut der: &[u8]) -> Option<Vec<(Any<'_>, &[u8])>> {
    let mut out = Vec::new();
    while !der.is_empty() {
        let (rest, any) = Any::from_der(der).ok()?;
        out.push((any, &der[..der.len() - rest.len()]));
        der = rest;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn subtree(s: &str) -> NameSubtree {
        s.parse().unwrap()
    }

    #[test]
    fn an_ip_subtree_is_a_network_with_no_host_bits() {
        assert_eq!(subtree("10.20.0.0/16").to_string(), "10.20.0.0/16");
        assert_eq!(subtree("0.0.0.0/0").to_string(), "0.0.0.0/0");
        assert_eq!(subtree("::/0").to_string(), "::/0");
        assert_eq!(subtree("192.0.2.7/32").to_string(), "192.0.2.7/32");
        assert_eq!(subtree("fd00:20::/32").to_string(), "fd00:20::/32");
        for refused in [
            "10.20.0.1/16",
            "10.0.0.0/33",
            "::1/127",
            "::/129",
            "fd00::/x",
        ] {
            assert!(refused.parse::<NameSubtree>().is_err(), "{refused}");
        }
    }

    #[test]
    fn an_ip_subtree_carries_its_address_then_its_mask() {
        let NameSubtree::Ip(v4) = subtree("10.20.0.0/16") else {
            unreachable!()
        };
        assert_eq!(v4.octets(), [10, 20, 0, 0, 255, 255, 0, 0]);
        let NameSubtree::Ip(v6) = subtree("fd00:20::/33") else {
            unreachable!()
        };
        let mut want = [0u8; 32];
        want[..4].copy_from_slice(&[0xfd, 0, 0, 0x20]);
        want[16..21].copy_from_slice(&[0xff, 0xff, 0xff, 0xff, 0x80]);
        assert_eq!(v6.octets(), want);
        assert_eq!(IpSubtree::from_octets(&want), Some(v6));
    }

    #[test]
    fn a_mask_with_a_gap_or_host_bits_reads_as_no_ip_subtree() {
        assert_eq!(IpSubtree::from_octets(&[10, 0, 0, 0, 255, 0, 255, 0]), None);
        assert_eq!(IpSubtree::from_octets(&[10, 0, 0, 1, 255, 0, 0, 0]), None);
        assert_eq!(IpSubtree::from_octets(&[10, 0, 0, 0, 255]), None);
    }

    #[test]
    fn a_dns_subtree_is_a_name_with_an_optional_leading_dot() {
        assert_eq!(
            subtree("example.com"),
            NameSubtree::Dns("example.com".into())
        );
        assert_eq!(
            subtree(".example.net"),
            NameSubtree::Dns(".example.net".into())
        );
        for refused in ["", "*.example.com", "a b.example", "..example.com"] {
            assert!(refused.parse::<NameSubtree>().is_err(), "{refused:?}");
        }
    }

    #[test]
    fn a_subtree_with_a_maximum_or_of_another_kind_reads_as_its_der() {
        let with_maximum = [0x30, 0x08, 0x82, 0x03, b'a', b'.', b'b', 0x81, 0x01, 0x01];
        let email = [0x30, 0x05, 0x81, 0x03, b'a', b'@', b'b'];
        let value = [&[0x30, 0x13, 0xa0, 0x11][..], &with_maximum, &email].concat();
        assert_eq!(
            read(&value),
            Some(NameConstraints {
                permitted: vec![
                    NameSubtree::Other(with_maximum.to_vec()),
                    NameSubtree::Other(email.to_vec())
                ],
                excluded: vec![],
            })
        );
        assert_eq!(read(&value[..value.len() - 1]), None);
    }
}
