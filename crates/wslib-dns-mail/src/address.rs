//! Which address space a network or address belongs to.

use std::net::IpAddr;

/// The host bits of a `bits`-wide address under `prefix`.
pub(crate) fn host_mask(bits: u8, prefix: u8) -> u128 {
    let host = u32::from(bits - prefix.min(bits));
    if host == 128 {
        u128::MAX
    } else {
        (1u128 << host) - 1
    }
}

/// Whether a network is IPv6, and its first and last address.
pub(crate) fn range(cidr: &str) -> Option<(bool, u128, u128)> {
    let (address, prefix) = cidr.split_once('/')?;
    let prefix: u8 = prefix.parse().ok()?;
    let (is_ipv6, start, bits) = match address.parse::<IpAddr>().ok()? {
        IpAddr::V4(v4) => (false, u128::from(u32::from(v4)), 32),
        IpAddr::V6(v6) => (true, u128::from(v6), 128),
    };
    Some((is_ipv6, start, start | host_mask(bits, prefix)))
}

/// Whether a network shares any address with a network in the list for its
/// family.
pub(crate) fn overlaps(cidr: &str, ipv4: &[&str], ipv6: &[&str]) -> bool {
    let Some((is_ipv6, start, end)) = range(cidr) else {
        return false;
    };
    let networks = if is_ipv6 { ipv6 } else { ipv4 };
    networks
        .iter()
        .filter_map(|network| range(network))
        .any(|(_, s, e)| start <= e && s <= end)
}

#[cfg(any(test, feature = "http"))]
/// Whether an address is globally routable: outside every IANA
/// special-purpose range.
pub(crate) fn is_global(address: IpAddr) -> bool {
    let bits = if address.is_ipv4() { 32 } else { 128 };
    !overlaps(&format!("{address}/{bits}"), SPECIAL_IPV4, SPECIAL_IPV6)
}

pub(crate) const PRIVATE_IPV4: &[&str] = &[
    "10.0.0.0/8",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.168.0.0/16",
];

pub(crate) const PRIVATE_IPV6: &[&str] = &["::1/128", "fc00::/7", "fe80::/10"];

/// IANA special-purpose IPv4 ranges (RFC 6890 and its updates).
pub(crate) const SPECIAL_IPV4: &[&str] = &[
    "0.0.0.0/8",
    "10.0.0.0/8",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.0.0.0/24",
    "192.0.2.0/24",
    "192.88.99.0/24",
    "192.168.0.0/16",
    "198.18.0.0/15",
    "198.51.100.0/24",
    "203.0.113.0/24",
    "224.0.0.0/4",
    "240.0.0.0/4",
];

/// IANA special-purpose IPv6 ranges that aren't globally routable.
pub(crate) const SPECIAL_IPV6: &[&str] = &[
    "::/127",
    "::ffff:0:0/96",
    "64:ff9b:1::/48",
    "100::/64",
    "2001:db8::/32",
    "fc00::/7",
    "fe80::/10",
    "ff00::/8",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_and_reserved_addresses_are_not_global() {
        for address in [
            "127.0.0.1",
            "10.0.3.7",
            "169.254.169.254",
            "100.64.0.1",
            "192.0.2.1",
            "::1",
            "fe80::1",
            "fd00::1",
            "::ffff:127.0.0.1",
        ] {
            assert!(!is_global(address.parse().unwrap()), "{address}");
        }
    }
}
