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

pub(crate) const PRIVATE_IPV4: &[&str] = &[
    "10.0.0.0/8",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.168.0.0/16",
];

pub(crate) const PRIVATE_IPV6: &[&str] = &["::1/128", "fc00::/7", "fe80::/10"];
