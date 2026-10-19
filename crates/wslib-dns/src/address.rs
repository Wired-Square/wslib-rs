use std::net::IpAddr;

/// Whether an address is globally routable: outside every IANA
/// special-purpose range, so not private, loopback, link-local, shared,
/// multicast, reserved or for documentation.
pub fn is_global(address: IpAddr) -> bool {
    let bits = if address.is_ipv4() { 32 } else { 128 };
    is_global_network(address, bits)
}

/// Whether every address in `network`/`prefix` is globally routable.
pub fn is_global_network(network: IpAddr, prefix: u8) -> bool {
    let (start, end) = bounds(network, prefix);
    let special = if network.is_ipv4() {
        SPECIAL_IPV4
    } else {
        SPECIAL_IPV6
    };
    !special.iter().any(|&(range, range_prefix)| {
        let range = range
            .parse::<IpAddr>()
            .expect("the special ranges are addresses");
        let (s, e) = bounds(range, range_prefix);
        start <= e && s <= end
    })
}

fn bounds(network: IpAddr, prefix: u8) -> (u128, u128) {
    let (start, bits) = match network {
        IpAddr::V4(v4) => (u128::from(u32::from(v4)), 32u32),
        IpAddr::V6(v6) => (u128::from(v6), 128),
    };
    let host = bits - u32::from(prefix).min(bits);
    let mask = if host == 128 {
        u128::MAX
    } else {
        (1u128 << host) - 1
    };
    (start & !mask, start | mask)
}

/// IANA special-purpose IPv4 ranges (RFC 6890 and its updates).
const SPECIAL_IPV4: &[(&str, u8)] = &[
    ("0.0.0.0", 8),
    ("10.0.0.0", 8),
    ("100.64.0.0", 10),
    ("127.0.0.0", 8),
    ("169.254.0.0", 16),
    ("172.16.0.0", 12),
    ("192.0.0.0", 24),
    ("192.0.2.0", 24),
    ("192.88.99.0", 24),
    ("192.168.0.0", 16),
    ("198.18.0.0", 15),
    ("198.51.100.0", 24),
    ("203.0.113.0", 24),
    ("224.0.0.0", 4),
    ("240.0.0.0", 4),
];

/// IANA special-purpose IPv6 ranges that aren't globally routable.
const SPECIAL_IPV6: &[(&str, u8)] = &[
    ("::", 127),
    ("::ffff:0:0", 96),
    ("64:ff9b:1::", 48),
    ("100::", 64),
    ("2001:db8::", 32),
    ("fc00::", 7),
    ("fe80::", 10),
    ("ff00::", 8),
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
            "0.0.0.0",
            "::1",
            "fe80::1",
            "fd00::1",
            "::ffff:127.0.0.1",
            "2001:db8::1",
        ] {
            assert!(!is_global(address.parse().unwrap()), "{address}");
        }
    }

    #[test]
    fn a_network_is_global_only_if_none_of_it_is_special() {
        assert!(!is_global_network("0.0.0.0".parse().unwrap(), 0));
        assert!(!is_global_network("10.0.0.0".parse().unwrap(), 8));
        assert!(!is_global_network("fd00::".parse().unwrap(), 8));
    }
}
