# wslib-dns

DNS lookups that say why they came back empty. NXDOMAIN, NODATA, SERVFAIL,
REFUSED and a timeout are all different answers here, so a caller never reports
"no record" when it couldn't actually tell.

```rust
use wslib_dns::{HickoryOptions, HickoryResolver, LookupError, Resolver};

let dns = HickoryResolver::from_system(HickoryOptions::default())?;
match dns.txt("_dmarc.example.com").await {
    Ok(answer) => { /* answer.records, answer.ttl */ }
    Err(error) if error.is_absent() => { /* NXDOMAIN or NODATA: nothing published */ }
    Err(LookupError::Timeout) => { /* unknown, not absent */ }
    Err(_) => { /* SERVFAIL, REFUSED, ... */ }
}
```

## What's here

- **`Resolver`**: an async trait with one method per record type (`txt`, `a`,
  `aaaa`, `mx`, `ns`, `cname`, `ptr`), plus `ip` (A and AAAA together) and
  `cname_chain` (follows aliases, detects loops, capped at
  `DEFAULT_MAX_CNAME_HOPS`). Futures are `Send`, and there's no global state.
  Returned names are normalised: lowercase, no trailing dot. The root (a null
  MX's exchange) stays `.`.
- **`Txt`** keeps the raw character-strings. `joined()` concatenates them with
  no separator and no escaping, as SPF and DMARC require (RFC 7208 §3.3).
- **`HickoryResolver`** (feature `hickory`): hickory 0.26 with its TTL cache.
  `from_system` reads `/etc/resolv.conf` (the VPC resolver on Lambda) and falls
  back to Cloudflare. `from_nameservers` takes explicit addresses. Queries are
  sent fully qualified, so search domains never apply.
- **`FakeResolver`** (feature `testing`): an in-memory zone for tests, in this
  crate and in yours. Unknown names answer NXDOMAIN, and known names without
  the type answer NODATA. Any name and type can be set to fail, and queries are
  counted per name and type.
- **`LoggingResolver`**: wraps any resolver and records each query, its answers
  in presentation form or its error, and how long it took.
- **Names**: `normalise`, `validate_hostname` (RFC 1035/1123) and
  `validate_service_name` (which also allows `_`), `to_ascii`/`to_unicode`
  (IDNA, UTS #46), `public_suffix` and `registrable_domain` (the Public Suffix
  List, ICANN and private sections, compiled in), and `reverse_name` for PTR
  and DNSBL names.

## Features

| Feature   | Adds                                                      |
| --------- | --------------------------------------------------------- |
| `hickory` | `HickoryResolver`, over hickory-resolver with tokio       |
| `testing` | `FakeResolver`                                            |
| `serde`   | `Serialize`/`Deserialize` on every public type            |

None are on by default. No rustls provider is pulled in: hickory is built
without TLS transports.

The Public Suffix List comes from the `psl` crate, which publishes the list as
it changes. `cargo update -p psl` picks up a newer list.

## Known gaps

- No DNSSEC: the AD bit and validation status aren't reported.
