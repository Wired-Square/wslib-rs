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
  `&R` and `Arc<R>` are resolvers too.
  Returned names are normalised: lowercase, no trailing dot. The root (a null
  MX's exchange) stays `.`.
- **`Txt`** keeps the raw character-strings. `joined()` concatenates them with
  no separator and no escaping, as SPF and DMARC require (RFC 7208 §3.3).
- **`txt::split`** and **`txt::quote`**: the other way, for publishing. A long
  value split into character-strings of at most 255 octets, never inside a
  character, and those written as a zone file (and Route 53) takes them:
  `"a" "b"`, with `"` and `\` escaped. No feature needed.
- **`HickoryResolver`** (feature `hickory`): hickory 0.26 with its TTL cache.
  `from_system` reads `/etc/resolv.conf` (the VPC resolver on Lambda) and falls
  back to Cloudflare. `from_nameservers` takes explicit socket addresses.
  Queries are sent fully qualified, so search domains never apply. EDNS0 is
  always on, whatever resolv.conf says, so large TXT sets fit in one UDP
  answer.
- **Internationalised names** are converted to A-labels before every query, in
  every resolver here, so `txt("bücher.example")` asks for
  `xn--bcher-kva.example`.
- **`FakeResolver`** (feature `testing`): an in-memory zone for tests, in this
  crate and in yours. Unknown names answer NXDOMAIN, and known names without
  the type answer NODATA. Any name and type can be set to fail, and queries are
  counted per name and type.
- **`LoggingResolver`**: wraps any resolver and records each query, its answers
  in presentation form or its error, and how long it took.
- **`BudgetResolver`**: wraps any resolver and stops sending queries at a
  deadline or after a set number. The queries it holds back answer
  `LookupError::NotSent`, so a caller can tell work that was cut short from a
  lookup that failed. A query already in flight runs to the inner resolver's
  own timeout × attempts.
- **`Answer::canonical_name`**: the name the records belong to, when the
  queried name is an alias for it, taken from the CNAME chain in the answer.
  You can tell an alias apart without a separate CNAME query.
- **DNSSEC** (feature `dnssec-ring` or `dnssec-aws-lc-rs`, plus
  `HickoryOptions::validate`): hickory validates from the root's trust
  anchor and each `Answer` carries a `DnssecStatus`. A bogus answer is
  `LookupError::Bogus`. Without validation, `Answer::dnssec` is `None` and
  nothing changes. `tlsa` and `ds` look up TLSA and DS records.
- **Names**: `normalise`, `validate_hostname` (RFC 1035/1123) and
  `validate_service_name` (which also allows `_`), `to_ascii`/`to_unicode`
  (IDNA, UTS #46), `public_suffix` and `registrable_domain` (the Public Suffix
  List, ICANN and private sections, compiled in), and `reverse_name` for PTR
  and DNSBL names.

## Features

| Feature   | Adds                                                      |
| --------- | --------------------------------------------------------- |
| `hickory` | `HickoryResolver`, over hickory-resolver with tokio       |
| `dnssec-ring` | `HickoryOptions::validate`, with ring                 |
| `dnssec-aws-lc-rs` | The same, with aws-lc-rs                         |
| `testing` | `FakeResolver`                                            |
| `serde`   | `Serialize`/`Deserialize` on every public type            |

None are on by default. No rustls provider is pulled in: hickory is built
without TLS transports.

The Public Suffix List comes from the `psl` crate, which publishes the list as
it changes. `cargo update -p psl` picks up a newer list.

## Known gaps

- Hickory can't set the CD bit, so behind an upstream resolver that
  validates (most public ones, and the VPC resolver if Route 53 validation
  is on), a bogus zone comes back SERVFAIL, not `Bogus`. Only a
  non-validating upstream lets hickory see the bad signatures. Whether the
  Route 53 VPC resolver passes RRSIGs through is unconfirmed.
- An upstream that strips RRSIGs makes signed zones look Insecure.
- Secure denial of existence isn't reported: NXDOMAIN and NODATA carry no
  status.
