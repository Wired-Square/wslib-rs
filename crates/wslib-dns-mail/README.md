# wslib-dns-mail

Email-authentication records published in DNS: SPF, DMARC, DKIM keys, BIMI,
MTA-STS and TLS-RPT. Built on [`wslib-dns`](../wslib-dns).

This crate looks at what a domain *publishes*. It doesn't verify DKIM
signatures on messages or evaluate DMARC for a message.

## Parsers

Each parser is lenient. It reads past faults, so every tag and term can still
be shown, and returns a `Parsed<T>`:

```rust
use wslib_dns_mail::{FaultCode, dmarc};

let input = "v=DMARC1; p=reject; pct=200; rua=mailto:dmarc@example.com";
let parsed = dmarc::parse(input);
assert_eq!(parsed.record.effective_percent(), 100);
assert_eq!(parsed.faults[0].code, FaultCode::InvalidTagValue);
assert_eq!(&input[parsed.faults[0].span.clone()], "200");
assert!(parsed.is_usable());
```

A `SyntaxFault` carries a stable `FaultCode`, a byte span into the input (so a
UI can highlight the bad token), and the tag or mechanism it's about. Each
record type answers "would a receiver use this?" with `is_usable()`, derived
from the faults; it's the one definition of valid. Some faults are advisory
(`FaultCode::is_advisory`): the record is out of spec, but receivers still use
it. Examples are `v=dmarc1` in the wrong case, a DMARC `p` that isn't directly
after `v`, a tab between SPF terms, and unknown tags.

"Usable" describes what receivers do, not what the RFC says. `v=dmarc1` is
usable because reports still arrive for it, yet RFC 7489 §6.3 says a
conforming receiver ignores the whole record. So an advisory fault can still
be out of spec, and the checks report it that way: as a `Spec` finding, with
the risk spelled out in its detail. Inputs are unwrapped first:
a UTF-8 BOM, outer whitespace and stray wrapping quotes are removed, and spans
still point into the original text.

| Module     | Record                                     | Notes |
| ---------- | ------------------------------------------ | ----- |
| `spf`      | RFC 7208                                   | Typed `Mechanism`s and qualifiers, `redirect=`/`exp=`, dual CIDR, the §7 macro grammar. Unknown modifiers are kept, not faulted. |
| `dmarc`    | RFC 7489 and DMARCbis (`np`, `psd`, `t`)   | Literal values plus `effective_*` with the RFC defaults applied. The §6.6.3 fallback to `p=none` when `rua` is valid is `policy_treated_as_none()`. |
| `dkim`     | RFC 6376 §3.6.1, RFC 8301, RFC 8463        | Case-sensitive tags. Decodes `p=` and reports `rsa_bits`. An empty `p=` means revoked. |
| `bimi`     | draft-brand-indicators-for-message-identification | `l=` and `a=` must be `https:` or empty; an empty `l=` means declined. |
| `mta_sts`  | RFC 8461                                   | The TXT record, and the policy file with `mx` pattern matching. |
| `tls_rpt`  | RFC 8460                                   | `rua=` with `mailto:` and `https:` URIs. |

`is_spf`, `is_dmarc`, `is_bimi`, `is_mta_sts` and `is_tls_rpt` tell whether a
TXT string is that kind of record at all.

## Discovery

`discover` finds records through any `wslib_dns::Resolver`, so production uses
hickory and tests use `FakeResolver`. Every result says how it was found:

- `RecordSet<T>` holds every matching TXT record at a name, parsed, so several
  SPF records are all there to report. It also keeps the lookup error, and
  separates `is_absent()` (known to have none) from `failure()` (couldn't
  tell).
- `spf`, `mta_sts` (`_mta-sts.`) and `tls_rpt` (`_smtp._tls.`) return a
  `RecordSet`.
- `dmarc` walks from the domain to its organisational domain (RFC 7489, the
  default) or up the tree (DMARCbis, `DmarcDiscoveryMode::TreeWalk`).
  Several records or a failed lookup stop the walk without a policy. The
  result says whether the policy is the domain's own or inherited from an
  ancestor, and whether `p`, `sp` or `np` applies.
- `dmarc_report_authorisation` is the RFC 7489 §7.1 check: whether an
  external `rua`/`ruf` destination publishes
  `<policy-domain>._report._dmarc.<destination>`.
- `dkim` follows the selector's CNAME chain and exposes the terminal name.
  `probe_dkim` tries a list of selectors, such as `COMMON_SELECTORS`,
  concurrently.
- `mx` inspects every exchange: aliases, addresses, the PTR of each address,
  and forward-confirmed reverse DNS. It recognises null MX (RFC 7505) and IP
  literals.
- `bimi` looks at `<selector>._bimi.` on the domain, then on its
  organisational domain.
- `dnsbl` tells `Listed`, `NotListed`, `QueryBlocked` and `Failed` apart. A
  zone that answers outside `127.0.0.2`–`127` is refusing the query, as
  Spamhaus does for cloud resolvers. That isn't a clean result.

Discovery futures are `Send`, and concurrency within a call needs no runtime.

## Building and editing records

- `Display` on every record renders it canonically: `v=spf1` and single-spaced
  terms, or tag-list tags joined by `; `.
- `dmarc::DmarcBuilder` composes a record with its tags in a fixed order.
- `dmarc::with_aggregate(record, uri)` adds a `rua=` destination, and
  `spf::with_includes(record, domains)` adds `include:`s before the `all`.
  Both keep the other tags and terms, in order and as written, and don't add
  anything already there.

## Features

| Feature | Adds                                           |
| ------- | ---------------------------------------------- |
| `serde` | `Serialize`/`Deserialize` on every public type |

None are on by default. The parsers need no async runtime.
