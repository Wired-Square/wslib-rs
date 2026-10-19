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
  ancestor, and whether `p`, `sp` or `np` applies. `np` is for a name with
  no A, AAAA or MX (RFC 9091 §2.7). If that can't be told, `applies` is
  `None` and `existence_error` says why.
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
- `mta_sts_policy` (feature `http`) fetches
  `https://mta-sts.<domain>/.well-known/mta-sts.txt` following RFC 8461 §3.3:
  no redirects, `200` and `text/plain` only, and at most 64 KiB. A failure is
  a typed `FetchFailure`.

  It's safe to point at a domain anyone supplies. It resolves the policy host
  through your `Resolver` and refuses, without connecting, if any address
  isn't globally routable (`NonGlobalAddress`). Otherwise it connects only to
  the addresses it checked, so DNS rebinding can't redirect it into a private
  network or to `169.254.169.254`. `HttpClients` makes the
  `reqwest::ClientBuilder` it starts from, which is where your TLS provider
  and timeouts go. Every fetch sends a user agent, because some hosts refuse
  a request without one. It's `DEFAULT_USER_AGENT` unless
  `HttpClients::user_agent` sets another. Don't configure a proxy: a proxy
  resolves the host itself.
- `dnsbl` tells `Listed`, `NotListed`, `QueryBlocked` and `Failed` apart. A
  zone that answers outside `127.0.0.2`–`127` is refusing the query, as
  Spamhaus does for cloud resolvers. That isn't a clean result.

Discovery futures are `Send`, and concurrency within a call needs no runtime.

## SPF evaluation

- `spf::tree::walk` builds an `SpfTree` (`walk_record` does the same from a
  draft record that isn't published): the record, every `include:` and
  applicable `redirect=` it reaches, and the result of each `a`, `mx` and
  `exists` lookup, in evaluation order. `Accounting` gives the §4.6.4 cost of
  evaluating it when nothing matches:
  - DNS-querying terms and void lookups;
  - the term where each limit was crossed, with the domains leading to it;
  - any `mx` with more than ten names;
  - loops.
  The walk goes past the RFC limits to report the real count, up to
  `WalkLimits` (50 lookups, depth 12 by default). `redirect=` is ignored
  beside `all`, as §6.1 says. Terms whose target needs a message to expand,
  such as `exists:%{i}…` and `ptr`, are counted but not looked up.
- `SpfTree::flatten` lists every netblock with the path that produced it, its
  qualifier, and whether it was resolved from `a` or `mx` (`dynamic`). It also
  gives the duplicates and overlaps across all qualifiers. Its totals, IPv4
  addresses (each counted once) and IPv6 networks, count only `pass` blocks.
  `Netblock::is_global` tells whether a block avoids private and reserved
  space.
- `SpfTree::targets` lists every `include:` and `redirect=` target with its
  record.
- `spf::check_host(resolver, ip, helo, sender)` is the full RFC 7208 §4
  evaluation: macros (§7), `exp=` explanations, and the lookup, void and
  name limits. It returns the result, the term that decided it (through any
  `include:`s), and why it was a `temperror`, `permerror` or `none`.

## Checks

`check` turns what was found into findings: data, not prose.

```rust
pub struct Finding {
    pub code: FindingCode,   // stable, snake_case, #[non_exhaustive]
    pub kind: Kind,          // Spec | Practice | Observation
    pub severity: Severity,  // Error | Warning | Info
    pub subject: String,     // the DNS name or record it's about
    pub reference: Cow<'static, str>, // e.g. "RFC 7208 §4.6.4"
    pub detail: Detail,      // typed: the fault and its span, counts, paths, …
}
```

`FindingCode::ALL` lists the catalogue, and each code carries a default kind,
severity and reference. `Spec` means a MUST is broken. `Practice` means the
record is in spec but inadvisable. `Observation` is a fact about the domain
(an inherited DMARC policy) or about the check itself (`lookup_failed`,
`incomplete`). There's no product posture: `dmarc_policy_none` is `Info`, and
how much it matters is the consumer's call. `Display` gives neutral wording.

Advisory parser faults map to `Spec` findings. `v=dmarc1` is usable, because
receivers accept it, and is still `dmarc_version_noncanonical`, Spec/Error,
with the risk in its detail.

Each family runs on its own: `check_spf`, `check_dmarc` (including the §7.1
report authorisation), `check_dkim`, `check_mx` (with DNSBL zones), plus the
pure `bimi_findings` and `mta_sts_findings`. Each `*_findings` function also
works on results a caller already holds.

`check_domain(resolver, domain, &CheckOptions)` runs them all concurrently.
With `http` and `mta_sts_http`, it also fetches the MTA-STS policy. That
gives the policy findings and the check of MX coverage, and the policy host's
lookup counts towards the query budget.
It's bounded by `deadline` and `max_queries` (10 s and 200 by default), and
can keep a query log. A query the bounds stopped is never a `lookup_failed`.
The checks it cut short are named in a single `incomplete` finding instead.
The deadline only stops new queries. One already in flight can run up to the
resolver's timeout × attempts past it: 4 s with `HickoryOptions::default()`.

## DNSSEC and DANE

With a validating resolver (`Resolver::validates`), `check_domain` reports
the domain's DNSSEC status in `DomainReport::dnssec` and a `dnssec_status`
finding: Bogus if any lookup at or under the domain was, else the worst of
its MX and SPF answers, else Indeterminate. Any lookup that came back bogus
is `dnssec_bogus`. One query, the root's NS records, tells whether the
resolver gets signatures at all: if that answer isn't Secure, the status is
Indeterminate and `dnssec_unsupported_resolver` says why. Behind an upstream
that validates, a bogus zone answers SERVFAIL (see `wslib-dns`), so a
SERVFAIL inside a zone whose parent publishes DS records is flagged as
`dnssec_suspected_bogus`, with those DS records.

`discover::mx` also looks up each MX host's TLSA records at
`_25._tcp.<exchange>` when the resolver validates. They count only from a
Secure answer reached through a Secure MX answer (RFC 7672 §2.2), hence
`dane_tlsa_insecure` and `dane_mx_insecure` for an Insecure answer (an
Indeterminate one is the resolver's problem, not the domain's);
`dane_tlsa_syntax` and `dane_tlsa_usage_discouraged` (PKIX usages 0 and 1)
check the records themselves. Nothing connects to port 25, so the records
aren't compared with the servers' certificates.

## BIMI logos

`bimi::validate_logo(svg)` checks an uncompressed SVG against the SVG Tiny PS
profile mailbox providers enforce and reports every violation, each with its
rule (`SvgRule`), a byte offset and a detail. It needs no `http` and no
runtime, so it also works on logos a caller already holds. Entities are
never expanded.

`discover::bimi_logo` (feature `http`) fetches a record's `l=` URL with the
MTA-STS fetch's protections. The URL's host can be anything, so it's
resolved and vetted, or vetted directly if it's an IP literal, before any
connection. A `.svgz` or gzip-encoded logo is inflated, with a cap on both
the compressed and the inflated size.

## Logo geometry

`bimi::measure_logo(svg)` (feature `render`) measures what the BIMI Group's
guidance asks of a mark: centred, inside the circle that mailbox providers
crop it to, on a solid background. It reports the offset of the marks'
bounding box from the viewBox's centre, how far they reach past the inscribed
circle (a full-viewBox background is left out of both, since the crop is
meant to cut it), and whether one is there at all. `<text>` can't be
measured without its font, so a logo with text gets only the background
judged. `check_domain` measures a fetched logo and raises
`bimi_logo_off_centre`, `bimi_logo_crop_risk` and
`bimi_logo_transparent_background` against `CheckOptions::bimi_render`.
These are Practice findings: receivers don't reject on them.

## Mark certificates

`bimi::verify_vmc(pem, domain, selector, logo, &VmcOptions)` verifies the PEM
chain a BIMI record's `a=` names, following draft-fetch-validation-vmc-wchuang
and the BIMI Group's Mark Certificate Requirements. It checks the chain, the
BIMI-only extended key usage, the dates, the subject names, the mark type
(VMC or CMC), the embedded logo (checked, and compared with `l=`) and the
Certificate Transparency timestamps, and reports every problem. No roots are
built in: `VmcTrustAnchors::from_pem` takes the caller's, and the signature
algorithms come from the caller's rustls provider, so this crate pulls in
none. SCT signatures aren't verified, only their presence.

Production trust anchors are the roots of the CAs the BIMI Group lists as
qualified to issue mark certificates (its Mark Certificate Issuer
Information page), and mailbox providers may trust a different set. Choosing
and refreshing them is the caller's job. Anchoring on the last certificate of
a fetched chain proves the checks work, but it proves no trust: anyone can
publish a chain that ends in a root they made.

`discover::bimi_certificate` (feature `http`) fetches the chain with the logo
fetch's protections.

## Building and editing records

- `Display` on every record renders it canonically: `v=spf1` and single-spaced
  terms, or tag-list tags joined by `; `.
- `dmarc::DmarcBuilder` composes a record with its tags in a fixed order.
- `dmarc::with_aggregate(record, uri)` adds a `rua=` destination, and
  `spf::with_includes(record, domains)` adds `include:`s before the `all`.
  Both keep the other tags and terms, in order and as written, and don't add
  anything already there.

## Features

| Feature | Adds                                                         |
| ------- | ------------------------------------------------------------ |
| `serde` | `Serialize`/`Deserialize` on every public type               |
| `http`  | The MTA-STS and BIMI logo fetches, `CheckOptions::{mta_sts_http, bimi_http}` |
| `render` | `bimi::measure_logo` and the logo geometry findings, over usvg |

None are on by default. The parsers need no async runtime. `http` uses
reqwest with rustls and no crypto provider; the application installs one, as
for every wslib crate.

## Known gaps

- Mark certificates: revocation (CRLs) isn't checked, and SCT signatures
  aren't verified against a CT log list.
- Logo geometry doesn't measure `<text>`, and it doesn't apply clip paths or
  masks, so a clipped logo can measure larger than it renders. Colours
  aren't checked.
- DANE: TLSA records aren't matched against the MX hosts' certificates,
  which needs an outbound SMTP connection.
- DNSSEC: bogus zones behind a validating upstream are only suspected, and
  secure denial of existence isn't reported (see `wslib-dns`). The suspicion
  asks only for the registrable domain's DS, so it misses a signed delegated
  subzone.
