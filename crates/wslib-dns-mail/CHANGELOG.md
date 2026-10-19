# Changelog

## 0.4.0

- **Breaking:** needs wslib-dns 0.2. `discover::RecordSet`, `MxDiscovery`
  and `MxHost` are `#[non_exhaustive]`.
- DNSSEC, through a validating resolver (wslib-dns `dnssec-ring` or
  `dnssec-aws-lc-rs`): `RecordSet::dnssec`, `MxDiscovery::dnssec` and
  `DomainReport::dnssec`: Bogus if any lookup at or under the domain was,
  else the worst of its MX and SPF answers, else Indeterminate.
  Findings `dnssec_status`, `dnssec_bogus` (any lookup that came back
  bogus), `dnssec_unsupported_resolver` (the root's NS answer isn't Secure,
  so the domain's status is Indeterminate) and `dnssec_suspected_bogus` (a
  SERVFAIL inside a zone whose parent publishes DS records).
- DANE for SMTP (RFC 7672): with a validating resolver, `discover::mx` looks
  up TLSA at `_25._tcp.<exchange>` for each MX host (`MxHost::tlsa`), and
  `dane::parse_tlsa` gives the records meaning. Findings
  `dane_tlsa_insecure`, `dane_mx_insecure`, `dane_tlsa_syntax` and
  `dane_tlsa_usage_discouraged`. An Indeterminate TLSA or MX answer gives
  no DANE status finding, since that's the resolver's limit. DANE alongside
  MTA-STS isn't flagged (RFC 8461 §2).

## 0.3.0

- **Breaking:** `check::Detail`, `discover::PolicyFetch`, `LogoFetch` and the
  new `CertificateFetch` are `#[non_exhaustive]`; a `match` on them needs a
  wildcard arm. Later variants are then not breaking.
- `bimi::verify_vmc` checks a BIMI record's mark certificate chain
  (VMC or CMC) and reports every problem (`VmcProblem`):
  - the chain to caller-supplied `VmcTrustAnchors`, with the caller's
    signature algorithms, since no crypto provider is built in;
  - the BIMI purpose as the only extended key usage;
  - the validity dates, against a caller-supplied time;
  - a subject name covering the domain or `<selector>._bimi.` name;
  - `subject:markType`, giving `MarkCertificateKind`;
  - the embedded logo, decoded, inflated, checked against SVG Tiny PS and
    compared by SHA-256 with the `l=` logo;
  - at least one Certificate Transparency timestamp.
- `discover::bimi_certificate` (feature `http`) fetches the `a=` chain with
  the logo fetch's protections. `check_domain` verifies it when given
  `CheckOptions::bimi_vmc`, reporting `DomainReport::{bimi_certificate,
  bimi_vmc}`.
- Findings `bimi_vmc_absent` (a logo with no `a=`), `bimi_vmc_unreachable`,
  `bimi_vmc_invalid`, `bimi_vmc_logo_mismatch` and `bimi_vmc_missing_sct`.
- `Display` with neutral wording on `FetchFailure`, `SvgRule`,
  `SvgViolation` and `VmcProblem`.

## 0.2.0

- **Breaking:** `CheckOptions` and `DomainReport` are `#[non_exhaustive]`, so
  they can no longer be built with a struct literal outside the crate. Start
  from `CheckOptions::default()` and set fields. Later additions to either
  are then not breaking.
- `bimi::validate_logo` checks an SVG logo against SVG Tiny PS and reports
  every violation with a byte offset (`SvgRule`): UTF-8 and well-formed XML,
  no DOCTYPE or entities (never expanded), an `<svg>` root in the SVG
  namespace with `version="1.2"`, `baseProfile="tiny-ps"`, no `x`/`y` and a
  square `viewBox`, a non-empty `<title>` directly under the root, no
  prohibited elements, no event handlers, and no external references in
  links, `url()` or `@import`, in `<style>` text as well as attributes.
- `discover::bimi_logo` (feature `http`) fetches an `l=` URL with the same
  protections as the MTA-STS fetch, vetting the URL's own host or IP literal.
  It refuses non-`https` URLs and credentials (`FetchFailure::InvalidUrl`),
  caps the body at 64 KiB while streaming, and inflates `.svgz` or
  gzip-encoded logos up to 256 KiB (`TooLarge { decompressed }`,
  `Undecodable`).
- Findings `bimi_logo_unreachable`, `bimi_logo_invalid`,
  `bimi_logo_too_large` (over the BIMI Group's 32 KiB) and
  `bimi_logo_content_type`. `check_domain` fetches the logo when given
  `CheckOptions::bimi_http`, and reports it as `DomainReport::bimi_logo`.
- The MTA-STS and logo fetches share one vetted request path. It always
  sends a user agent, since some hosts refuse a request without one:
  `DEFAULT_USER_AGENT` unless `HttpClients::user_agent` replaces it. It also
  sends an `Accept` header for what it wants.

## 0.1.0

- Lenient parsers returning `Parsed<T>` with byte-span `SyntaxFault`s, and an
  `is_usable()` per record type: `spf` (RFC 7208, including macros and dual
  CIDR), `dmarc` (RFC 7489 and the DMARCbis tags), `dkim` key records (with
  the RSA key size), `bimi`, `mta_sts` (TXT record and policy file) and
  `tls_rpt`.
- `discover`: SPF, DMARC (RFC 7489 or the DMARCbis tree walk, with which of
  `p`, `sp` or `np` applies), the RFC 7489 §7.1 external report
  authorisation, DKIM by selector or by probing common selectors, MX with
  address, alias and forward-confirmed reverse DNS inspection, BIMI, MTA-STS
  and TLS-RPT records, and DNSBL lookups that tell a refused query from a
  clean one.
- `spf::tree::walk`: the SPF record and everything it reaches, with RFC 7208
  §4.6.4 accounting (lookups, void lookups, where each limit was crossed,
  `mx` name counts, loops) beyond the limits up to a ceiling. `flatten` gives
  the netblocks with their paths, duplicates, overlaps and totals, and
  `targets` gives every include and redirect target.
- `spf::tree::walk_record` walks a record that isn't published, such as a
  draft. Flattened totals count only `pass` netblocks, and
  `Netblock::is_global` tells whether a block avoids private and reserved
  space. An include or redirect target whose TXT answer holds no SPF record
  is no longer counted as a void lookup.
- `spf::check_host`: RFC 7208 §4 evaluation with macro expansion and `exp=`.
- `check`: a findings catalogue (stable code, Spec/Practice/Observation,
  severity, RFC reference, typed detail) for SPF, DMARC, DKIM, MX and DNSBL,
  BIMI, MTA-STS and TLS-RPT. Each family can run on its own, and
  `check_domain` runs them all concurrently under a deadline and a query
  budget, with an optional query log. Checks the bounds cut short are named in
  one `incomplete` finding.
- `RecordSet::others` keeps the TXT strings at a name that aren't the record
  kind looked for, so a DMARC record with `v` out of place can be reported.
- An unknown DKIM `k=` no longer has its key read as RSA.
- Feature `http`: `discover::mta_sts_policy` fetches the MTA-STS policy file
  per RFC 8461 §3.3 (no redirects, `200` and `text/plain` only, 64 KiB cap).
  The policy host is resolved through the crate's `Resolver`, refused if any
  address isn't globally routable, and connected to only at those addresses.
  `check_domain` fetches it when given `CheckOptions::mta_sts_http`. Failures
  are a typed `FetchFailure`, which `PolicyFetch::Unreachable` and the
  `mta_sts_policy_unreachable` detail carry.
- MX inspection takes an exchange's alias from its address answer rather
  than a separate CNAME query, which some providers answer SERVFAIL;
  `MxHost::cname_error` is gone. `mx_exchange_no_address` is a Warning while
  another MX host resolves.
- Canonical `Display` on every record, `DmarcBuilder`, and the editors
  `dmarc::with_aggregate` and `spf::with_includes`.
