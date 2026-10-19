# Changelog

## Unreleased

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
- MX inspection takes an exchange's alias from its address answer rather
  than a separate CNAME query, which some providers answer SERVFAIL;
  `MxHost::cname_error` is gone. `mx_exchange_no_address` is a Warning while
  another MX host resolves.
- Canonical `Display` on every record, `DmarcBuilder`, and the editors
  `dmarc::with_aggregate` and `spf::with_includes`.
