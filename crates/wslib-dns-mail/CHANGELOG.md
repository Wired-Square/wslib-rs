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
- Canonical `Display` on every record, `DmarcBuilder`, and the editors
  `dmarc::with_aggregate` and `spf::with_includes`.
