# Changelog

## Unreleased

- Lenient parsers returning `Parsed<T>` with byte-span `SyntaxFault`s, and an
  `is_usable()` per record type: `spf` (RFC 7208, including macros and dual
  CIDR), `dmarc` (RFC 7489 and the DMARCbis tags), `dkim` key records (with
  the RSA key size), `bimi`, `mta_sts` (TXT record and policy file) and
  `tls_rpt`.
- Canonical `Display` on every record, `DmarcBuilder`, and the editors
  `dmarc::with_aggregate` and `spf::with_includes`.
