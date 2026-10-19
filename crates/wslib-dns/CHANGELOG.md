# Changelog

## Unreleased

- `Resolver`: one query per record type (TXT, A, AAAA, MX, NS, CNAME, PTR),
  each answering a `Lookup` that keeps NXDOMAIN, NODATA, SERVFAIL, REFUSED and
  a timeout apart. Provided `ip` (A and AAAA together) and `cname_chain`
  (loop-detecting, hop-capped).
- `HickoryResolver` (feature `hickory`, hickory 0.26) from the system
  configuration with a Cloudflare fallback, or from explicit nameservers; 2 s
  timeout and 2 attempts by default.
- `FakeResolver` (feature `testing`): an in-memory zone that counts queries per
  name and type.
- `LoggingResolver`: records every query and its outcome.
- `normalise`, `validate_hostname`, `validate_service_name`, IDNA `to_ascii`
  and `to_unicode`, `public_suffix` and `registrable_domain` from the Public
  Suffix List, and `reverse_name`.
