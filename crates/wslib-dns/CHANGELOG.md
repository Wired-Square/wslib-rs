# Changelog

## 0.1.0

- `Resolver`: one query per record type (TXT, A, AAAA, MX, NS, CNAME, PTR),
  each answering a `Lookup` that keeps NXDOMAIN, NODATA, SERVFAIL, REFUSED and
  a timeout apart. Provided `ip` (A and AAAA together) and `cname_chain`
  (loop-detecting, hop-capped).
- `HickoryResolver` (feature `hickory`, hickory 0.26) from the system
  configuration with a Cloudflare fallback, or from explicit nameserver socket
  addresses; 2 s timeout and 2 attempts by default, EDNS0 always on. Queries
  go to one server at a time, because hickory 0.26 drops the TCP retry of a
  truncated answer when it races two.
- Internationalised names are queried as A-labels by every resolver here.
- `&R` and `Arc<R>` implement `Resolver`.
- `FakeResolver` (feature `testing`): an in-memory zone that counts queries per
  name and type.
- `LoggingResolver`: records every query and its outcome.
- `Answer::canonical_name`: the end of the CNAME chain an answer came with.
- `BudgetResolver`: stops sending queries at a deadline or a query count,
  answering `LookupError::NotSent`.
- `normalise`, `validate_hostname`, `validate_service_name`, IDNA `to_ascii`
  and `to_unicode`, `public_suffix` and `registrable_domain` from the Public
  Suffix List, and `reverse_name`.
