# Changelog

## 0.2.4

- `AuthoritativeResolver`: a server that answers EDNS with FORMERR, even
  without echoing the question, is asked again without EDNS, and without it
  from then on (RFC 6891 §7), rather than timing out.

## 0.2.3

- `AuthoritativeResolver` (feature `hickory`): every query answered by the
  zone's authoritative servers, walking from the root, with only delegations
  cached, so a stale negative answer is never served.
  `AuthoritativeResolver::delegation`: the NS set the parent publishes.
  `AuthoritativeOptions` sets the timeout, attempts and a per-lookup query
  budget.

## 0.2.2

- Rust 1.99 floor.

## 0.2.1

- `txt::split`: a long value as TXT character-strings of at most 255
  octets, split only between characters; an empty value is one empty
  string. `txt::quote`: strings in zone file form, `"a" "b"`, with `"` and
  `\` escaped.

## 0.2.0

- **Breaking:** `Answer` and `HickoryOptions` are `#[non_exhaustive]`; build
  them with `Answer::new` and `HickoryOptions::default()`. Later fields are
  then not breaking.
- DNSSEC validation in `HickoryResolver`, behind feature `dnssec-ring` or
  `dnssec-aws-lc-rs` (the caller picks the crypto provider) and
  `HickoryOptions::validate`. Answers carry `Answer::dnssec` (`DnssecStatus`:
  Secure, Insecure, Bogus or Indeterminate, the worst of the records and any
  CNAMEs that led to them), set only when validating; a bogus answer is
  `LookupError::Bogus`, never NODATA.
- `Resolver::tlsa` and `Resolver::ds` (`Tlsa`, `Ds`), provided methods that
  answer `LookupError::Other` unless a resolver supports them, and
  `Resolver::validates`.
- `FakeResolver::{with_tlsa, with_ds, with_dnssec, validating}`.
- `LoggingResolver` logs DS queries; the root name `.` can be queried
  through `HickoryResolver`.

## 0.1.1

- `is_global` and `is_global_network`: whether an address or network is
  outside every IANA special-purpose range, the check every fetch of a
  DNS-named host needs before it connects.

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
