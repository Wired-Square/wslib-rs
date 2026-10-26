# Changelog

## 0.1.1

- `CsrView::subject_text`: the subject in RFC 4514 form, as
  `wslib_crypto_x509::rfc_4514` writes it.
- `CsrView::key`: the requested key's `wslib_crypto_x509::KeyDescription`.
- `CsrView::signature_algorithm` and `CrlView::signature_algorithm`: the
  signature algorithm by OpenSSL's long name, or its dotted OID.
- Needs `wslib-crypto-x509` 0.1.2.

## 0.1.0

- `Csr`: a certificate signing request parsed and its signature verified
  over the caller's algorithms; its subject (DER, byte for byte), common
  name, public key and requested DNS, address, email and URI names, and
  nothing else it asks for. `has_rsa_key` for key encipherment.
- `Subject` and `build_csr`: a request with CN, C, ST, L, O, OU and
  emailAddress in that order, in OpenSSL's string types, and its names in
  an extension request.
- `Profile`: basic constraints with an optional path length, key usage and
  extended key usage each with their criticality, a `SanPolicy` (none, the
  request's, or the common name then the request's), CRL distribution point
  and CA issuers URLs. Extensions are written in OpenSSL's order.
- `Authority`: an existing CA certificate (an OpenSSL-made one included)
  and its `Signer`, or a new self-signed one; `issue` from a `Csr` with the
  caller's `Serial` and `Validity`; `re_sign` a self-signed certificate
  keeping its subject, key and key identifier. Issuer names and the
  request's subject and key are copied byte for byte. `KeyIdentifierMethod`
  `Sha1` (OpenSSL's) or `Sha256` (`wslib-crypto`'s); the authority key
  identifier is the CA certificate's own.
- `Authority::revocation_list`: a v2 CRL with its number, this and next
  update, the authority key identifier from the CA's own, and entries in
  serial order, each with an optional `Reason` and invalidity date; the
  issuer name byte for byte.
- `CrlView`: a CRL read back (issuer, number, dates, authority key
  identifier, entries), and `verify` against an issuer certificate over the
  caller's algorithms.
- `CsrView`: a request read without a provider, a SHA-1-signed one
  included, with `Csr`'s accessors; `verify` makes the `Csr` that `issue`
  takes. `Serial` reads and writes decimal (`Error::NotDecimal` for other
  text) and converts from `i64`. A CRL's next update may equal its this
  update (`Error::CrlValidity` when before it). `CrlView::issuer_text` in
  RFC 4514 form.
