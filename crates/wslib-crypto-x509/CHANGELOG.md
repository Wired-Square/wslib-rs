# Changelog

## 0.1.5

- `mint`: valid from 1975-01-01, not 2026-07-01. Safari and SecTrust refuse
  a certificate issued from 1 July 2019 that is valid for more than 825
  days.

## 0.1.4

- An ECDSA key with explicit curve parameters, rather than a named curve, is
  described with no curve instead of the parameters' DER.

## 0.1.3

- `CertificateView::name_constraints`: the RFC 5280 name constraints, as
  `NameConstraints` with permitted and excluded `NameSubtree`s. A DNS
  subtree keeps its optional leading dot; an address subtree is an
  `IpSubtree`, a network with no host bits set. A subtree of another kind,
  or with a minimum or maximum, is kept as its DER in `NameSubtree::Other`.
- `NameSubtree` parses `example.com`, `.example.com`, `10.0.0.0/8` and
  `fd00::/8`, and displays the same way.

## 0.1.2

- `CertificateView::signature_algorithm`: the certificate's signature
  algorithm by OpenSSL's long name (`sha256WithRSAEncryption`,
  `ecdsa-with-SHA256`, `ED25519`), or its dotted OID when unknown;
  `signature::algorithm_name` maps an OID the same way.
- `KeyDescription::of_spki`: the description of a DER
  SubjectPublicKeyInfo's key, outside a certificate.
- `KeyDescription::bits`: an RSA modulus's bits, or 256, 384 or 521 for
  the NIST curves.

## 0.1.1

- `rfc_4514`: a DER Name in the RFC 4514 form `CertificateView` gives
  subject and issuer, public for names outside certificates, such as a
  CRL's issuer.
- `name_attributes`: a DER Name's attributes in DER order, each a dotted
  OID with its value as text, or as DER when it is no string type.

## 0.1.0

- `pem`: read certificates, refusing a private key or any other section
  beside them; read one unencrypted private key; normalise to the sections
  alone with LF endings; indented markers read; a 256 KiB cap; encode with
  LF endings.
- `inspect` and `inspect_pem`: `CertificateView`, with subject and issuer
  in RFC 4514 form (keywords and escaping as x509-cert prints them),
  subject alternative names, validity, key description,
  fingerprint, CA flag and key usages.
- `examine`: warnings for expired, not yet valid, no host name (no DNS or
  address subject alternative name), host not covered, no server
  authentication and `CA:TRUE`, at an injected time.
- `SubjectAltName`: parsing and validation of typed names, DNS names as
  rustls accepts them, `covers` with single-label wildcards, and `is_host`.
- `chain::verify` for any extended key usage and an optional leaf key usage
  (digital signature for code signing), over the caller's signature
  algorithms, and `chain::trust_anchor`.
- `signature::verify`: a signature with a SubjectPublicKeyInfo's key, by the
  named signature algorithm, over the caller's algorithms.
- `mint`: a self-signed serving certificate through a `wslib_crypto::Signer`.
- Moved from the chassis's TLS inspection and mint.
