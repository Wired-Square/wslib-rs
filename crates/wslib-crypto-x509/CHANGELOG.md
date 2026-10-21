# Changelog

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
