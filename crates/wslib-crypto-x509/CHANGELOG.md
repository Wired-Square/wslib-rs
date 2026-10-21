# Changelog

## 0.1.0

- `pem`: read certificates, refusing a private key or any other section
  beside them; read one unencrypted private key; normalise to the sections
  alone with LF endings; a 256 KiB cap; encode with LF endings.
- `inspect` and `inspect_pem`: `CertificateView`, with subject alternative
  names, validity, key description, fingerprint, CA flag and key usages.
- `examine`: warnings for expired, not yet valid, no subject alternative
  name, host not covered, no server authentication and `CA:TRUE`, at an
  injected time.
- `SubjectAltName`: parsing and validation of typed names, and `covers` with
  single-label wildcards.
- `chain::verify` for any extended key usage, over the caller's signature
  algorithms, and `chain::trust_anchor`.
- `mint`: a self-signed serving certificate through a `wslib_crypto::Signer`.
- Moved from the chassis's TLS inspection and mint.
