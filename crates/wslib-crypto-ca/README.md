# wslib-crypto-ca

A certificate authority on `wslib-crypto-x509`: certificate signing
requests read and built, certificates issued under a profile, and
revocation lists. rcgen encodes and x509-parser reads; signing goes through
a `wslib_crypto::Signer` and signature checks through the caller's
algorithms, so no crypto provider is enabled here.

```rust
use wslib_crypto_ca::{Csr, Subject, build_csr};

// A request of our own, for an external CA:
let subject = Subject { country: Some("AU".into()), ..Subject::new("www.example.com") };
let der = build_csr(&signer, &subject, &["www.example.com".parse()?])?;

// One somebody sent, checked with the provider's algorithms:
let csr = Csr::from_pem(&pasted, provider.signature_verification_algorithms.all)?;
```

## What's here

- **`Csr`**: `from_der` and `from_pem` parse a request and verify its
  self-signature with whichever of the caller's algorithms fit. What is
  kept is the subject (DER, copied into a certificate byte for byte), its
  first common name, the public key, and the DNS names, addresses, emails
  and URIs it asks for. Every other requested extension is dropped: the
  profile decides those. `has_rsa_key` tells a caller whether key
  encipherment may be claimed.
- **`Subject`** and **`build_csr`**: a request signed by a `Signer`, its
  subject in the order CN, C, ST, L, O, OU, emailAddress and in OpenSSL's
  string types (PrintableString country, IA5String email, UTF8String for the
  rest), and its subject alternative names in a non-critical extension
  request. Names are `wslib_crypto_x509::SubjectAltName`, parsed from what a
  person types.

## What isn't

Policy: which profile a kind of certificate gets, validity caps, serial
and CRL number counters, renewal, and when CRLs are made and published are
the application's.
