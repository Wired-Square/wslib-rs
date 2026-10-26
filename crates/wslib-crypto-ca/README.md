# wslib-crypto-ca

A certificate authority on `wslib-crypto-x509`: certificate signing
requests read and built, certificates issued under a profile, and
revocation lists. rcgen encodes and x509-parser reads; signing goes through
a `wslib_crypto::Signer` and signature checks through the caller's
algorithms, so no crypto provider is enabled here.

```rust
use wslib_crypto_ca::{Authority, CrlView, Csr, KeyIdentifierMethod, Profile, Revocation, Serial, Subject, Validity, build_csr};

// A request of our own, for an external CA:
let subject = Subject { country: Some("AU".into()), ..Subject::new("www.example.com") };
let der = build_csr(&signer, &subject, &["www.example.com".parse()?])?;

// One somebody sent, checked with the provider's algorithms:
let csr = Csr::from_pem(&pasted, provider.signature_verification_algorithms.all)?;

// Issued under a CA certificate made elsewhere, by its key:
let ca = Authority::new(ca_certificate, ca_signer, KeyIdentifierMethod::Sha1)?;
let validity = Validity { not_before: now, not_after: now + Duration::from_secs(397 * 86_400) };
let leaf = ca.issue(&csr, &web_server_profile, &Serial::try_from(next_serial)?, validity)?;

// Revoked, and read back:
let crl = ca.revocation_list(crl_number, now, now + week, &[Revocation::new(revoked_serial, revoked_at)])?;
CrlView::from_der(&crl)?.verify(ca.certificate(), provider.signature_verification_algorithms.all)?;
```

## What's here

- **`Csr`**: `from_der` and `from_pem` parse a request and verify its
  self-signature with whichever of the caller's algorithms fit. What is
  kept is the subject (DER, copied into a certificate byte for byte), its
  first common name, the public key, and the DNS names, addresses, emails
  and URIs it asks for. Every other requested extension is dropped: the
  profile decides those. `has_rsa_key` tells a caller whether key
  encipherment may be claimed. For display, `subject_text` is the subject
  in RFC 4514 form, `key` the `wslib_crypto_x509::KeyDescription`, and
  `signature_algorithm` OpenSSL's name for it (`ecdsa-with-SHA256`). `CsrView` reads one without checking the
  signature, so a stored request needs no provider and a SHA-1-signed one
  still reads; its `verify(algorithms)` gives the `Csr` that `issue`
  takes, and a `Csr` has the view's accessors.
- **`Subject`** and **`build_csr`**: a request signed by a `Signer`, its
  subject in the order CN, C, ST, L, O, OU, emailAddress and in OpenSSL's
  string types (PrintableString country, IA5String email, UTF8String for the
  rest), and its subject alternative names in a non-critical extension
  request. Names are `wslib_crypto_x509::SubjectAltName`, parsed from what a
  person types.

- **`Profile`**: what a certificate says beyond its subject, key and key
  identifiers, built by the caller from `Profile::default()` (no
  extensions): basic constraints (`EndEntity`, stated, or `Authority` with
  an optional path length), key usage and extended key usage, each as an
  `Extension` with its criticality; a `SanPolicy` of none, the request's
  names, or the common name (an address when it parses as one) followed by
  the request's names not already there; CRL distribution point URLs (one
  distribution point) and CA issuers URLs. Subject and authority key
  identifiers are always written, and every extension goes in the order
  OpenSSL writes them, so its text of two certificates lines up.
- **`Authority`**: a CA certificate and its `Signer`. `new` takes one made
  anywhere, OpenSSL included, refusing one without `CA:TRUE` or whose key
  is not the signer's; `self_signed` makes one for a DER subject
  (`Subject::to_der`, or any name). `issue(csr, profile, serial, validity)`
  writes a certificate whose issuer is the CA's subject and whose subject
  and key are the request's, each byte for byte, so chains build by exact
  name in webpki and OpenSSL alike. `re_sign` replaces a self-signed
  certificate with new validity, keeping its subject, key and key
  identifier, so certificates it issued still chain.
- **`KeyIdentifierMethod`**: `Sha1`, RFC 5280 method 1 as OpenSSL computes
  it, or `Sha256`, `wslib_crypto::key_identifier`, for the subject key
  identifier of what the authority signs. The authority key identifier is
  always the CA certificate's own subject key identifier, or, when it has
  none, the method's.
- **`Serial`**: positive and at most 20 octets, from a `u64`, an `i64`,
  bytes or decimal text (and `Display`ed in decimal), or
  `Serial::random` from the provider (16 bytes, as `wslib-crypto` makes
  them). The caller keeps any counter.

- **`Authority::revocation_list(number, this_update, next_update, revoked)`**:
  a v2 CRL whose issuer is the CA's subject byte for byte, with its CRL
  number and an authority key identifier (the CA's own), and its entries in
  serial order. The next update may equal this update. A `Revocation` may carry a `Reason` (none means
  unspecified) and the date the key became invalid. No issuing distribution
  point and no deltas.
- **`CrlView`**: what a CRL says, read without trusting it: issuer (DER,
  and `issuer_text` in RFC 4514 form),
  number, this and next update, authority key identifier and entries, and
  `signature_algorithm()` by OpenSSL's name.
  `verify(issuer, algorithms)` checks that the certificate's subject is the
  CRL's issuer, byte for byte, and that its key signed it.

## What isn't

Policy: which profile a kind of certificate gets, validity caps, serial
and CRL number counters, renewal, and when CRLs are made and published are
the application's. OCSP, delta CRLs, name constraints and policy
extensions are not here.
