# wslib-crypto-x509

X.509 certificates on `wslib-crypto`: PEM as people paste it, what a
certificate says and what is odd about it, whether a name is covered,
whether a chain holds, whether a signature is a certificate's key's, and a
self-signed certificate to serve. x509-parser
reads and rcgen writes; no crypto provider is enabled here.

```rust
use wslib_crypto::{KeyAlgorithm, Signer};
use wslib_crypto_x509::{SubjectAltName, chain, examine, inspect, inspect_pem, mint, pem, signature};

// A serving pair of our own:
let key = KeyAlgorithm::EcP256.generate()?;
let signer = Signer::new(provider.clone(), &key.clone_key().into())?;
let names: Vec<SubjectAltName> = vec!["widget-01.local".parse()?, "127.0.0.1".parse()?];
let cert_pem = pem::encode(pem::CERTIFICATE, &mint(&signer, &names)?);
let key_pem = pem::encode(pem::PRIVATE_KEY, key.secret_pkcs8_der());

// One somebody pasted:
let report = examine(inspect_pem(&pasted)?, Some(host), SystemTime::now());
for warning in &report.warnings { /* Expired, HostNotCovered { host }, … */ }

// A chain, with the provider's algorithms:
let anchors = [chain::trust_anchor(&root)?];
chain::verify(&leaf, &intermediates, &anchors, chain::Purpose::CODE_SIGNING, at,
    provider.signature_verification_algorithms.all)?;

// A signature by that leaf's key:
signature::verify(&inspect(&leaf)?.spki, &algorithm_identifier, message, signed,
    provider.signature_verification_algorithms.all)?;
```

## What's here

- **`pem`**: `certificates` reads the certificates in some text, leaf
  first, and refuses any other section beside them, a private key above
  all, since that text is usually served to anyone. `private_key` reads one
  key and refuses an encrypted one or two. `normalise` keeps every section
  verbatim with LF endings and drops what is between them, and indented
  markers read as if they were not;
  `certificate_sections` keeps only the certificates. Text over `MAX_LEN`
  (256 KiB) is refused before parsing. `encode` writes PEM with LF endings.
- **`inspect` and `inspect_pem`**: a `CertificateView` copied out of the
  certificate: subject and issuer in RFC 4514 form (`CN=R3,O=Let's
  Encrypt,C=US`), serial, subject alternative names, validity,
  the key (`RSA 2048`, `ECDSA P-256`; `KeyDescription::of_spki` reads one
  from any SubjectPublicKeyInfo, and `bits` gives its size), the signature
  algorithm by OpenSSL's name (`sha256WithRSAEncryption`), SHA-256
  fingerprint, the SubjectPublicKeyInfo for `wslib_crypto::key_matches`,
  and the CA flag, key usages, extended key usages and name constraints.
- **`NameConstraints`**: permitted and excluded `NameSubtree`s: a DNS name
  (with an optional leading dot for the names below it only), an
  `IpSubtree` (an address and prefix length, with no host bits set), or any
  other subtree as its DER. A subtree parses from and displays as
  `example.com` or `10.0.0.0/8`.
- **`rfc_4514(name)`**: any DER Name in that same form, such as a CRL's
  issuer.
- **`name_attributes(name)`**: a DER Name's attributes in the order the DER
  has them, RDN by RDN, each a dotted OID with its value as text (UTF8,
  Printable, IA5, Numeric, BMP or Universal string) or, for any other type,
  as the value's DER. For an application's own one-line form.
- **`examine(view, host, now)`**: a `Report` of warnings: expired, not yet
  valid, no host name (no DNS name or address among the subject alternative
  names), `host` not covered, an extended key
  usage without server authentication, `CA:TRUE`. `now` is an argument, so a
  host with no clock yet can be tested. Nothing here is a trust decision.
- **`SubjectAltName`**: a DNS name, address, email or URI, parsed from what
  a person types and refused when it is none of them; a DNS name is what
  rustls takes as a server name, or a wildcard over one. `covers(host)`
  ignores case and IPv6 brackets; a wildcard covers one label and never an
  address.
- **`chain::verify`**: the end-entity certificate through its intermediates
  to a trust anchor at a given time, for a `Purpose` (an extended key usage,
  required outright or only when the extension is there, and optionally a
  key usage the leaf must allow: code signing needs digital signatures), with
  the signature algorithms the caller passes. `ChainError` tells expiry, a
  wrong purpose or key usage and an untrusted issuer apart. Revocation and
  the anchor's own validity are not checked.
- **`signature::verify`**: a signature over a message with the key of a
  SubjectPublicKeyInfo, by the AlgorithmIdentifier the signature names, with
  whichever of the caller's algorithms fits both. `SignatureError` tells no
  fitting algorithm from a signature that does not verify.
  `signature::algorithm_name(oid)` is OpenSSL's name for a signature
  algorithm, or the OID when unknown.
- **`mint(signer, names)`**: a self-signed serving certificate. The first
  name is the common name; valid from 1 July 2026 into the year 4096;
  `CA:FALSE`, digital signature and server authentication, each stated;
  a random serial and key identifier from `wslib-crypto`.

## What isn't

Issuing from a CA, CSRs and CRLs. Loading certificates from disk, OS roots
and reloading a TLS config.
