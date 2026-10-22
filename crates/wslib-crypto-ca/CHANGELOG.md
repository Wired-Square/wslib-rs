# Changelog

## 0.1.0 (unreleased)

- `Csr`: a certificate signing request parsed and its signature verified
  over the caller's algorithms; its subject (DER, byte for byte), common
  name, public key and requested DNS, address, email and URI names, and
  nothing else it asks for. `has_rsa_key` for key encipherment.
- `Subject` and `build_csr`: a request with CN, C, ST, L, O, OU and
  emailAddress in that order, in OpenSSL's string types, and its names in
  an extension request.
