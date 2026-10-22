# Changelog

## 0.1.0

- `Key::parse` reads one `authorized_keys` line as sshd does: leading
  options, key type, base64 blob, comment. The blob must load as the type the
  line names: its embedded type string, an Ed25519 key of 32 bytes, an ECDSA
  curve name and uncompressed point of the right size, an RSA modulus of 1024
  to 16384 bits, a security key's application, nothing trailing. Options are
  the ones sshd knows, values quoted. The line is written back as given.
- `KeyType`: Ed25519, ECDSA P-256, P-384 and P-521, RSA, and the two
  security-key types. No DSA.
- `Fingerprint`: OpenSSH's `SHA256:` form over the wire blob, as
  `ssh-keygen -l` prints it, parsed back with `FromStr`.
- `Error` says what is wrong in words for whoever pasted the line: a private
  key, a DSA key (`Dsa`, whether the line or the blob names it), a type
  mismatch from a spliced or truncated paste.
- `AuthorisedKeys`: a file's keys, each with an optional `Provenance` read
  from a `# added by <who> on <RFC 3339>` comment above it, and the lines it
  can't read kept verbatim. `add` refuses a fingerprint already there,
  `remove` and `get` take one, and `remove_where` takes the first entry a
  test matches. `read` takes a missing file as empty; `write`
  replaces the file whole, `0644`, under a `with_header` comment.
