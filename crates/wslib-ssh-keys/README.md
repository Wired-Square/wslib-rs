# wslib-ssh-keys

OpenSSH `authorized_keys`: key lines checked as sshd reads them, `SHA256:`
fingerprints as `ssh-keygen -l` prints them, who added each key and when, and
a whole-file rewrite that never leaves half a file for sshd to read.

```rust
use wslib_ssh_keys::{AuthorisedKeys, Entry, Key, Provenance};

let key = Key::parse(pasted)?;
println!("{} {} {}", key.bits(), key.fingerprint(), key.key_type());

let mut file = AuthorisedKeys::read(path)?.with_header("Managed by the operator's tools.");
if !file.add(Entry::new(key).with_provenance(Provenance::new("admin", Some(Utc::now())))) {
    println!("already authorised");
}
file.remove(&"SHA256:/7MVDOe0auFFSFk/9EBpTvK7defzpFI3ccbS8WyAmiU".parse()?);
file.write(path)?;
```

## What's here

- **`Key`**: one line, as sshd reads it. Options first if the line doesn't
  start with a key type, each one sshd knows (any case), values in double
  quotes with `\"` inside; then the type, the base64 blob and the comment.
  The blob is checked as sshd loads it, short of the curve arithmetic: its
  own type string matches the line's, an Ed25519 key is 32 bytes, an ECDSA
  key names its curve and holds an uncompressed point of that curve's size,
  an RSA modulus is 1024 to 16384 bits, a security key carries its
  application, and nothing trails. `line()` is what a rewrite writes back,
  `blob()` the decoded wire form, `bits()` what `ssh-keygen -l` prints.
- **`KeyType`**: `ssh-ed25519`, `ecdsa-sha2-nistp256`, `-nistp384`,
  `-nistp521`, `ssh-rsa`, `sk-ssh-ed25519@openssh.com` and
  `sk-ecdsa-sha2-nistp256@openssh.com`. Not `ssh-dss`: OpenSSH has refused
  DSA by default since 7.0, so storing one would look like it worked and let
  nobody in.
- **`Fingerprint`**: SHA-256 of the wire blob as `SHA256:` and unpadded
  base64, byte for byte what `ssh-keygen -l` prints. It is not
  `wslib-crypto`'s fingerprint, which is colon hex over a DER public key.
- **`Error`**: worded for whoever pasted the line. A private key is caught
  first, since the file is world-readable; a spliced or truncated paste shows
  up as a type mismatch or malformed data.
- **`AuthorisedKeys`**: a file's `entries()`, each a `Key` with an optional
  `Provenance` (`# added by <who> on <RFC 3339>` directly above the key), and
  `unparsed()`: lines that are not keys this crate accepts, kept verbatim
  because sshd may still honour them. Other comments are dropped; the header
  set by `with_header` is written first, each line prefixed `# `. `add`
  refuses a key whose fingerprint is already there, whatever its options.
  A control character in a provenance name is written as a space, so a name
  can't add a line of its own.
- **`read`** takes a missing file as an empty one. **`write`** replaces the
  file whole through `wslib-file-atomic`, `0644`: sshd opens it as the
  account logging in, so `0600` fails every login without saying why.

## Left to the caller

- **One writer per file.** A change is read, edit, write: hold a lock.
- **The directories.** Under `StrictModes` sshd wants every parent owned by
  root or the account, with no group or other write, and readable by the
  account. Making them is the caller's.
- **Policy.** Which file, whether options are allowed, who may add a key.
- **ECDSA points are not checked to lie on the curve**, which needs curve
  arithmetic; sshd refuses such a key when it loads the file. Option values
  (`from` patterns, `expiry-time`, `permitopen`) are not checked either.
