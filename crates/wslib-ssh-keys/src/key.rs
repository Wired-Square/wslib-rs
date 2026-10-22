use std::fmt;
use std::str::FromStr;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;

use crate::{Error, Fingerprint};

/// A key type sshd accepts in `authorized_keys`, by its OpenSSH name.
///
/// `ssh-dss` is not one: OpenSSH has refused DSA by default since 7.0.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum KeyType {
    Ed25519,
    EcdsaP256,
    EcdsaP384,
    EcdsaP521,
    Rsa,
    SkEd25519,
    SkEcdsaP256,
}

impl KeyType {
    pub const ALL: [Self; 7] = [
        Self::Ed25519,
        Self::EcdsaP256,
        Self::EcdsaP384,
        Self::EcdsaP521,
        Self::Rsa,
        Self::SkEd25519,
        Self::SkEcdsaP256,
    ];

    /// `ssh-ed25519`, `ecdsa-sha2-nistp256`, `sk-ssh-ed25519@openssh.com`, …
    pub fn name(self) -> &'static str {
        match self {
            Self::Ed25519 => "ssh-ed25519",
            Self::EcdsaP256 => "ecdsa-sha2-nistp256",
            Self::EcdsaP384 => "ecdsa-sha2-nistp384",
            Self::EcdsaP521 => "ecdsa-sha2-nistp521",
            Self::Rsa => "ssh-rsa",
            Self::SkEd25519 => "sk-ssh-ed25519@openssh.com",
            Self::SkEcdsaP256 => "sk-ecdsa-sha2-nistp256@openssh.com",
        }
    }

    /// A security-key type, whose private half stays on a FIDO authenticator.
    pub fn is_security_key(self) -> bool {
        matches!(self, Self::SkEd25519 | Self::SkEcdsaP256)
    }

    fn curve(self) -> Option<(&'static str, u32)> {
        match self {
            Self::EcdsaP256 | Self::SkEcdsaP256 => Some(("nistp256", 256)),
            Self::EcdsaP384 => Some(("nistp384", 384)),
            Self::EcdsaP521 => Some(("nistp521", 521)),
            _ => None,
        }
    }
}

impl fmt::Display for KeyType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

impl FromStr for KeyType {
    type Err = Error;

    fn from_str(name: &str) -> Result<Self, Error> {
        Self::ALL
            .into_iter()
            .find(|t| t.name() == name)
            .ok_or_else(|| Error::UnsupportedType(name.to_string()))
    }
}

/// One of a key line's leading options, such as `no-pty` or `from="10.0.0.0/8"`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct KeyOption {
    /// As written; sshd matches it without regard to case.
    pub name: String,
    /// Unquoted, with `\"` read as `"`.
    pub value: Option<String>,
}

/// One `authorized_keys` key line, checked as sshd would read it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Key {
    line: String,
    options: Vec<KeyOption>,
    key_type: KeyType,
    blob: Vec<u8>,
    bits: u32,
    comment: Option<String>,
}

impl Key {
    /// Parse one line: options, key type, base64 blob and comment.
    pub fn parse(line: &str) -> Result<Self, Error> {
        let line = line.trim();
        if line.contains("PRIVATE KEY-----") {
            return Err(Error::PrivateKey);
        }
        if line.contains('\n') {
            return Err(Error::MultipleLines);
        }
        if line.is_empty() {
            return Err(Error::Empty);
        }
        let (options, rest) = match field(line).0.parse::<KeyType>() {
            Ok(_) => (Vec::new(), line),
            Err(_) => split_options(line)?,
        };
        let (type_name, rest) = field(rest);
        if type_name.is_empty() {
            return Err(Error::Empty);
        }
        let key_type: KeyType = type_name.parse()?;
        let (blob, comment) = field(rest);
        if blob.is_empty() {
            return Err(Error::MissingBlob(key_type));
        }
        let blob = STANDARD.decode(blob).map_err(|_| Error::Base64)?;
        let bits = check_blob(key_type, &blob)?;
        Ok(Self {
            line: line.to_string(),
            options,
            key_type,
            blob,
            bits,
            comment: (!comment.is_empty()).then(|| comment.to_string()),
        })
    }

    /// The line as given, trimmed: what a rewrite writes back.
    pub fn line(&self) -> &str {
        &self.line
    }

    pub fn options(&self) -> &[KeyOption] {
        &self.options
    }

    pub fn key_type(&self) -> KeyType {
        self.key_type
    }

    /// The decoded wire blob (RFC 4253 §6.6), which the fingerprint is taken over.
    pub fn blob(&self) -> &[u8] {
        &self.blob
    }

    /// The size `ssh-keygen -l` prints: the RSA modulus, the curve, or 256 for Ed25519.
    pub fn bits(&self) -> u32 {
        self.bits
    }

    /// Everything after the blob, conventionally `user@host`.
    pub fn comment(&self) -> Option<&str> {
        self.comment.as_deref()
    }

    pub fn fingerprint(&self) -> Fingerprint {
        Fingerprint::of_blob(&self.blob)
    }
}

impl fmt::Display for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.line)
    }
}

impl FromStr for Key {
    type Err = Error;

    fn from_str(line: &str) -> Result<Self, Error> {
        Self::parse(line)
    }
}

const BLANK: [char; 2] = [' ', '\t'];

fn field(s: &str) -> (&str, &str) {
    let s = s.trim_start_matches(BLANK);
    s.split_once(BLANK).map_or((s, ""), |(field, rest)| {
        (field, rest.trim_start_matches(BLANK))
    })
}

fn split_options(line: &str) -> Result<(Vec<KeyOption>, &str), Error> {
    let first = field(line).0;
    let looks_like_a_type = !first.starts_with("no-") && !first.contains(['=', ',', '"']);
    if looks_like_a_type && option_takes_value(first).is_none() {
        return Err(Error::UnsupportedType(first.to_string()));
    }
    let mut quoted = false;
    let mut escaped = false;
    let end = line
        .char_indices()
        .find(|&(_, c)| {
            let was_escaped = std::mem::take(&mut escaped);
            match c {
                '\\' => escaped = true,
                '"' if !was_escaped => quoted = !quoted,
                ' ' | '\t' if !quoted => return true,
                _ => {}
            }
            false
        })
        .map_or(line.len(), |(i, _)| i);
    Ok((parse_options(&line[..end])?, &line[end..]))
}

fn parse_options(mut rest: &str) -> Result<Vec<KeyOption>, Error> {
    let bad = |why: String| Err(Error::BadOptions(why));
    let mut options = Vec::new();
    loop {
        let (name, after) = rest.split_at(rest.find(['=', ',']).unwrap_or(rest.len()));
        let Some(takes_value) = option_takes_value(name) else {
            return bad(format!("`{name}` is not an option sshd knows"));
        };
        rest = after;
        let value = match (rest.strip_prefix('='), takes_value) {
            (Some(quoted), true) => {
                let (value, after) = dequote(quoted)?;
                rest = after;
                Some(value)
            }
            (Some(_), false) => return bad(format!("`{name}` takes no value")),
            (None, true) => return bad(format!("`{name}` needs a quoted value")),
            (None, false) => None,
        };
        options.push(KeyOption {
            name: name.to_string(),
            value,
        });
        match rest.strip_prefix(',') {
            None if rest.is_empty() => return Ok(options),
            Some(next) if !next.is_empty() => rest = next,
            _ => return bad("options are separated by single commas".to_string()),
        }
    }
}

fn dequote(s: &str) -> Result<(String, &str), Error> {
    let unquoted = |why: &str| Error::BadOptions(why.to_string());
    let s = s
        .strip_prefix('"')
        .ok_or_else(|| unquoted("a value starts with `\"`"))?;
    let mut value = String::new();
    let mut chars = s.char_indices();
    while let Some((i, c)) = chars.next() {
        match c {
            '"' => return Ok((value, &s[i + 1..])),
            '\\' if s[i + 1..].starts_with('"') => {
                chars.next();
                value.push('"');
            }
            c => value.push(c),
        }
    }
    Err(unquoted("a quoted value is not closed"))
}

/// `Some(true)` for an option sshd reads a value for, `Some(false)` for a flag.
fn option_takes_value(name: &str) -> Option<bool> {
    const VALUES: &[&str] = &[
        "command",
        "environment",
        "expiry-time",
        "from",
        "permitlisten",
        "permitopen",
        "principals",
        "tunnel",
    ];
    const FLAGS: &[&str] = &["cert-authority", "restrict"];
    const NEGATABLE: &[&str] = &[
        "agent-forwarding",
        "port-forwarding",
        "pty",
        "touch-required",
        "user-rc",
        "verify-required",
        "x11-forwarding",
    ];
    let name = name.to_ascii_lowercase();
    let positive = name.strip_prefix("no-").unwrap_or(&name);
    if VALUES.contains(&name.as_str()) {
        Some(true)
    } else if FLAGS.contains(&name.as_str()) || NEGATABLE.contains(&positive) {
        Some(false)
    } else {
        None
    }
}

/// The key's bits, once the blob is one sshd would load as `key_type`.
fn check_blob(key_type: KeyType, blob: &[u8]) -> Result<u32, Error> {
    let mut wire = Wire(blob);
    let named = wire.string().ok_or(Error::Malformed)?;
    if named != key_type.name().as_bytes() {
        return Err(Error::TypeMismatch {
            line: key_type,
            blob: String::from_utf8_lossy(named).into_owned(),
        });
    }
    let bits = match (key_type, key_type.curve()) {
        (KeyType::Ed25519 | KeyType::SkEd25519, _) => {
            (wire.string().ok_or(Error::Malformed)?.len() == 32).then_some(256)
        }
        (KeyType::Rsa, _) => {
            wire.mpint().ok_or(Error::Malformed)?;
            let bits = wire.mpint().ok_or(Error::Malformed)?;
            if !(1024..=16384).contains(&bits) {
                return Err(Error::RsaSize(bits));
            }
            Some(bits)
        }
        (_, Some((curve, bits))) => {
            let named_curve = wire.string().ok_or(Error::Malformed)?;
            let point = wire.string().ok_or(Error::Malformed)?;
            let uncompressed = 1 + 2 * bits.div_ceil(8) as usize;
            (named_curve == curve.as_bytes() && point.len() == uncompressed && point[0] == 4)
                .then_some(bits)
        }
        _ => None,
    }
    .ok_or(Error::Malformed)?;
    if key_type.is_security_key() && wire.string().is_none_or(|app| app.contains(&0)) {
        return Err(Error::Malformed);
    }
    if !wire.0.is_empty() {
        return Err(Error::Malformed);
    }
    Ok(bits)
}

struct Wire<'a>(&'a [u8]);

impl<'a> Wire<'a> {
    fn string(&mut self) -> Option<&'a [u8]> {
        let (len, rest) = self.0.split_first_chunk::<4>()?;
        let len = usize::try_from(u32::from_be_bytes(*len)).ok()?;
        if rest.len() < len {
            return None;
        }
        let (string, rest) = rest.split_at(len);
        self.0 = rest;
        Some(string)
    }

    /// A non-negative mpint as sshd reads one (at most 16384 bits), as its bit length.
    fn mpint(&mut self) -> Option<u32> {
        let bytes = self.string()?;
        if bytes.len() > 2049 || bytes.first().is_some_and(|b| b & 0x80 != 0) {
            return None;
        }
        let significant = &bytes[bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len())..];
        let top = significant.first().map_or(0, |b| 8 - b.leading_zeros());
        Some(top + 8 * significant.len().saturating_sub(1) as u32)
    }
}
