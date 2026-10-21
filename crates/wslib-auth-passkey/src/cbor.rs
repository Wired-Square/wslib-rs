//! The CBOR (RFC 8949) an attestation object, a COSE key and an extensions map
//! are written in, and no more: definite lengths only, no tags, no floats, maps
//! without a repeated key, bounded in size, depth and count.

pub(crate) const MAX_INPUT: usize = 8 * 1024;
const MAX_DEPTH: usize = 8;
const MAX_ITEMS: u64 = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Value<'a> {
    Int(i128),
    Bytes(&'a [u8]),
    Text(&'a str),
    Array(Vec<Value<'a>>),
    Map(Vec<(Value<'a>, Value<'a>)>),
    Bool(bool),
    Null,
}

/// Why some CBOR was refused; for the journal, never the client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Malformed(pub(crate) &'static str);

impl<'a> Value<'a> {
    pub(crate) fn get(&self, key: &Value<'_>) -> Option<&Value<'a>> {
        match self {
            Value::Map(entries) => entries.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }
}

/// Exactly one item, with nothing after it.
pub(crate) fn decode(input: &[u8]) -> Result<Value<'_>, Malformed> {
    match decode_prefix(input)? {
        (value, []) => Ok(value),
        _ => Err(Malformed("bytes after the item")),
    }
}

/// The item `input` starts with, and what follows it.
pub(crate) fn decode_prefix(input: &[u8]) -> Result<(Value<'_>, &[u8]), Malformed> {
    if input.len() > MAX_INPUT {
        return Err(Malformed("too long"));
    }
    let mut reader = Reader { rest: input };
    let value = reader.item(0)?;
    Ok((value, reader.rest))
}

struct Reader<'a> {
    rest: &'a [u8],
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], Malformed> {
        if n > self.rest.len() {
            return Err(Malformed("truncated"));
        }
        let (taken, rest) = self.rest.split_at(n);
        self.rest = rest;
        Ok(taken)
    }

    fn argument(&mut self, info: u8) -> Result<u64, Malformed> {
        let width = match info {
            0..=23 => return Ok(u64::from(info)),
            24 => 1,
            25 => 2,
            26 => 4,
            27 => 8,
            31 => return Err(Malformed("an indefinite length")),
            _ => return Err(Malformed("a reserved additional information value")),
        };
        Ok(self
            .take(width)?
            .iter()
            .fold(0, |n, &byte| (n << 8) | u64::from(byte)))
    }

    fn count(&mut self, info: u8) -> Result<usize, Malformed> {
        let n = self.argument(info)?;
        if n > MAX_ITEMS {
            return Err(Malformed("too many items"));
        }
        Ok(n as usize)
    }

    fn string(&mut self, info: u8) -> Result<&'a [u8], Malformed> {
        let n = self.argument(info)?;
        let n = usize::try_from(n).map_err(|_| Malformed("truncated"))?;
        self.take(n)
    }

    fn item(&mut self, depth: usize) -> Result<Value<'a>, Malformed> {
        if depth > MAX_DEPTH {
            return Err(Malformed("nested too deeply"));
        }
        let initial = self.take(1)?[0];
        let (major, info) = (initial >> 5, initial & 0x1f);
        Ok(match major {
            0 => Value::Int(i128::from(self.argument(info)?)),
            1 => Value::Int(-1 - i128::from(self.argument(info)?)),
            2 => Value::Bytes(self.string(info)?),
            3 => Value::Text(
                std::str::from_utf8(self.string(info)?).map_err(|_| Malformed("text not UTF-8"))?,
            ),
            4 => {
                let n = self.count(info)?;
                Value::Array(
                    (0..n)
                        .map(|_| self.item(depth + 1))
                        .collect::<Result<_, _>>()?,
                )
            }
            5 => {
                let n = self.count(info)?;
                let mut entries: Vec<(Value<'a>, Value<'a>)> = Vec::new();
                for _ in 0..n {
                    let key = self.item(depth + 1)?;
                    if entries.iter().any(|(k, _)| *k == key) {
                        return Err(Malformed("a repeated map key"));
                    }
                    let value = self.item(depth + 1)?;
                    entries.push((key, value));
                }
                Value::Map(entries)
            }
            6 => return Err(Malformed("a tag")),
            _ => match info {
                20 => Value::Bool(false),
                21 => Value::Bool(true),
                22 => Value::Null,
                _ => return Err(Malformed("a float or an unassigned simple value")),
            },
        })
    }
}

/// Just enough of an encoder to build what the tests send.
#[cfg(any(test, feature = "testing"))]
pub(crate) mod encode {
    fn head(major: u8, n: u64) -> Vec<u8> {
        let major = major << 5;
        match n {
            0..=23 => vec![major | n as u8],
            24..=0xff => vec![major | 24, n as u8],
            0x100..=0xffff => [vec![major | 25], (n as u16).to_be_bytes().to_vec()].concat(),
            _ => [vec![major | 26], (n as u32).to_be_bytes().to_vec()].concat(),
        }
    }

    pub(crate) fn int(n: i64) -> Vec<u8> {
        match n {
            0.. => head(0, n as u64),
            _ => head(1, (-1 - n) as u64),
        }
    }

    pub(crate) fn bytes(b: &[u8]) -> Vec<u8> {
        [head(2, b.len() as u64), b.to_vec()].concat()
    }

    pub(crate) fn text(s: &str) -> Vec<u8> {
        [head(3, s.len() as u64), s.as_bytes().to_vec()].concat()
    }

    pub(crate) fn map(entries: &[(Vec<u8>, Vec<u8>)]) -> Vec<u8> {
        let mut out = head(5, entries.len() as u64);
        for (k, v) in entries {
            out.extend_from_slice(k);
            out.extend_from_slice(v);
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn refused(input: &[u8]) -> &'static str {
        decode(input).expect_err("refused").0
    }

    #[test]
    fn the_items_webauthn_uses_decode() {
        let input = [
            0xa6, // map(6)
            0x01, 0x02, // 1: 2
            0x20, 0x26, // -1: -7
            0x61, b'a', 0x42, 0xde, 0xad, // "a": h'dead'
            0x62, b'b', b'c', 0x82, 0xf5, 0xf4, // "bc": [true, false]
            0x3b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xf6, // -2^64: null
            0x19, 0x01, 0x00, 0xa0, // 256: {}
        ];
        let value = decode(&input).expect("decodes");
        assert_eq!(value.get(&Value::Int(1)), Some(&Value::Int(2)));
        assert_eq!(value.get(&Value::Int(-1)), Some(&Value::Int(-7)));
        assert_eq!(
            value.get(&Value::Text("a")),
            Some(&Value::Bytes(&[0xde, 0xad]))
        );
        assert_eq!(
            value.get(&Value::Text("bc")),
            Some(&Value::Array(vec![Value::Bool(true), Value::Bool(false)]))
        );
        assert_eq!(
            value.get(&Value::Int(-1 - i128::from(u64::MAX))),
            Some(&Value::Null)
        );
        assert_eq!(value.get(&Value::Int(256)), Some(&Value::Map(vec![])));
    }

    #[test]
    fn a_prefix_hands_back_what_follows() {
        let (value, rest) = decode_prefix(&[0x01, 0xaa, 0xbb]).expect("decodes");
        assert_eq!(value, Value::Int(1));
        assert_eq!(rest, [0xaa, 0xbb]);
        assert_eq!(refused(&[0x01, 0xaa]), "bytes after the item");
    }

    #[test]
    fn indefinite_lengths_tags_floats_and_reserved_values_are_refused() {
        assert_eq!(refused(&[0x5f, 0x41, 0x00, 0xff]), "an indefinite length");
        assert_eq!(refused(&[0xbf, 0xff]), "an indefinite length");
        assert_eq!(refused(&[0x9f, 0xff]), "an indefinite length");
        assert_eq!(refused(&[0xc2, 0x41, 0x01]), "a tag");
        assert_eq!(
            refused(&[0xf9, 0x3c, 0x00]),
            "a float or an unassigned simple value"
        );
        assert_eq!(refused(&[0xf7]), "a float or an unassigned simple value");
        assert_eq!(refused(&[0x1c]), "a reserved additional information value");
    }

    #[test]
    fn a_repeated_map_key_is_refused() {
        assert_eq!(
            refused(&[0xa2, 0x01, 0x02, 0x01, 0x03]),
            "a repeated map key"
        );
        assert_eq!(
            refused(&[0xa2, 0x61, b'x', 0x00, 0x61, b'x', 0x01]),
            "a repeated map key"
        );
    }

    #[test]
    fn a_length_past_the_input_is_truncated_not_an_allocation() {
        assert_eq!(
            refused(&[0x5b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]),
            "truncated"
        );
        assert_eq!(refused(&[0x42, 0x00]), "truncated");
        assert_eq!(refused(&[0x19, 0x01]), "truncated");
        assert_eq!(refused(&[]), "truncated");
        assert_eq!(
            refused(&[0x9b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]),
            "too many items"
        );
        assert_eq!(refused(&[0x82, 0x01]), "truncated");
    }

    #[test]
    fn depth_size_and_text_are_bounded() {
        let nested: Vec<u8> = std::iter::repeat_n(0x81, MAX_DEPTH + 1)
            .chain([0x00])
            .collect();
        assert_eq!(refused(&nested), "nested too deeply");
        let shallow: Vec<u8> = std::iter::repeat_n(0x81, MAX_DEPTH).chain([0x00]).collect();
        decode(&shallow).expect("at the limit");

        let long = encode::bytes(&vec![0; MAX_INPUT]);
        assert_eq!(refused(&long), "too long");
        assert_eq!(refused(&[0x62, 0xc3, 0x28]), "text not UTF-8");
    }
}
