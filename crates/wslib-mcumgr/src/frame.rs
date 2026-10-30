//! One SMP message: the header and a CBOR map, and the error maps a reply can
//! carry in place of its result.

use std::fmt;

use serde::de::{self, DeserializeOwned, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::header::{HEADER_LEN, Header, Op, Version};
use crate::{Error, Group};

#[derive(Serialize, Deserialize)]
pub(crate) struct Empty {}

pub(crate) fn encode<T: Serialize>(
    op: Op,
    group: Group,
    command: u8,
    seq: u8,
    payload: &T,
) -> Result<Vec<u8>, Error> {
    let mut frame = vec![0; HEADER_LEN];
    ciborium::into_writer(payload, &mut frame).map_err(|e| Error::Encode(e.to_string()))?;
    let len = u16::try_from(frame.len() - HEADER_LEN)
        .map_err(|_| Error::Encode(format!("{}-byte payload overflows the header", frame.len())))?;
    let header = Header {
        version: Version::V1,
        op,
        flags: 0,
        len,
        group,
        seq,
        command,
    };
    frame[..HEADER_LEN].copy_from_slice(&header.encode());
    Ok(frame)
}

pub(crate) fn decode<T: DeserializeOwned>(frame: &[u8]) -> Result<(Header, T), Error> {
    let header = Header::decode(frame)?;
    let payload = frame
        .get(HEADER_LEN..HEADER_LEN + usize::from(header.len))
        .ok_or_else(|| {
            Error::Decode(format!(
                "header promises {} payload bytes, frame has {}",
                header.len,
                frame.len() - HEADER_LEN
            ))
        })?;
    let body = ciborium::from_reader(payload).map_err(|e| Error::Decode(e.to_string()))?;
    Ok((header, body))
}

/// A reply's result, or [`Error::Rejected`] if it carries a non-zero `rc`
/// (version 1) or an `err` map (version 2). `context` names the request.
pub(crate) fn decode_reply<T: DeserializeOwned>(frame: &[u8], context: &str) -> Result<T, Error> {
    #[derive(Deserialize)]
    struct Status {
        #[serde(default)]
        rc: i32,
        #[serde(default)]
        rsn: Option<String>,
        #[serde(default)]
        err: Option<GroupError>,
    }
    #[derive(Deserialize)]
    struct GroupError {
        group: u16,
        rc: i32,
    }

    let (_, status): (_, Status) = decode(frame)?;
    if let Some(err) = status.err {
        return Err(Error::Rejected {
            rc: err.rc,
            group: Some(err.group),
            reason: context.to_owned(),
        });
    }
    if status.rc != 0 {
        let reason = match status.rsn {
            Some(rsn) => format!("{context}: {rsn}"),
            None => context.to_owned(),
        };
        return Err(Error::Rejected {
            rc: status.rc,
            group: None,
            reason,
        });
    }
    decode(frame)
        .map(|(_, body)| body)
        .map_err(|e| Error::Decode(format!("{context}: {e}")))
}

/// A CBOR byte string; serde alone would write a `Vec<u8>` as an array.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Bytes(pub Vec<u8>);

/// [`Bytes`] borrowed, for requests.
pub(crate) struct BytesRef<'a>(pub &'a [u8]);

impl Serialize for BytesRef<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(self.0)
    }
}

impl Serialize for Bytes {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(&self.0)
    }
}

impl<'de> Deserialize<'de> for Bytes {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct BytesVisitor;

        impl<'de> Visitor<'de> for BytesVisitor {
            type Value = Bytes;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a byte string")
            }

            fn visit_bytes<E: de::Error>(self, v: &[u8]) -> Result<Bytes, E> {
                Ok(Bytes(v.to_vec()))
            }

            fn visit_byte_buf<E: de::Error>(self, v: Vec<u8>) -> Result<Bytes, E> {
                Ok(Bytes(v))
            }
        }

        deserializer.deserialize_bytes(BytesVisitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The spec's image state read: op 0, group 1, command 0, an empty map (0xa0).
    #[test]
    fn an_empty_read_is_the_header_and_an_empty_map() {
        let frame = encode(Op::Read, Group::Image, 0, 7, &Empty {}).unwrap();
        assert_eq!(
            frame,
            [0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x07, 0x00, 0xa0]
        );
    }

    #[test]
    fn bytes_are_a_cbor_byte_string_both_ways() {
        let mut out = Vec::new();
        ciborium::into_writer(&BytesRef(&[1, 2, 3]), &mut out).unwrap();
        assert_eq!(out, [0x43, 1, 2, 3]);
        let back: Bytes = ciborium::from_reader(&out[..]).unwrap();
        assert_eq!(back.0, [1, 2, 3]);
    }

    #[derive(Debug, Deserialize)]
    struct Off {
        off: u32,
    }

    fn reply(version: Version, payload: &[u8]) -> Vec<u8> {
        let header = Header {
            version,
            op: Op::WriteResponse,
            flags: 0,
            len: payload.len() as u16,
            group: Group::Fs,
            seq: 9,
            command: 0,
        };
        [&header.encode()[..], payload].concat()
    }

    // CBOR by hand from RFC 8949: {"rc": 3} and {"err": {"group": 8, "rc": 5}}.
    #[test]
    fn a_version_1_rc_or_a_version_2_err_map_is_a_rejection() {
        let v1 = reply(Version::V1, &[0xa1, 0x62, b'r', b'c', 0x03]);
        assert!(matches!(
            decode_reply::<Off>(&v1, "upload"),
            Err(Error::Rejected {
                rc: 3,
                group: None,
                ..
            })
        ));
        let mut err = vec![0xa1, 0x63, b'e', b'r', b'r', 0xa2, 0x65];
        err.extend_from_slice(b"group");
        err.extend_from_slice(&[0x08, 0x62, b'r', b'c', 0x05]);
        assert!(matches!(
            decode_reply::<Off>(&reply(Version::V2, &err), "status"),
            Err(Error::Rejected {
                rc: 5,
                group: Some(8),
                ..
            })
        ));
    }

    #[test]
    fn rc_zero_beside_the_result_is_success() {
        let ok = [0xa2, 0x63, b'o', b'f', b'f', 0x04, 0x62, b'r', b'c', 0x00];
        let ack: Off = decode_reply(&reply(Version::V1, &ok), "upload").unwrap();
        assert_eq!(ack.off, 4);
    }

    #[test]
    fn a_payload_shorter_than_the_header_says_is_an_error() {
        let frame = [0x01, 0, 0, 5, 0, 1, 9, 0, 0xa0];
        assert!(matches!(decode::<Off>(&frame), Err(Error::Decode(_))));
    }
}
