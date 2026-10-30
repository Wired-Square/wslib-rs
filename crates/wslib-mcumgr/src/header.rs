//! The 8-byte SMP header, as Zephyr's "SMP Protocol Specification" lays it
//! out: `res:3 ver:2 op:3`, flags, length (BE), group (BE), sequence, command.

use crate::Error;

pub const HEADER_LEN: usize = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Op {
    Read,
    ReadResponse,
    Write,
    WriteResponse,
}

impl Op {
    fn bits(self) -> u8 {
        match self {
            Self::Read => 0,
            Self::ReadResponse => 1,
            Self::Write => 2,
            Self::WriteResponse => 3,
        }
    }

    fn from_bits(bits: u8) -> Option<Self> {
        Some(match bits {
            0 => Self::Read,
            1 => Self::ReadResponse,
            2 => Self::Write,
            3 => Self::WriteResponse,
            _ => return None,
        })
    }
}

/// The protocol version in the header's `ver` bits.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Version {
    /// SMP version 1: errors come back as `{rc, rsn}`.
    #[default]
    V1,
    /// SMP version 2: group errors come back as `{err: {group, rc}}`.
    V2,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Group {
    Os,
    Image,
    Stat,
    Settings,
    Log,
    Crash,
    Split,
    Run,
    Fs,
    Shell,
    Enumeration,
    ZephyrBasic,
    Other(u16),
}

impl From<Group> for u16 {
    fn from(group: Group) -> Self {
        match group {
            Group::Os => 0,
            Group::Image => 1,
            Group::Stat => 2,
            Group::Settings => 3,
            Group::Log => 4,
            Group::Crash => 5,
            Group::Split => 6,
            Group::Run => 7,
            Group::Fs => 8,
            Group::Shell => 9,
            Group::Enumeration => 10,
            Group::ZephyrBasic => 63,
            Group::Other(id) => id,
        }
    }
}

impl From<u16> for Group {
    fn from(id: u16) -> Self {
        match id {
            0 => Self::Os,
            1 => Self::Image,
            2 => Self::Stat,
            3 => Self::Settings,
            4 => Self::Log,
            5 => Self::Crash,
            6 => Self::Split,
            7 => Self::Run,
            8 => Self::Fs,
            9 => Self::Shell,
            10 => Self::Enumeration,
            63 => Self::ZephyrBasic,
            other => Self::Other(other),
        }
    }
}

/// `len` counts the CBOR payload that follows, not the header.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct Header {
    pub version: Version,
    pub op: Op,
    pub flags: u8,
    pub len: u16,
    pub group: Group,
    pub seq: u8,
    pub command: u8,
}

impl Header {
    /// A version 1 header with no flags set.
    pub fn new(op: Op, group: Group, command: u8, seq: u8, len: u16) -> Self {
        Self {
            version: Version::V1,
            op,
            flags: 0,
            len,
            group,
            seq,
            command,
        }
    }

    pub fn encode(&self) -> [u8; HEADER_LEN] {
        let version = match self.version {
            Version::V1 => 0,
            Version::V2 => 1,
        };
        let [len_hi, len_lo] = self.len.to_be_bytes();
        let [group_hi, group_lo] = u16::from(self.group).to_be_bytes();
        [
            version << 3 | self.op.bits(),
            self.flags,
            len_hi,
            len_lo,
            group_hi,
            group_lo,
            self.seq,
            self.command,
        ]
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let Some(b) = bytes.first_chunk::<HEADER_LEN>() else {
            return Err(Error::Decode(format!(
                "{} bytes is shorter than the SMP header",
                bytes.len()
            )));
        };
        let op = Op::from_bits(b[0] & 0b111)
            .ok_or_else(|| Error::Decode(format!("op {} is not an SMP op", b[0] & 0b111)))?;
        let version = match (b[0] >> 3) & 0b11 {
            0 => Version::V1,
            1 => Version::V2,
            other => {
                return Err(Error::Decode(format!(
                    "SMP version bits {other} are reserved"
                )));
            }
        };
        Ok(Self {
            version,
            op,
            flags: b[1],
            len: u16::from_be_bytes([b[2], b[3]]),
            group: Group::from(u16::from_be_bytes([b[4], b[5]])),
            seq: b[6],
            command: b[7],
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The spec's field layout, with every field distinct so a swap shows.
    #[test]
    fn encodes_each_field_where_the_spec_puts_it() {
        let header = Header {
            version: Version::V2,
            op: Op::WriteResponse,
            flags: 0x5A,
            len: 0x0102,
            group: Group::Other(0x0304),
            seq: 0x05,
            command: 0x06,
        };
        assert_eq!(
            header.encode(),
            [0b0000_1011, 0x5A, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06]
        );
        assert_eq!(Header::decode(&header.encode()).unwrap(), header);
    }

    #[test]
    fn the_spec_group_ids_round_trip() {
        for (group, id) in [
            (Group::Os, 0),
            (Group::Image, 1),
            (Group::Fs, 8),
            (Group::Enumeration, 10),
            (Group::ZephyrBasic, 63),
            (Group::Other(64), 64),
        ] {
            assert_eq!(u16::from(group), id);
            assert_eq!(Group::from(id), group);
        }
    }

    #[test]
    fn decode_refuses_a_short_buffer_and_reserved_bits() {
        assert!(Header::decode(&[0; 7]).is_err());
        assert!(Header::decode(&[0b0000_0100, 0, 0, 0, 0, 0, 0, 0]).is_err());
        assert!(Header::decode(&[0b0001_0000, 0, 0, 0, 0, 0, 0, 0]).is_err());
    }
}
