//! `target` values are product-defined; they do not belong in this crate.

use crate::Error;

const BEGIN_LEN: usize = 9;
const END_LEN: usize = 1;

pub const DATA_OFFSET_LEN: usize = 4;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileBegin {
    pub target: u8,
    pub size: u32,
    pub crc32: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileData {
    pub offset: u32,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum FileAction {
    Abort,
    Commit,
}

impl FileAction {
    fn wire(self) -> u8 {
        match self {
            Self::Abort => 0,
            Self::Commit => 1,
        }
    }
}

/// The CRC-32 (ISO-HDLC) a device checks a transfer against at commit.
pub use wslib_checksum::crc32 as file_crc32;

pub fn pack_begin(begin: &FileBegin) -> Vec<u8> {
    let mut out = Vec::with_capacity(BEGIN_LEN);
    out.push(begin.target);
    out.extend_from_slice(&begin.size.to_le_bytes());
    out.extend_from_slice(&begin.crc32.to_le_bytes());
    out
}

pub fn parse_begin(buf: &[u8]) -> Result<FileBegin, Error> {
    if buf.len() != BEGIN_LEN {
        return Err(Error::InvalidPayload("FILE_BEGIN length"));
    }
    Ok(FileBegin {
        target: buf[0],
        size: u32::from_le_bytes([buf[1], buf[2], buf[3], buf[4]]),
        crc32: u32::from_le_bytes([buf[5], buf[6], buf[7], buf[8]]),
    })
}

pub fn pack_data(data: &FileData) -> Vec<u8> {
    let mut out = Vec::with_capacity(DATA_OFFSET_LEN + data.data.len());
    out.extend_from_slice(&data.offset.to_le_bytes());
    out.extend_from_slice(&data.data);
    out
}

pub fn parse_data(buf: &[u8]) -> Result<FileData, Error> {
    if buf.len() <= DATA_OFFSET_LEN {
        return Err(Error::InvalidPayload("FILE_DATA carries no data"));
    }
    Ok(FileData {
        offset: u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]),
        data: buf[DATA_OFFSET_LEN..].to_vec(),
    })
}

pub fn pack_end(action: FileAction) -> Vec<u8> {
    vec![action.wire()]
}

pub fn parse_end(buf: &[u8]) -> Result<FileAction, Error> {
    if buf.len() != END_LEN {
        return Err(Error::InvalidPayload("FILE_END length"));
    }
    match buf[0] {
        0 => Ok(FileAction::Abort),
        1 => Ok(FileAction::Commit),
        _ => Err(Error::InvalidPayload("FILE_END action")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOLDEN_BEGIN: [u8; 9] = [0x03, 0x58, 0x02, 0x00, 0x00, 0x78, 0x56, 0x34, 0x12];

    #[test]
    fn begin_matches_the_golden_vector() {
        let begin = FileBegin {
            target: 3,
            size: 600,
            crc32: 0x1234_5678,
        };

        assert_eq!(pack_begin(&begin), GOLDEN_BEGIN);
        assert_eq!(parse_begin(&GOLDEN_BEGIN).unwrap(), begin);
    }

    #[test]
    fn crc32_is_the_iso_hdlc_variant_the_device_checks_at_commit() {
        assert_eq!(file_crc32(b"123456789"), 0xCBF4_3926);
    }

    #[test]
    fn data_carries_its_length_in_the_header_not_the_payload() {
        let data = FileData {
            offset: 0x0002_D3FB,
            data: vec![0xAA, 0xBB, 0xCC],
        };

        let packed = pack_data(&data);

        assert_eq!(packed, [0xFB, 0xD3, 0x02, 0x00, 0xAA, 0xBB, 0xCC]);
        assert_eq!(parse_data(&packed).unwrap(), data);
    }

    #[test]
    fn parse_rejects_a_data_message_with_no_data() {
        assert!(parse_data(&[0x00, 0x00, 0x00, 0x00]).is_err());
    }

    #[test]
    fn end_round_trips_both_actions() {
        for action in [FileAction::Abort, FileAction::Commit] {
            let packed = pack_end(action);
            assert_eq!(packed.len(), 1);
            assert_eq!(parse_end(&packed).unwrap(), action);
        }
    }

    #[test]
    fn parse_rejects_an_unknown_end_action() {
        assert!(parse_end(&[2]).is_err());
    }

    #[test]
    fn parse_rejects_wrong_fixed_lengths() {
        assert!(parse_begin(&[0u8; 8]).is_err());
        assert!(parse_begin(&[0u8; 10]).is_err());
        assert!(parse_end(&[]).is_err());
        assert!(parse_end(&[1, 1]).is_err());
    }
}
