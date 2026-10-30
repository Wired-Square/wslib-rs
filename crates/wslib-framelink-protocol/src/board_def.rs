//! A board definition stored on the device, moved in chunks.

use crate::Error;

#[derive(Debug, Clone)]
pub struct BoardDefChunk {
    pub offset: u32,
    pub total_size: u32,
    pub data: Vec<u8>,
}

pub fn build_board_def_upload(offset: u32, total_size: u32, data: &[u8]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(10 + data.len());
    payload.extend_from_slice(&offset.to_le_bytes());
    payload.extend_from_slice(&total_size.to_le_bytes());
    payload.extend_from_slice(&(data.len() as u16).to_le_bytes());
    payload.extend_from_slice(data);
    payload
}

pub fn build_board_def_download_req(offset: u32, max_chunk_len: u16) -> Vec<u8> {
    let mut payload = Vec::with_capacity(6);
    payload.extend_from_slice(&offset.to_le_bytes());
    payload.extend_from_slice(&max_chunk_len.to_le_bytes());
    payload
}

pub fn parse_board_def_download_resp(payload: &[u8]) -> Result<BoardDefChunk, Error> {
    if payload.len() < 10 {
        return Err(Error::InvalidPayload("board def chunk too short"));
    }
    let offset = u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]);
    let total_size = u32::from_le_bytes([payload[4], payload[5], payload[6], payload[7]]);
    let chunk_len = u16::from_le_bytes([payload[8], payload[9]]) as usize;
    if payload.len() < 10 + chunk_len {
        return Err(Error::InvalidPayload("chunk data truncated"));
    }
    Ok(BoardDefChunk {
        offset,
        total_size,
        data: payload[10..10 + chunk_len].to_vec(),
    })
}

pub fn build_board_def_clear() -> Vec<u8> {
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_upload_roundtrip() {
        let data = vec![0x01, 0x02, 0x03, 0x04, 0x05];
        let payload = build_board_def_upload(1024, 5000, &data);
        let chunk = parse_board_def_download_resp(&payload).unwrap();
        assert_eq!(chunk.offset, 1024);
        assert_eq!(chunk.total_size, 5000);
        assert_eq!(chunk.data, data);
    }

    #[test]
    fn test_download_req() {
        let payload = build_board_def_download_req(512, 400);
        assert_eq!(payload.len(), 6);
        assert_eq!(
            u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]),
            512
        );
        assert_eq!(u16::from_le_bytes([payload[4], payload[5]]), 400);
    }

    #[test]
    fn test_clear() {
        assert!(build_board_def_clear().is_empty());
    }

    #[test]
    fn test_parse_too_short() {
        assert!(parse_board_def_download_resp(&[0; 9]).is_err());
    }

    #[test]
    fn test_parse_truncated_data() {
        let mut payload = build_board_def_upload(0, 100, &[1, 2, 3]);
        payload.pop();
        assert!(parse_board_def_download_resp(&payload).is_err());
    }
}
