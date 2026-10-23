//! Firmware files as bytes to write. Intel HEX keeps its gaps as separate
//! spans; a DFU/DfuSe file yields its first target's first element, which
//! is what a single-region download needs.

use std::path::Path;

use ihex::Record;

use crate::error::{FlashError, Result};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriteSpan {
    pub address: u32,
    pub data: Vec<u8>,
}

pub fn parse_intel_hex(bytes: &[u8]) -> Result<Vec<WriteSpan>> {
    let text = std::str::from_utf8(bytes)
        .map_err(|e| FlashError::Message(format!("Intel HEX file is not valid UTF-8: {e}")))?;

    let mut upper: u32 = 0;
    let mut spans: Vec<WriteSpan> = Vec::new();

    for line in text.lines().map(str::trim).filter(|l| !l.is_empty()) {
        let record = Record::from_record_string(line)
            .map_err(|e| FlashError::Message(format!("Intel HEX parse error: {e}")))?;
        match record {
            Record::Data { offset, value } => {
                let address = upper.wrapping_add(offset as u32);
                match spans.last_mut() {
                    Some(last) if last.address.wrapping_add(last.data.len() as u32) == address => {
                        last.data.extend_from_slice(&value);
                    }
                    _ => spans.push(WriteSpan {
                        address,
                        data: value,
                    }),
                }
            }
            Record::ExtendedLinearAddress(u) => upper = (u as u32) << 16,
            Record::ExtendedSegmentAddress(s) => upper = (s as u32) << 4,
            Record::EndOfFile
            | Record::StartLinearAddress(_)
            | Record::StartSegmentAddress { .. } => {}
        }
    }

    if spans.is_empty() {
        return Err("Intel HEX file has no data records".into());
    }
    Ok(spans)
}

pub fn intel_hex_first_span(bytes: &[u8]) -> Result<Vec<u8>> {
    Ok(parse_intel_hex(bytes)?.swap_remove(0).data)
}

/// Strip the 16-byte DFU suffix; a DfuSe body yields its first element's data.
pub fn parse_dfu_file(bytes: &[u8]) -> Result<Vec<u8>> {
    if bytes.len() < 16 {
        return Err("DFU file shorter than its 16-byte suffix".into());
    }
    let suffix_start = bytes.len() - 16;
    if &bytes[suffix_start + 8..suffix_start + 11] != b"UFD" {
        return Err("DFU file missing 'UFD' suffix signature".into());
    }
    let body = &bytes[..suffix_start];
    if body.len() < 11 || &body[0..5] != b"DfuSe" {
        return Ok(body.to_vec());
    }
    parse_dfuse_first_element(body)
}

fn parse_dfuse_first_element(body: &[u8]) -> Result<Vec<u8>> {
    const PREFIX: usize = 11;
    const TARGET_PREFIX: usize = 274;
    const ELEMENT_HEADER: usize = 8;

    if body[10] == 0 {
        return Err("DfuSe file has zero targets".into());
    }
    let mut cursor = PREFIX;
    if body.len() < cursor + TARGET_PREFIX {
        return Err("DfuSe target prefix truncated".into());
    }
    if &body[cursor..cursor + 6] != b"Target" {
        return Err("DfuSe target signature missing".into());
    }
    let num_elements = u32::from_le_bytes(body[cursor + 270..cursor + 274].try_into().unwrap());
    if num_elements == 0 {
        return Err("DfuSe target has zero image elements".into());
    }
    cursor += TARGET_PREFIX;

    if body.len() < cursor + ELEMENT_HEADER {
        return Err("DfuSe element header truncated".into());
    }
    let element_size =
        u32::from_le_bytes(body[cursor + 4..cursor + 8].try_into().unwrap()) as usize;
    let data_start = cursor + ELEMENT_HEADER;
    let data_end = data_start
        .checked_add(element_size)
        .ok_or_else(|| FlashError::Message("DfuSe element size overflow".into()))?;
    if body.len() < data_end {
        return Err(FlashError::Message(format!(
            "DfuSe element claims {element_size} bytes but file ends at {}",
            body.len() - data_start
        )));
    }
    Ok(body[data_start..data_end].to_vec())
}

fn read(path: &Path) -> Result<Vec<u8>> {
    std::fs::read(path)
        .map_err(|e| FlashError::Message(format!("Failed to read {}: {e}", path.display())))
}

fn has_extension(path: &Path, ext: &str) -> bool {
    path.extension()
        .is_some_and(|e| e.eq_ignore_ascii_case(ext))
}

/// `.hex` as its spans; anything else as one span at `base_address`.
pub fn load_spans(path: &Path, base_address: u32) -> Result<Vec<WriteSpan>> {
    let bytes = read(path)?;
    if has_extension(path, "hex") {
        parse_intel_hex(&bytes)
    } else {
        Ok(vec![WriteSpan {
            address: base_address,
            data: bytes,
        }])
    }
}

/// `.hex` as its first span, `.dfu` unwrapped, anything else raw.
pub fn load_flat(path: &Path) -> Result<Vec<u8>> {
    let bytes = read(path)?;
    if has_extension(path, "hex") {
        intel_hex_first_span(&bytes)
    } else if has_extension(path, "dfu") {
        parse_dfu_file(&bytes)
    } else {
        Ok(bytes)
    }
}

/// Pad to a multiple of four with `0xFF`, the erased-flash value.
pub fn pad_word_with_ff(data: &[u8]) -> Vec<u8> {
    let mut v = data.to_vec();
    v.resize(data.len().div_ceil(4) * 4, 0xFF);
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    const CONTIGUOUS: &[u8] = b":020000040800F2\n\
                               :04000000DEADBEEFC4\n\
                               :04000400CAFEBABEB8\n\
                               :00000001FF\n";
    const GAPPED: &[u8] = b":020000040800F2\n\
                           :04000000DEADBEEFC4\n\
                           :04010000CAFEBABEBB\n\
                           :00000001FF\n";

    fn with_dfu_suffix(mut body: Vec<u8>) -> Vec<u8> {
        body.extend_from_slice(&[0; 8]);
        body.extend_from_slice(b"UFD");
        body.extend_from_slice(&[0; 5]);
        body
    }

    #[test]
    fn parse_intel_hex_coalesces_contiguous_data() {
        let spans = parse_intel_hex(CONTIGUOUS).unwrap();
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0].address, 0x0800_0000);
        assert_eq!(
            spans[0].data,
            vec![0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE]
        );
    }

    #[test]
    fn parse_intel_hex_splits_non_contiguous() {
        let spans = parse_intel_hex(GAPPED).unwrap();
        assert_eq!(spans.len(), 2);
        assert_eq!(spans[0].address, 0x0800_0000);
        assert_eq!(spans[1].address, 0x0800_0100);
    }

    #[test]
    fn first_span_stops_at_gap() {
        assert_eq!(
            intel_hex_first_span(CONTIGUOUS).unwrap(),
            vec![0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE]
        );
        assert_eq!(
            intel_hex_first_span(GAPPED).unwrap(),
            vec![0xDE, 0xAD, 0xBE, 0xEF]
        );
        assert!(parse_intel_hex(b":00000001FF\n").is_err());
    }

    #[test]
    fn parse_dfu_strips_plain_suffix() {
        let payload = b"\xDE\xAD\xBE\xEF";
        assert_eq!(
            parse_dfu_file(&with_dfu_suffix(payload.to_vec())).unwrap(),
            payload
        );
    }

    #[test]
    fn parse_dfu_rejects_missing_signature_or_short_file() {
        assert!(parse_dfu_file(&[0u8; 16]).is_err());
        assert!(parse_dfu_file(&[0u8; 8]).is_err());
    }

    #[test]
    fn parse_dfuse_first_element_extracts_data() {
        let mut body = Vec::new();
        body.extend_from_slice(b"DfuSe");
        body.push(0x01);
        body.extend_from_slice(&0u32.to_le_bytes());
        body.push(1);
        body.extend_from_slice(b"Target");
        body.push(0);
        body.extend_from_slice(&0u32.to_le_bytes());
        body.extend_from_slice(&[0u8; 255]);
        body.extend_from_slice(&12u32.to_le_bytes());
        body.extend_from_slice(&1u32.to_le_bytes());
        body.extend_from_slice(&0x0800_0000u32.to_le_bytes());
        body.extend_from_slice(&4u32.to_le_bytes());
        body.extend_from_slice(&[0xCA, 0xFE, 0xBA, 0xBE]);

        assert_eq!(
            parse_dfu_file(&with_dfu_suffix(body)).unwrap(),
            vec![0xCA, 0xFE, 0xBA, 0xBE]
        );
    }

    #[test]
    fn pad_word_with_ff_pads_to_4() {
        assert_eq!(pad_word_with_ff(&[1]), vec![1, 0xFF, 0xFF, 0xFF]);
        assert_eq!(pad_word_with_ff(&[1, 2, 3, 4]), vec![1, 2, 3, 4]);
        assert_eq!(
            pad_word_with_ff(&[1, 2, 3, 4, 5]),
            vec![1, 2, 3, 4, 5, 0xFF, 0xFF, 0xFF],
        );
        assert!(pad_word_with_ff(&[]).is_empty());
    }

    #[test]
    fn load_picks_the_parser_by_extension() {
        let dir = std::env::temp_dir().join(format!("wslib-flash-image-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let hex = dir.join("app.HEX");
        let bin = dir.join("app.bin");
        std::fs::write(&hex, GAPPED).unwrap();
        std::fs::write(&bin, [1, 2, 3]).unwrap();

        assert_eq!(load_spans(&hex, 0).unwrap().len(), 2);
        assert_eq!(load_spans(&bin, 0x100).unwrap()[0].address, 0x100);
        assert_eq!(load_flat(&hex).unwrap(), vec![0xDE, 0xAD, 0xBE, 0xEF]);
        assert_eq!(load_flat(&bin).unwrap(), vec![1, 2, 3]);
        assert!(load_flat(&dir.join("missing.bin")).is_err());

        std::fs::remove_dir_all(&dir).unwrap();
    }
}
