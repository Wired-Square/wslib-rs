//! Board TOML gzipped for storing on a device.

use std::io::{Read as _, Write as _};

use flate2::Compression;
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;

use crate::Error;

pub fn compress_board_toml(toml: &[u8]) -> Result<Vec<u8>, Error> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(toml)?;
    Ok(encoder.finish()?)
}

pub fn decompress_board_toml(data: &[u8]) -> Result<String, Error> {
    let mut decoder = GzDecoder::new(data);
    let mut output = String::new();
    decoder.read_to_string(&mut output)?;
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let original = "[board]\nname = \"test\"\n";
        let compressed = compress_board_toml(original.as_bytes()).unwrap();
        assert!(compressed.len() < original.len() + 30);
        let decompressed = decompress_board_toml(&compressed).unwrap();
        assert_eq!(decompressed, original);
    }

    #[test]
    fn decompress_invalid_data() {
        assert!(decompress_board_toml(b"not gzip").is_err());
    }
}
