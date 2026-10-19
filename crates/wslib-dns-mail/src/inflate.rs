use std::io::Read;

/// A gzip stream starts with these bytes, which is how a `.svgz` is told
/// from an SVG.
pub(crate) fn is_gzip(bytes: &[u8]) -> bool {
    bytes.starts_with(&[0x1f, 0x8b])
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum InflateError {
    TooLarge,
    Corrupt,
}

/// Decompresses a gzip stream, stopping as soon as the output would pass
/// `limit` bytes, so a small file can't inflate into a large one.
pub(crate) fn gunzip(bytes: &[u8], limit: usize) -> Result<Vec<u8>, InflateError> {
    let mut out = Vec::new();
    let limit = u64::try_from(limit).unwrap_or(u64::MAX);
    flate2::read::GzDecoder::new(bytes)
        .take(limit + 1)
        .read_to_end(&mut out)
        .map_err(|_| InflateError::Corrupt)?;
    if out.len() as u64 > limit {
        return Err(InflateError::TooLarge);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::*;

    fn gzip(bytes: &[u8]) -> Vec<u8> {
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(bytes).unwrap();
        encoder.finish().unwrap()
    }

    #[test]
    fn round_trips_within_the_limit() {
        let packed = gzip(b"<svg/>");
        assert!(is_gzip(&packed));
        assert_eq!(gunzip(&packed, 1024).unwrap(), b"<svg/>");
    }

    #[test]
    fn a_bomb_stops_at_the_limit() {
        let packed = gzip(&vec![b'a'; 10 * 1024 * 1024]);
        assert!(packed.len() < 64 * 1024);
        assert_eq!(gunzip(&packed, 256 * 1024), Err(InflateError::TooLarge));
        assert_eq!(
            gunzip(b"\x1f\x8bnot gzip", 1024),
            Err(InflateError::Corrupt)
        );
    }
}
