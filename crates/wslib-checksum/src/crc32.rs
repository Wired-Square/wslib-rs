use crate::algorithms::reflected_table;

static TABLE: [u32; 256] = reflected_table(0xEDB8_8320);

/// CRC-32 as IEEE 802.3 defines it (zlib's `crc32`): reflected, polynomial
/// `0xEDB88320`, initial value and final XOR `0xFFFFFFFF`.
pub fn crc32(bytes: &[u8]) -> u32 {
    !bytes.iter().fold(!0u32, |crc, &b| {
        (crc >> 8) ^ TABLE[((crc ^ u32::from(b)) & 0xFF) as usize]
    })
}

#[cfg(test)]
mod tests {
    use super::crc32;

    #[test]
    fn the_standard_check_value() {
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
    }

    #[test]
    fn known_vectors() {
        assert_eq!(crc32(b""), 0);
        assert_eq!(crc32(b"a"), 0xE8B7_BE43);
        assert_eq!(
            crc32(b"The quick brown fox jumps over the lazy dog"),
            0x414F_A339
        );
        assert_eq!(crc32(&[0u8; 32]), 0x190A_55AD);
    }
}
