use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::Error;
use crate::frame::{Bytes, BytesRef};
use crate::session::{CHUNK_TIMEOUT, FIRST_CHUNK_TIMEOUT};

/// The image group's commands.
pub(crate) const CMD_STATE: u8 = 0;
pub(crate) const CMD_UPLOAD: u8 = 1;

/// One image slot, as the image group's state read reports it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct ImageSlot {
    pub slot: i32,
    pub version: String,
    /// The image's SHA-256, as MCUboot stores it.
    pub hash: Vec<u8>,
    pub bootable: bool,
    pub pending: bool,
    pub confirmed: bool,
    pub active: bool,
    pub permanent: bool,
    /// Which image, on a device with more than one.
    pub image: Option<i32>,
}

/// How [`Session::upload`](crate::Session::upload) sends an image.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct UploadOptions {
    /// Which image, on a device with more than one; 0 by default.
    pub image: u8,
    /// How long the first chunk's reply may take, while the device erases
    /// the slot.
    pub first_chunk_timeout: Duration,
    /// How long a later chunk's reply may take before the upload resumes.
    pub chunk_timeout: Duration,
}

impl Default for UploadOptions {
    fn default() -> Self {
        Self {
            image: 0,
            first_chunk_timeout: FIRST_CHUNK_TIMEOUT,
            chunk_timeout: CHUNK_TIMEOUT,
        }
    }
}

impl UploadOptions {
    pub fn with_image(self, image: u8) -> Self {
        Self { image, ..self }
    }

    pub fn with_first_chunk_timeout(self, first_chunk_timeout: Duration) -> Self {
        Self {
            first_chunk_timeout,
            ..self
        }
    }

    pub fn with_chunk_timeout(self, chunk_timeout: Duration) -> Self {
        Self {
            chunk_timeout,
            ..self
        }
    }
}

/// One acknowledged step of an upload.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct UploadProgress {
    pub bytes_sent: usize,
    pub total_bytes: usize,
    /// On the final event, the image's hash for [`test`] and [`confirm`].
    ///
    /// [`test`]: crate::Session::test
    /// [`confirm`]: crate::Session::confirm
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image_hash: Option<Vec<u8>>,
    /// On the first event after the upload lost ground, the offset it lost.
    #[serde(default)]
    pub resumed_from: Option<usize>,
}

impl UploadProgress {
    pub fn percent(&self) -> f32 {
        if self.total_bytes == 0 {
            100.0
        } else {
            self.bytes_sent as f32 / self.total_bytes as f32 * 100.0
        }
    }

    pub fn is_complete(&self) -> bool {
        self.bytes_sent >= self.total_bytes
    }
}

#[derive(Deserialize)]
pub(crate) struct StateResponse {
    #[serde(default)]
    pub images: Vec<SlotWire>,
}

/// Zephyr leaves out a flag that is false.
#[derive(Deserialize)]
pub(crate) struct SlotWire {
    #[serde(default)]
    image: Option<i32>,
    slot: i32,
    #[serde(default)]
    version: String,
    #[serde(default)]
    hash: Bytes,
    #[serde(default)]
    bootable: bool,
    #[serde(default)]
    pending: bool,
    #[serde(default)]
    confirmed: bool,
    #[serde(default)]
    active: bool,
    #[serde(default)]
    permanent: bool,
}

impl From<SlotWire> for ImageSlot {
    fn from(w: SlotWire) -> Self {
        Self {
            slot: w.slot,
            version: w.version,
            hash: w.hash.0,
            bootable: w.bootable,
            pending: w.pending,
            confirmed: w.confirmed,
            active: w.active,
            permanent: w.permanent,
            image: w.image,
        }
    }
}

/// An empty `hash` with `confirm` confirms the running image.
#[derive(Serialize)]
pub(crate) struct StateWrite<'a> {
    pub hash: BytesRef<'a>,
    pub confirm: bool,
}

/// `image`, `len` and `sha` go on the first chunk only.
#[derive(Serialize)]
pub(crate) struct UploadChunk<'a> {
    pub data: BytesRef<'a>,
    pub off: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub len: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha: Option<BytesRef<'a>>,
}

#[derive(Deserialize)]
pub(crate) struct UploadAck {
    pub off: usize,
    /// Set on the last chunk by a device built to check the whole-image `sha`.
    #[serde(default, rename = "match")]
    pub matched: Option<bool>,
}

/// The value of the image's IMAGE_TLV_SHA256, which is what the device
/// matches a state write's `hash` against. Layout per MCUboot's `image.h`,
/// little-endian: magic, load address, header size, protected TLV size and
/// image size, then after the body the TLV info (magic `0x6907`, total) and
/// each TLV as type, reserved, length, value.
pub(crate) fn mcuboot_image_hash(bin: &[u8]) -> Result<Vec<u8>, Error> {
    const MAGIC: u32 = 0x96f3_b83d;
    const TLV_INFO_MAGIC: u16 = 0x6907;
    const TLV_SHA256: u8 = 0x10;
    const SHA256_LEN: usize = 32;

    let le16 = |at: usize| u16::from_le_bytes([bin[at], bin[at + 1]]) as usize;
    if bin.len() < 16 {
        return Err(Error::NotMcuboot(format!(
            "{} bytes is too small for a header",
            bin.len()
        )));
    }
    let magic = u32::from_le_bytes([bin[0], bin[1], bin[2], bin[3]]);
    if magic != MAGIC {
        return Err(Error::NotMcuboot(format!("magic {magic:#010x}")));
    }
    let img_size = u32::from_le_bytes([bin[12], bin[13], bin[14], bin[15]]) as usize;
    let tlv_off = le16(8)
        .checked_add(img_size)
        .and_then(|v| v.checked_add(le16(10)))
        .filter(|off| off + 4 <= bin.len())
        .ok_or_else(|| Error::NotMcuboot("its TLVs lie past its end".into()))?;
    if le16(tlv_off) as u16 != TLV_INFO_MAGIC {
        return Err(Error::NotMcuboot(format!(
            "TLV info magic {:#06x}",
            le16(tlv_off)
        )));
    }
    let tlv_end = tlv_off + le16(tlv_off + 2);
    if tlv_end > bin.len() {
        return Err(Error::NotMcuboot("its TLVs run past its end".into()));
    }
    let mut at = tlv_off + 4;
    while at + 4 <= tlv_end {
        let len = le16(at + 2);
        if bin[at] == TLV_SHA256 && len == SHA256_LEN && at + 4 + len <= tlv_end {
            return Ok(bin[at + 4..at + 4 + len].to_vec());
        }
        at += 4 + len;
    }
    Err(Error::NotMcuboot("no SHA-256 TLV".into()))
}

#[cfg(test)]
pub(crate) fn make_image(hash: [u8; 32], body: &[u8]) -> Vec<u8> {
    let mut bin = Vec::new();
    bin.extend_from_slice(&0x96f3_b83d_u32.to_le_bytes());
    bin.extend_from_slice(&0_u32.to_le_bytes());
    bin.extend_from_slice(&16_u16.to_le_bytes());
    bin.extend_from_slice(&0_u16.to_le_bytes());
    bin.extend_from_slice(&(body.len() as u32).to_le_bytes());
    bin.extend_from_slice(body);
    bin.extend_from_slice(&0x6907_u16.to_le_bytes());
    bin.extend_from_slice(&40_u16.to_le_bytes());
    bin.extend_from_slice(&[0x10, 0x00]);
    bin.extend_from_slice(&32_u16.to_le_bytes());
    bin.extend_from_slice(&hash);
    bin
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_the_sha256_tlv() {
        let bin = make_image([0xAB; 32], &[0xCC; 64]);
        assert_eq!(mcuboot_image_hash(&bin).unwrap(), [0xAB; 32]);
    }

    #[test]
    fn refuses_other_magic_and_a_truncated_header() {
        let mut bin = make_image([0xAB; 32], &[0xCC; 64]);
        bin[0] = 0;
        assert!(matches!(
            mcuboot_image_hash(&bin),
            Err(Error::NotMcuboot(_))
        ));
        assert!(matches!(
            mcuboot_image_hash(&[0; 8]),
            Err(Error::NotMcuboot(_))
        ));
    }

    #[test]
    fn refuses_an_image_cut_short() {
        let bin = make_image([0xAB; 32], &[0xCC; 64]);
        assert!(matches!(
            mcuboot_image_hash(&bin[..bin.len() - 8]),
            Err(Error::NotMcuboot(_))
        ));
    }

    #[test]
    fn upload_progress_percent_and_completion() {
        let p = |sent, total| UploadProgress {
            bytes_sent: sent,
            total_bytes: total,
            image_hash: None,
            resumed_from: None,
        };
        assert!((p(250, 1000).percent() - 25.0).abs() < f32::EPSILON);
        assert_eq!(p(0, 0).percent(), 100.0);
        assert!(p(0, 0).is_complete());
        assert!(p(1000, 1000).is_complete());
    }

    // CBOR by hand from the spec's state response, flags left out when false.
    #[test]
    fn a_slot_without_its_false_flags_decodes() {
        let mut map = vec![0xa4, 0x64];
        map.extend_from_slice(b"slot");
        map.push(0x01);
        map.push(0x67);
        map.extend_from_slice(b"version");
        map.push(0x65);
        map.extend_from_slice(b"1.2.3");
        map.push(0x64);
        map.extend_from_slice(b"hash");
        map.extend_from_slice(&[0x42, 0xde, 0xad]);
        map.push(0x68);
        map.extend_from_slice(b"bootable");
        map.push(0xf5);
        let slot: ImageSlot = ciborium::from_reader::<SlotWire, _>(&map[..])
            .unwrap()
            .into();
        assert_eq!(slot.slot, 1);
        assert_eq!(slot.version, "1.2.3");
        assert_eq!(slot.hash, [0xde, 0xad]);
        assert!(slot.bootable && !slot.active && !slot.confirmed);
        assert_eq!(slot.image, None);
    }
}
