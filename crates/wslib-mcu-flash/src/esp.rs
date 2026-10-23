//! ESP32-family flashing in process over `espflash`. Every function here
//! blocks on the serial port; wrap calls in `spawn_blocking`.
//!
//! `read_flash` drives the bootloader's `ReadFlash` command itself rather
//! than `Flasher::read_flash`, which truncates its output file per call:
//! chunking is what gives progress and a cancel point.

use std::io::Write as _;
use std::path::Path;
use std::str::FromStr;
use std::time::Duration;

pub use espflash;
use espflash::command::{Command, CommandType};
use espflash::connection::{Connection, ResetAfterOperation, ResetBeforeOperation};
use espflash::flasher::{FlashFrequency, FlashMode, FlashSize, Flasher};
use espflash::target::{Chip, ProgressCallbacks};
use serialport::UsbPortInfo;

use crate::chip::ESPTOOL_DEFAULT_BAUD;
use crate::error::{FlashError, Result};
use crate::ports;
use crate::progress::{FlashProgress, FlashStage, check_cancel};

const READ_CHUNK_SIZE: u32 = 64 * 1024;
const READ_BLOCK_SIZE: u32 = 1024;
const READ_MAX_IN_FLIGHT: u32 = 64;
const ESP_IMAGE_MAGIC: u8 = 0xE9;

/// Flasher tuning; `None` leaves espflash's own default in place.
#[derive(Debug, Clone, Default)]
pub struct EspFlashOptions {
    pub chip: Option<Chip>,
    pub flash_baud: Option<u32>,
    pub flash_mode: Option<FlashMode>,
    pub flash_freq: Option<FlashFrequency>,
    pub flash_size: Option<FlashSize>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct EspChipInfo {
    pub chip: String,
    pub features: Vec<String>,
    pub mac: String,
    pub flash_size_bytes: Option<u64>,
}

pub fn detect_chip(port: &str, options: &EspFlashOptions) -> Result<EspChipInfo> {
    chip_info_from(&mut open_flasher(port, options)?)
}

pub fn flash(
    port: &str,
    image_path: &Path,
    address: u32,
    options: &EspFlashOptions,
    progress: &mut dyn FlashProgress,
) -> Result<()> {
    progress.on_stage(FlashStage::Connecting, &format!("Opening {port}"));
    let mut flasher = open_flasher(port, options)?;

    if let Ok(info) = chip_info_from(&mut flasher) {
        progress.on_progress(&format!(
            "Connected: {} · MAC {} · {}",
            info.chip,
            info.mac,
            info.flash_size_bytes
                .map(|b| format!("{} MB flash", b / (1024 * 1024)))
                .unwrap_or_else(|| "flash size unknown".to_string()),
        ));
    }

    if let Some(size) = options.flash_size {
        flasher.set_flash_size(size);
    }

    let mut buffer = std::fs::read(image_path).map_err(|e| {
        FlashError::Message(format!("Failed to read {}: {e}", image_path.display()))
    })?;

    if address == 0x0
        && let Some(notes) = patch_image_header(&mut buffer, options, flasher.chip())?
    {
        progress.on_progress(&format!("Patched image header: {notes}"));
    }

    check_cancel(progress)?;

    let total = buffer.len() as u64;
    progress.on_stage(
        FlashStage::Writing,
        &format!("Writing {total} bytes to 0x{address:x}"),
    );

    let mut callbacks = Callbacks { progress, total };
    flasher
        .write_bin_to_flash(address, &buffer, &mut callbacks)
        .map_err(|e| FlashError::Message(format!("Flash write failed: {e}")))?;

    check_cancel(progress)?;
    progress.on_stage(FlashStage::Resetting, "Flash complete; chip will reset");
    Ok(())
}

pub fn read_flash(
    port: &str,
    output_path: &Path,
    offset: u32,
    size: Option<u32>,
    options: &EspFlashOptions,
    progress: &mut dyn FlashProgress,
) -> Result<()> {
    progress.on_stage(FlashStage::Connecting, &format!("Opening {port}"));
    let mut flasher = open_flasher(port, options)?;

    let resolved_size = match size {
        Some(s) => s,
        None => flasher
            .flash_detect()
            .ok()
            .flatten()
            .map(|detected| detected.size())
            .ok_or_else(|| {
                FlashError::Message(
                    "Could not auto-detect flash size; specify size or pick one from the form"
                        .to_string(),
                )
            })?,
    };

    let total = resolved_size as u64;
    progress.on_stage(
        FlashStage::Writing,
        &format!(
            "Reading {total} bytes from 0x{offset:x} to {}",
            output_path.display()
        ),
    );

    let mut file = std::fs::File::create(output_path).map_err(|e| {
        FlashError::Message(format!("Failed to open {}: {e}", output_path.display()))
    })?;

    let mut bytes_done: u64 = 0;
    let mut current_offset = offset;
    let mut remaining = resolved_size;

    while remaining > 0 {
        check_cancel(progress)?;

        let chunk_size = remaining.min(READ_CHUNK_SIZE);
        let chunk = read_chunk(
            flasher.connection(),
            current_offset,
            chunk_size,
            READ_BLOCK_SIZE.min(chunk_size),
            READ_MAX_IN_FLIGHT,
        )?;

        file.write_all(&chunk).map_err(|e| {
            FlashError::Message(format!("Failed to write {}: {e}", output_path.display()))
        })?;

        bytes_done += chunk.len() as u64;
        current_offset = current_offset.saturating_add(chunk.len() as u32);
        remaining = remaining.saturating_sub(chunk.len() as u32);
        progress.on_bytes(bytes_done, total);
    }

    file.sync_all().ok();
    progress.on_progress(&format!("Saved {total} bytes to {}", output_path.display()));
    Ok(())
}

pub fn erase(
    port: &str,
    options: &EspFlashOptions,
    progress: &mut dyn FlashProgress,
) -> Result<()> {
    progress.on_stage(FlashStage::Connecting, &format!("Opening {port}"));
    let mut flasher = open_flasher(port, options)?;
    progress.on_stage(
        FlashStage::Erasing,
        "Erasing entire flash — this can take a minute…",
    );
    flasher
        .erase_flash()
        .map_err(|e| FlashError::Message(format!("Erase failed: {e}")))
}

fn open_flasher(port: &str, options: &EspFlashOptions) -> Result<Flasher> {
    let target_baud = options.flash_baud.unwrap_or(ESPTOOL_DEFAULT_BAUD);

    // The bootloader handshake is always at 115 200; espflash raises the rate after sync.
    let serial = serialport::new(port, 115_200)
        .timeout(Duration::from_millis(3_000))
        .open_native()
        .map_err(|e| FlashError::Message(format!("Failed to open serial port {port}: {e}")))?;

    let connection = Connection::new(
        serial,
        usb_port_info(port),
        ResetAfterOperation::HardReset,
        ResetBeforeOperation::DefaultReset,
        target_baud,
    );

    Flasher::connect(
        connection,
        true,
        false,
        false,
        options.chip,
        Some(target_baud),
    )
    .map_err(|e| FlashError::Message(format!("Bootloader handshake failed: {e}")))
}

fn usb_port_info(port: &str) -> UsbPortInfo {
    match ports::usb_info_for(port) {
        Some(p) => UsbPortInfo {
            vid: p.vid,
            pid: p.pid,
            serial_number: p.serial_number,
            manufacturer: p.manufacturer,
            product: p.product,
            interface: p.interface,
        },
        None => UsbPortInfo {
            vid: 0,
            pid: 0,
            serial_number: None,
            manufacturer: None,
            product: None,
            interface: None,
        },
    }
}

fn chip_info_from(flasher: &mut Flasher) -> Result<EspChipInfo> {
    let info = flasher
        .device_info()
        .map_err(|e| FlashError::Message(format!("Failed to read chip info: {e}")))?;
    Ok(EspChipInfo {
        chip: info.chip.to_string(),
        features: info.features.clone(),
        mac: info
            .mac_address
            .clone()
            .unwrap_or_else(|| "(unknown)".to_string()),
        flash_size_bytes: Some(info.flash_size.size() as u64),
    })
}

/// Mirror `esptool write-flash --flash-mode/freq/size` on a bootloader image.
fn patch_image_header(
    buffer: &mut [u8],
    options: &EspFlashOptions,
    chip: Chip,
) -> Result<Option<String>> {
    if buffer.len() < 4 || buffer[0] != ESP_IMAGE_MAGIC {
        return Ok(None);
    }

    let mut notes: Vec<String> = Vec::new();

    if let Some(mode) = options.flash_mode {
        buffer[2] = mode as u8;
        notes.push(format!("mode={mode:?}"));
    }

    if options.flash_size.is_some() || options.flash_freq.is_some() {
        let existing = buffer[3];
        let mut size_nibble = (existing >> 4) & 0x0F;
        let mut freq_nibble = existing & 0x0F;

        if let Some(size) = options.flash_size {
            size_nibble = size
                .encode_flash_size()
                .map_err(|e| FlashError::Message(format!("Unsupported flash size: {e}")))?;
            notes.push(format!("size={size:?}"));
        }
        if let Some(freq) = options.flash_freq {
            freq_nibble = freq
                .encode_flash_frequency(chip)
                .map_err(|e| FlashError::Message(format!("Unsupported flash freq: {e}")))?;
            notes.push(format!("freq={freq:?}"));
        }

        buffer[3] = (size_nibble << 4) | (freq_nibble & 0x0F);
    }

    Ok((!notes.is_empty()).then(|| notes.join(", ")))
}

fn read_chunk(
    connection: &mut Connection,
    offset: u32,
    size: u32,
    block_size: u32,
    max_in_flight: u32,
) -> Result<Vec<u8>> {
    connection
        .with_timeout(CommandType::ReadFlash.timeout(), |c| {
            c.command(Command::ReadFlash {
                offset,
                size,
                block_size,
                max_in_flight,
            })
        })
        .map_err(|e| FlashError::Message(format!("ReadFlash command failed: {e}")))?;

    let mut data: Vec<u8> = Vec::with_capacity(size as usize);
    while data.len() < size as usize {
        let response = connection
            .read_flash_response()
            .map_err(|e| FlashError::Message(format!("Flash read response failed: {e}")))?;
        let chunk: Vec<u8> = match response {
            Some(r) => r
                .value
                .try_into()
                .map_err(|e| FlashError::Message(format!("Bad flash chunk response: {e}")))?,
            None => return Err("No response while reading flash".into()),
        };
        data.extend_from_slice(&chunk);
        if data.len() < size as usize && (chunk.len() as u32) < block_size {
            return Err(FlashError::Message(format!(
                "Truncated flash read: got {} of {} bytes",
                data.len(),
                size
            )));
        }
        connection
            .write_raw(data.len() as u32)
            .map_err(|e| FlashError::Message(format!("Flash read ack failed: {e}")))?;
    }

    // The bootloader follows up with an MD5 digest; drain it so the next command stays in sync.
    let _ = connection.read_flash_response();

    Ok(data)
}

struct Callbacks<'a> {
    progress: &'a mut dyn FlashProgress,
    total: u64,
}

impl ProgressCallbacks for Callbacks<'_> {
    fn init(&mut self, _addr: u32, total: usize) {
        self.total = total as u64;
        self.progress.on_bytes(0, self.total);
    }

    fn update(&mut self, current: usize) {
        self.progress.on_bytes(current as u64, self.total);
    }

    fn verifying(&mut self) {
        self.progress.on_stage(FlashStage::Verifying, "Verifying…");
    }

    fn finish(&mut self, _skipped: bool) {
        self.progress.on_bytes(self.total, self.total);
    }
}

fn explicit(s: Option<&str>) -> Option<&str> {
    s.map(str::trim)
        .filter(|t| !t.is_empty() && !t.eq_ignore_ascii_case("auto"))
}

pub fn parse_chip(s: Option<&str>) -> Result<Option<Chip>> {
    explicit(s)
        .map(|raw| {
            Chip::from_str(&raw.to_ascii_lowercase())
                .map_err(|e| FlashError::Message(format!("Unknown chip {raw:?}: {e}")))
        })
        .transpose()
}

pub fn parse_flash_mode(s: Option<&str>) -> Result<Option<FlashMode>> {
    explicit(s)
        .map(|raw| match raw.to_ascii_lowercase().as_str() {
            "qio" => Ok(FlashMode::Qio),
            "qout" => Ok(FlashMode::Qout),
            "dio" => Ok(FlashMode::Dio),
            "dout" => Ok(FlashMode::Dout),
            other => Err(FlashError::Message(format!("Unknown flash mode {other:?}"))),
        })
        .transpose()
}

pub fn parse_flash_size(s: Option<&str>) -> Result<Option<FlashSize>> {
    explicit(s)
        .map(|raw| {
            FlashSize::from_str(raw)
                .map_err(|e| FlashError::Message(format!("Unknown flash size {raw:?}: {e}")))
        })
        .transpose()
}

pub fn parse_flash_freq(s: Option<&str>) -> Result<Option<FlashFrequency>> {
    explicit(s)
        .map(|raw| {
            let freq = match raw
                .to_ascii_lowercase()
                .trim_end_matches("hz")
                .trim_end_matches('m')
            {
                "12" => FlashFrequency::_12Mhz,
                "15" => FlashFrequency::_15Mhz,
                "16" => FlashFrequency::_16Mhz,
                "20" => FlashFrequency::_20Mhz,
                "24" => FlashFrequency::_24Mhz,
                "26" => FlashFrequency::_26Mhz,
                "30" => FlashFrequency::_30Mhz,
                "40" => FlashFrequency::_40Mhz,
                "48" => FlashFrequency::_48Mhz,
                "60" => FlashFrequency::_60Mhz,
                "80" => FlashFrequency::_80Mhz,
                other => {
                    return Err(FlashError::Message(format!("Unknown flash freq {other:?}")));
                }
            };
            Ok(freq)
        })
        .transpose()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auto_and_blank_mean_none() {
        assert_eq!(parse_chip(None).unwrap(), None);
        assert_eq!(parse_chip(Some(" auto ")).unwrap(), None);
        assert_eq!(parse_flash_mode(Some("")).unwrap(), None);
        assert_eq!(parse_flash_size(Some("AUTO")).unwrap(), None);
        assert_eq!(parse_flash_freq(None).unwrap(), None);
    }

    #[test]
    fn parsers_accept_the_esptool_spellings() {
        assert_eq!(parse_chip(Some("ESP32S3")).unwrap(), Some(Chip::Esp32s3));
        assert_eq!(parse_flash_mode(Some("DIO")).unwrap(), Some(FlashMode::Dio));
        assert_eq!(
            parse_flash_size(Some("4MB")).unwrap(),
            Some(FlashSize::_4Mb)
        );
        assert_eq!(
            parse_flash_freq(Some("40MHz")).unwrap(),
            Some(FlashFrequency::_40Mhz)
        );
        assert_eq!(
            parse_flash_freq(Some("80m")).unwrap(),
            Some(FlashFrequency::_80Mhz)
        );
    }

    #[test]
    fn parsers_name_the_bad_value() {
        assert!(
            parse_chip(Some("z80"))
                .unwrap_err()
                .to_string()
                .contains("z80")
        );
        assert!(parse_flash_mode(Some("spi")).is_err());
        assert!(parse_flash_freq(Some("99")).is_err());
    }

    #[test]
    fn header_patch_only_touches_espressif_images() {
        let options = EspFlashOptions {
            flash_mode: Some(FlashMode::Dio),
            flash_size: Some(FlashSize::_4Mb),
            ..Default::default()
        };
        let mut plain = vec![0u8; 8];
        assert_eq!(
            patch_image_header(&mut plain, &options, Chip::Esp32).unwrap(),
            None
        );

        let mut image = vec![ESP_IMAGE_MAGIC, 0x03, 0x00, 0x0F];
        let notes = patch_image_header(&mut image, &options, Chip::Esp32)
            .unwrap()
            .unwrap();
        assert!(notes.contains("mode=Dio"), "{notes}");
        assert_eq!(image[2], FlashMode::Dio as u8);
        assert_eq!(image[3] & 0x0F, 0x0F);
        assert_eq!(image[3] >> 4, FlashSize::_4Mb.encode_flash_size().unwrap());
    }
}
