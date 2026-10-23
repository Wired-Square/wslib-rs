use crate::error::{FlashError, Result};

pub const KIND_APPLICATION: &str = "application";
pub const KIND_BOOTLOADER: &str = "bootloader";
pub const KIND_MERGED: &str = "merged";

pub const ESP32_CLASSIC_CHIP: &str = "esp32";
pub const ESP32_CLASSIC_BOOTLOADER_OFFSET: u32 = 0x1000;
pub const ESP32_RISCV_BOOTLOADER_OFFSET: u32 = 0x0;
pub const ESP32_APPLICATION_OFFSET: u32 = 0x20000;
pub const ESPTOOL_DEFAULT_BAUD: u32 = 921_600;
pub const ESPRESSIF_VID: u16 = 0x303A;

const ESP32_FAMILY_PREFIX: &str = "esp32";
const STM32_FAMILY_PREFIX: &str = "stm32";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum ChipFamily {
    Esp32,
    Stm32,
}

impl ChipFamily {
    pub fn as_str(self) -> &'static str {
        match self {
            ChipFamily::Esp32 => "esp32",
            ChipFamily::Stm32 => "stm32",
        }
    }

    pub fn flashes_over_serial(self) -> bool {
        matches!(self, ChipFamily::Esp32)
    }

    pub fn flashes_over_dfu(self) -> bool {
        matches!(self, ChipFamily::Stm32)
    }
}

pub fn classify_chip(chip: &str) -> Result<ChipFamily> {
    if chip.starts_with(ESP32_FAMILY_PREFIX) {
        Ok(ChipFamily::Esp32)
    } else if chip.starts_with(STM32_FAMILY_PREFIX) {
        Ok(ChipFamily::Stm32)
    } else {
        Err(FlashError::Message(format!(
            "chip {chip:?} is not in a supported family"
        )))
    }
}

pub fn bootloader_offset(chip: &str) -> u32 {
    if chip == ESP32_CLASSIC_CHIP {
        ESP32_CLASSIC_BOOTLOADER_OFFSET
    } else {
        ESP32_RISCV_BOOTLOADER_OFFSET
    }
}

pub fn default_offset(chip: &str, kind: &str) -> Option<u32> {
    if classify_chip(chip).ok()?.flashes_over_dfu() {
        return None;
    }
    match kind {
        KIND_MERGED | KIND_BOOTLOADER => Some(bootloader_offset(chip)),
        KIND_APPLICATION => Some(ESP32_APPLICATION_OFFSET),
        _ => None,
    }
}

/// `"esp32s3"` → `"ESP32-S3"`, `"esp32"` → `"ESP32"`, `"esp8266"` → `"ESP8266"`.
pub fn pretty_esp_chip(raw: &str) -> String {
    let lower = raw.to_ascii_lowercase();
    if lower == "esp8266" {
        return "ESP8266".to_string();
    }
    match lower.strip_prefix("esp32") {
        Some("") => "ESP32".to_string(),
        Some(suffix) => format!("ESP32-{}", suffix.to_ascii_uppercase()),
        None => raw.to_string(),
    }
}

/// Chip name and a conservative flash size in KB for an STM32 bootloader PID.
pub fn lookup_stm32_pid(pid: u16) -> (&'static str, Option<u32>) {
    match pid {
        // F0
        0x440 => ("STM32F05x / F030x8", Some(64)),
        0x442 => ("STM32F09x", Some(256)),
        0x444 => ("STM32F03x", Some(32)),
        0x445 => ("STM32F04x", Some(16)),
        0x448 => ("STM32F07x", Some(128)),
        // F1
        0x410 => ("STM32F1 medium-density", Some(128)),
        0x412 => ("STM32F1 low-density", Some(32)),
        0x414 => ("STM32F1 high-density", Some(512)),
        0x418 => ("STM32F105/F107 connectivity", Some(256)),
        0x420 => ("STM32F1 medium-density VL", Some(128)),
        0x428 => ("STM32F1 high-density VL", Some(512)),
        0x430 => ("STM32F1 XL-density", Some(1024)),
        // F2
        0x411 => ("STM32F2", Some(1024)),
        // F3
        0x422 => ("STM32F30x / F31x", Some(256)),
        0x432 => ("STM32F37x", Some(256)),
        0x438 => ("STM32F33x", Some(64)),
        0x439 => ("STM32F35x", Some(64)),
        0x446 => ("STM32F302xD/E / F303xD/E", Some(512)),
        // F4
        0x413 => ("STM32F40x / F41x", Some(1024)),
        0x419 => ("STM32F42x / F43x", Some(2048)),
        0x423 => ("STM32F401x B/C", Some(256)),
        0x431 => ("STM32F411xC/E", Some(512)),
        0x433 => ("STM32F401x D/E", Some(512)),
        0x434 => ("STM32F469 / F479", Some(2048)),
        0x441 => ("STM32F412", Some(1024)),
        0x458 => ("STM32F410", Some(128)),
        0x463 => ("STM32F413 / F423", Some(1536)),
        // F7
        0x449 => ("STM32F74x / F75x", Some(1024)),
        0x451 => ("STM32F76x / F77x", Some(2048)),
        0x452 => ("STM32F72x / F73x", Some(512)),
        // L0
        0x417 => ("STM32L05x / L06x", Some(64)),
        0x425 => ("STM32L03x / L04x", Some(32)),
        0x447 => ("STM32L07x / L08x", Some(192)),
        0x457 => ("STM32L01x / L02x", Some(16)),
        // L1
        0x416 => ("STM32L1 cat.1", Some(128)),
        0x429 => ("STM32L1 cat.2", Some(128)),
        0x427 => ("STM32L1 cat.3", Some(256)),
        0x436 => ("STM32L1 cat.4 / cat.3 medium+", Some(384)),
        0x437 => ("STM32L1 cat.5 / cat.6", Some(512)),
        // L4
        0x415 => ("STM32L47x / L48x", Some(1024)),
        0x435 => ("STM32L43x / L44x", Some(256)),
        0x461 => ("STM32L496 / L4A6", Some(1024)),
        0x462 => ("STM32L45x / L46x", Some(512)),
        0x464 => ("STM32L41x / L42x", Some(128)),
        0x470 => ("STM32L4Rx / L4Sx", Some(2048)),
        0x471 => ("STM32L4P5 / L4Q5", Some(1024)),
        // G0 / G4
        0x460 => ("STM32G07x / G08x", Some(128)),
        0x466 => ("STM32G03x / G04x", Some(64)),
        0x468 => ("STM32G43x / G44x", Some(128)),
        0x469 => ("STM32G47x / G48x", Some(512)),
        // H7
        0x450 => ("STM32H74x / H75x", Some(2048)),
        0x480 => ("STM32H7A3 / H7B3 / H7B0", Some(2048)),
        0x483 => ("STM32H72x / H73x", Some(1024)),
        // WB / WL
        0x495 => ("STM32WB55", Some(1024)),
        0x497 => ("STM32WLEx", Some(256)),
        _ => ("STM32 (unknown)", None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_known_families_and_rejects_others() {
        assert_eq!(classify_chip("esp32c6").unwrap(), ChipFamily::Esp32);
        assert_eq!(classify_chip("esp32").unwrap(), ChipFamily::Esp32);
        assert_eq!(classify_chip("stm32g474").unwrap(), ChipFamily::Stm32);
        assert!(
            classify_chip("rp2040")
                .unwrap_err()
                .to_string()
                .contains("rp2040")
        );
    }

    #[test]
    fn classic_esp32_bootloader_sits_at_0x1000() {
        assert_eq!(bootloader_offset("esp32"), 0x1000);
        assert_eq!(bootloader_offset("esp32c6"), 0);
        assert_eq!(bootloader_offset("esp32s3"), 0);
    }

    #[test]
    fn default_offsets_follow_kind_and_chip() {
        assert_eq!(default_offset("esp32", KIND_MERGED), Some(0x1000));
        assert_eq!(default_offset("esp32c6", KIND_BOOTLOADER), Some(0));
        assert_eq!(default_offset("esp32c6", KIND_APPLICATION), Some(0x20000));
        assert_eq!(default_offset("esp32", "nvs"), None);
        assert_eq!(default_offset("stm32g474", KIND_APPLICATION), None);
        assert_eq!(default_offset("rp2040", KIND_APPLICATION), None);
    }

    #[test]
    fn pretty_esp_chip_handles_known_variants() {
        assert_eq!(pretty_esp_chip("esp32"), "ESP32");
        assert_eq!(pretty_esp_chip("esp32s3"), "ESP32-S3");
        assert_eq!(pretty_esp_chip("esp32c6"), "ESP32-C6");
        assert_eq!(pretty_esp_chip("esp32c61"), "ESP32-C61");
        assert_eq!(pretty_esp_chip("esp8266"), "ESP8266");
        assert_eq!(pretty_esp_chip("foobar"), "foobar");
    }

    #[test]
    fn lookup_stm32_pid_known_and_unknown() {
        assert_eq!(lookup_stm32_pid(0x410).0, "STM32F1 medium-density");
        assert_eq!(lookup_stm32_pid(0x451).0, "STM32F76x / F77x");
        assert_eq!(lookup_stm32_pid(0xFFFF), ("STM32 (unknown)", None));
    }
}
