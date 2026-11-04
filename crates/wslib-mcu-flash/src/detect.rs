//! One probe for any serial-bootloader chip: STM32 first, because its sync
//! is a single byte with a tight timeout, then ESP.

use crate::chip::{ChipFamily, pretty_esp_chip};
use crate::error::{FlashError, Result};
use crate::esp::{self, EspChipInfo, EspFlashOptions};
use crate::stm32_uart::{self, Stm32ChipInfo, Stm32UartOptions};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Detected {
    Esp(EspChipInfo),
    Stm32(Stm32ChipInfo),
}

impl Detected {
    pub fn family(&self) -> ChipFamily {
        match self {
            Detected::Esp(_) => ChipFamily::Esp32,
            Detected::Stm32(_) => ChipFamily::Stm32,
        }
    }

    pub fn chip_name(&self) -> String {
        match self {
            Detected::Esp(info) => pretty_esp_chip(&info.chip),
            Detected::Stm32(info) => info.chip.clone(),
        }
    }

    pub fn flash_size_kb(&self) -> Option<u32> {
        match self {
            Detected::Esp(info) => info.flash_size_bytes.map(|b| (b / 1024) as u32),
            Detected::Stm32(info) => info.flash_size_kb,
        }
    }
}

pub fn detect(port: &str, stm32_options: &Stm32UartOptions) -> Result<Detected> {
    let stm32_err = match stm32_uart::detect_chip(port, stm32_options) {
        Ok(info) => return Ok(Detected::Stm32(info)),
        Err(e) => e,
    };
    let esp_err = match esp::detect_chip(port, &EspFlashOptions::default()) {
        Ok(info) => return Ok(Detected::Esp(info)),
        Err(e) => e,
    };
    Err(FlashError::Message(format!(
        "Could not identify chip on {port}.\nSTM32 (AN3155): {stm32_err}\nESP (esptool): {esp_err}"
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detected_summarises_either_family() {
        let esp = Detected::Esp(EspChipInfo {
            chip: "esp32s3".into(),
            features: vec![],
            mac: None,
            flash_size_bytes: Some(8 * 1024 * 1024),
        });
        assert_eq!(esp.family(), ChipFamily::Esp32);
        assert_eq!(esp.chip_name(), "ESP32-S3");
        assert_eq!(esp.flash_size_kb(), Some(8192));

        let stm = Detected::Stm32(Stm32ChipInfo {
            chip: "STM32F1 medium-density".into(),
            pid: 0x410,
            bootloader_version: "2.2".into(),
            flash_size_kb: Some(128),
            rdp_level: None,
        });
        assert_eq!(stm.family(), ChipFamily::Stm32);
        assert_eq!(stm.chip_name(), "STM32F1 medium-density");
        assert_eq!(stm.flash_size_kb(), Some(128));
    }
}
