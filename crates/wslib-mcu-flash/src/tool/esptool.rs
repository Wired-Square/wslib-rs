use std::path::Path;

use async_trait::async_trait;
use tokio::process::Command;

use super::{Flasher, run_cmd_streaming};
use crate::artefact::MaterialisedArtefact;
use crate::error::{FlashError, Result};
use crate::progress::{FlashProgress, FlashStage};

pub const ESPTOOL_BIN: &str = "esptool";

pub struct EsptoolFlasher {
    binary: String,
    chip: String,
    port: String,
    baud: u32,
    artefacts: Vec<MaterialisedArtefact>,
    erase_before_flash: bool,
}

impl EsptoolFlasher {
    pub fn new(
        chip: String,
        port: String,
        baud: u32,
        mut artefacts: Vec<MaterialisedArtefact>,
        erase_before_flash: bool,
    ) -> Result<Self> {
        if artefacts.is_empty() {
            return Err(FlashError::Message(format!("{chip}: nothing to flash")));
        }
        for a in &artefacts {
            if a.offset.is_none() {
                return Err(FlashError::Message(format!(
                    "{chip}: artefact {} has no flash offset",
                    a.kind
                )));
            }
        }
        artefacts.sort_by_key(|a| a.offset);
        Ok(Self {
            binary: ESPTOOL_BIN.to_string(),
            chip,
            port,
            baud,
            artefacts,
            erase_before_flash,
        })
    }

    /// Use another executable name, for hosts that only have `esptool.py`.
    pub fn with_binary(mut self, binary: &str) -> Self {
        self.binary = binary.to_string();
        self
    }

    pub fn write_args(&self) -> Vec<String> {
        let mut args = vec!["write-flash".to_string()];
        for a in &self.artefacts {
            args.push(format!("{:#x}", a.offset.unwrap_or_default()));
            args.push(a.path.to_string_lossy().into_owned());
        }
        args
    }

    fn esptool(&self) -> Command {
        let mut cmd = Command::new(&self.binary);
        cmd.arg("--chip")
            .arg(&self.chip)
            .arg("--port")
            .arg(&self.port)
            .arg("--baud")
            .arg(self.baud.to_string())
            .arg("--before")
            .arg("default-reset")
            .arg("--after")
            .arg("hard-reset");
        cmd
    }
}

#[async_trait]
impl Flasher for EsptoolFlasher {
    fn name(&self) -> &'static str {
        "esptool"
    }

    async fn flash(&self, progress: &mut dyn FlashProgress) -> Result<()> {
        for a in &self.artefacts {
            if !Path::new(&a.path).exists() {
                return Err(FlashError::Message(format!(
                    "{} not found: {}",
                    a.kind,
                    a.path.display()
                )));
            }
        }

        progress.on_stage(
            FlashStage::Connecting,
            &format!("Connecting to {} on {}…", self.chip, self.port),
        );

        if self.erase_before_flash {
            progress.on_stage(FlashStage::Erasing, "Erasing flash…");
            let mut cmd = self.esptool();
            cmd.arg("erase-flash");
            run_cmd_streaming(&mut cmd, "esptool erase", progress).await?;
        }

        let summary: Vec<String> = self
            .artefacts
            .iter()
            .map(|a| format!("{} @ {:#x}", a.kind, a.offset.unwrap_or_default()))
            .collect();
        progress.on_stage(
            FlashStage::Writing,
            &format!("Writing {}…", summary.join(", ")),
        );
        let mut cmd = self.esptool();
        cmd.args(self.write_args());
        run_cmd_streaming(&mut cmd, "esptool write-flash", progress).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn artefact(kind: &str, offset: Option<u32>, path: &str) -> MaterialisedArtefact {
        MaterialisedArtefact {
            kind: kind.into(),
            offset,
            path: path.into(),
        }
    }

    #[test]
    fn write_args_orders_every_artefact_by_offset() {
        let flasher = EsptoolFlasher::new(
            "esp32".into(),
            "/dev/ttyACM2".into(),
            115_200,
            vec![
                artefact("application", Some(0x20000), "/tmp/app"),
                artefact("nvs", Some(0x9000), "/tmp/nvs"),
                artefact("bootloader", Some(0x1000), "/tmp/boot"),
            ],
            false,
        )
        .unwrap();
        assert_eq!(
            flasher.write_args(),
            vec![
                "write-flash",
                "0x1000",
                "/tmp/boot",
                "0x9000",
                "/tmp/nvs",
                "0x20000",
                "/tmp/app"
            ]
        );
    }

    #[test]
    fn artefact_without_offset_is_refused() {
        let err = EsptoolFlasher::new(
            "esp32".into(),
            "/dev/ttyACM2".into(),
            115_200,
            vec![artefact("nvs", None, "/tmp/nvs")],
            false,
        )
        .err()
        .unwrap()
        .to_string();
        assert!(err.contains("nvs"), "{err}");
        assert!(err.contains("offset"), "{err}");
    }

    #[test]
    fn binary_can_be_overridden() {
        let flasher = EsptoolFlasher::new(
            "esp32".into(),
            "/dev/ttyACM2".into(),
            115_200,
            vec![artefact("application", Some(0x20000), "/tmp/app")],
            false,
        )
        .unwrap()
        .with_binary("esptool.py");
        assert_eq!(
            flasher.esptool().as_std().get_program().to_str(),
            Some("esptool.py")
        );
    }
}
