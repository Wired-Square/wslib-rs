//! `dfu-util` over USB, then a wait for the device to come back as ttys.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use tokio::process::Command;

use super::{Flasher, run_cmd_streaming};
use crate::artefact::MaterialisedArtefact;
use crate::chip::KIND_APPLICATION;
use crate::error::{FlashError, Result};
use crate::ports::{Enumerator, SerialPort, TtySettle};
use crate::progress::{FlashProgress, FlashStage};

pub const DFU_REENUMERATE_TIMEOUT: Duration = Duration::from_secs(30);
pub const DFU_POLL_INTERVAL: Duration = Duration::from_millis(500);

pub struct DfuUtilFlasher {
    usb_serial: String,
    alt: u8,
    image: PathBuf,
    enumerate: Enumerator,
}

impl DfuUtilFlasher {
    pub fn new(
        usb_serial: String,
        alt: u8,
        artefacts: Vec<MaterialisedArtefact>,
        enumerate: Enumerator,
    ) -> Result<Self> {
        let [artefact] = artefacts.as_slice() else {
            return Err(FlashError::Message(format!(
                "DFU flashes exactly one {KIND_APPLICATION} image, got {:?}",
                artefacts
                    .iter()
                    .map(|a| a.kind.as_str())
                    .collect::<Vec<_>>()
            )));
        };
        if artefact.kind != KIND_APPLICATION {
            return Err(FlashError::Message(format!(
                "DFU flashes the {KIND_APPLICATION} image only, got {}",
                artefact.kind
            )));
        }
        if let Some(offset) = artefact.offset {
            return Err(FlashError::Message(format!(
                "DFU targets have no flash offset, got {offset:#x}"
            )));
        }
        Ok(Self {
            usb_serial,
            alt,
            image: artefact.path.clone(),
            enumerate,
        })
    }

    pub fn args(&self) -> Vec<String> {
        vec![
            "-S".into(),
            self.usb_serial.clone(),
            "-a".into(),
            self.alt.to_string(),
            "-D".into(),
            self.image.to_string_lossy().into_owned(),
        ]
    }
}

pub async fn wait_for_ttys(
    enumerate: &Enumerator,
    usb_serial: &str,
    timeout: Duration,
    poll: Duration,
) -> Result<Vec<SerialPort>> {
    let started = Instant::now();
    let mut settle = TtySettle::default();
    loop {
        if let Some(ports) = settle.observe(enumerate(), usb_serial) {
            return Ok(ports);
        }
        if started.elapsed() >= timeout {
            return Err(settle.timeout_error(usb_serial, timeout));
        }
        tokio::time::sleep(poll).await;
    }
}

#[async_trait]
impl Flasher for DfuUtilFlasher {
    fn name(&self) -> &'static str {
        "dfu-util"
    }

    async fn flash(&self, progress: &mut dyn FlashProgress) -> Result<()> {
        if !Path::new(&self.image).exists() {
            return Err(FlashError::Message(format!(
                "{KIND_APPLICATION} not found: {}",
                self.image.display()
            )));
        }
        progress.on_stage(
            FlashStage::Writing,
            &format!(
                "Detaching {} into DFU mode and downloading {} to alt {}…",
                self.usb_serial,
                self.image.display(),
                self.alt
            ),
        );
        let mut cmd = Command::new("dfu-util");
        cmd.args(self.args());
        run_cmd_streaming(&mut cmd, "dfu-util", progress).await?;
        progress.on_stage(
            FlashStage::Booting,
            &format!("Waiting for {} to re-enumerate…", self.usb_serial),
        );
        let ports = wait_for_ttys(
            &self.enumerate,
            &self.usb_serial,
            DFU_REENUMERATE_TIMEOUT,
            DFU_POLL_INTERVAL,
        )
        .await?;
        let paths: Vec<&str> = ports.iter().map(|p| p.path.as_str()).collect();
        progress.on_progress(&format!(
            "{} is back on {}",
            self.usb_serial,
            paths.join(", ")
        ));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::*;

    fn artefact(kind: &str, offset: Option<u32>) -> MaterialisedArtefact {
        MaterialisedArtefact {
            kind: kind.into(),
            offset,
            path: "/tmp/zephyr.signed.bin".into(),
        }
    }

    fn port(path: &str, serial: &str) -> SerialPort {
        SerialPort::new(path, Some(serial), Some(1))
    }

    fn sequence(snapshots: Vec<Vec<SerialPort>>) -> Enumerator {
        let remaining = Mutex::new(snapshots);
        Arc::new(move || {
            let mut r = remaining.lock().unwrap();
            if r.len() > 1 {
                r.remove(0)
            } else {
                r.first().cloned().unwrap_or_default()
            }
        })
    }

    #[test]
    fn args_name_the_serial_alt_and_image() {
        let flasher = DfuUtilFlasher::new(
            "4B30".into(),
            0,
            vec![artefact("application", None)],
            Arc::new(Vec::new),
        )
        .unwrap();
        assert_eq!(
            flasher.args(),
            vec!["-S", "4B30", "-a", "0", "-D", "/tmp/zephyr.signed.bin"]
        );
    }

    #[test]
    fn refuses_anything_but_one_offsetless_application() {
        let two = DfuUtilFlasher::new(
            "S".into(),
            0,
            vec![artefact("application", None), artefact("nvs", None)],
            Arc::new(Vec::new),
        );
        assert!(two.is_err());
        let wrong_kind = DfuUtilFlasher::new(
            "S".into(),
            0,
            vec![artefact("merged", None)],
            Arc::new(Vec::new),
        );
        assert!(wrong_kind.is_err());
        let with_offset = DfuUtilFlasher::new(
            "S".into(),
            0,
            vec![artefact("application", Some(0x8000000))],
            Arc::new(Vec::new),
        );
        assert!(with_offset.is_err());
    }

    #[tokio::test]
    async fn wait_for_ttys_waits_until_the_composite_stops_growing() {
        let console = port("/dev/ttyACM1", "S");
        let bridge = port("/dev/ttyACM2", "S");
        let enumerate = sequence(vec![
            vec![],
            vec![console.clone()],
            vec![console.clone(), bridge.clone()],
            vec![console.clone(), bridge.clone()],
        ]);
        let ports = wait_for_ttys(
            &enumerate,
            "S",
            Duration::from_secs(5),
            Duration::from_millis(1),
        )
        .await
        .unwrap();
        let paths: Vec<&str> = ports.iter().map(|p| p.path.as_str()).collect();
        assert_eq!(paths, vec!["/dev/ttyACM1", "/dev/ttyACM2"]);
    }

    #[tokio::test]
    async fn wait_for_ttys_times_out_with_a_snapshot() {
        let enumerate = sequence(vec![vec![port("/dev/ttyACM0", "OTHER")]]);
        let err = wait_for_ttys(
            &enumerate,
            "S",
            Duration::from_millis(30),
            Duration::from_millis(5),
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(err.contains("re-enumerate"), "{err}");
        assert!(err.contains("/dev/ttyACM0 (OTHER)"), "{err}");
    }
}
