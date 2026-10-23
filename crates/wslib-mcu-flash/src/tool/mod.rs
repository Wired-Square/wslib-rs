//! Backends that drive an external flashing tool as a child process,
//! relaying its output line by line.

#[cfg(feature = "dfu-util")]
pub mod dfu_util;
#[cfg(feature = "esptool")]
pub mod esptool;

use async_trait::async_trait;
use tokio::io::{AsyncBufReadExt, AsyncRead, BufReader};
use tokio::process::Command;
use tokio::sync::mpsc;

use crate::error::{FlashError, Result};
use crate::progress::FlashProgress;

#[cfg(feature = "dfu-util")]
pub use dfu_util::DfuUtilFlasher;
#[cfg(feature = "esptool")]
pub use esptool::EsptoolFlasher;

#[async_trait]
pub trait Flasher: Send + Sync {
    fn name(&self) -> &'static str;

    async fn flash(&self, progress: &mut dyn FlashProgress) -> Result<()>;
}

enum Line {
    Out(String),
    Err(String),
}

fn relay<R: AsyncRead + Unpin + Send + 'static>(
    reader: Option<R>,
    tx: mpsc::UnboundedSender<Line>,
    wrap: fn(String) -> Line,
) {
    tokio::spawn(async move {
        if let Some(reader) = reader {
            let mut lines = BufReader::new(reader).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                if tx.send(wrap(line)).is_err() {
                    break;
                }
            }
        }
    });
}

/// Run `cmd`, forward every non-blank stdout and stderr line to `progress`
/// as it arrives, and fail with stderr when it exits non-zero.
pub async fn run_cmd_streaming(
    cmd: &mut Command,
    label: &str,
    progress: &mut dyn FlashProgress,
) -> Result<()> {
    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::piped());

    let mut child = cmd
        .spawn()
        .map_err(|e| FlashError::Message(format!("failed to spawn {label}: {e}")))?;

    let (tx, mut rx) = mpsc::unbounded_channel();
    relay(child.stdout.take(), tx.clone(), Line::Out);
    relay(child.stderr.take(), tx, Line::Err);

    let mut stderr_lines = Vec::new();
    while let Some(line) = rx.recv().await {
        let (text, is_err) = match line {
            Line::Out(text) => (text, false),
            Line::Err(text) => (text, true),
        };
        if !text.trim().is_empty() {
            progress.on_progress(&text);
        }
        if is_err {
            stderr_lines.push(text);
        }
    }

    let status = child
        .wait()
        .await
        .map_err(|e| FlashError::Message(format!("{label} wait failed: {e}")))?;

    if !status.success() {
        return Err(FlashError::Message(format!(
            "{label} failed (exit {status}): {}",
            stderr_lines.join("\n").trim()
        )));
    }

    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::progress::LogProgress;

    #[tokio::test]
    async fn lines_are_relayed_and_stderr_names_the_failure() {
        let mut cmd = Command::new("sh");
        cmd.args(["-c", "echo one; echo two 1>&2; exit 3"]);
        let mut log = LogProgress::default();
        let err = run_cmd_streaming(&mut cmd, "sh", &mut log)
            .await
            .unwrap_err()
            .to_string();
        assert!(log.0.contains(&"one".to_string()), "{:?}", log.0);
        assert!(log.0.contains(&"two".to_string()), "{:?}", log.0);
        assert!(err.contains("exit status: 3"), "{err}");
        assert!(err.contains("two"), "{err}");
    }
}
