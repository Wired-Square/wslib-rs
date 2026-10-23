//! Backends that drive an external flashing tool as a child process,
//! relaying its output line by line.

#[cfg(feature = "dfu-util")]
pub mod dfu_util;
#[cfg(feature = "esptool")]
pub mod esptool;

use async_trait::async_trait;
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncRead, BufReader};
use tokio::process::Command;
use tokio::sync::mpsc;
use tokio::time::timeout;

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

const CANCEL_POLL: Duration = Duration::from_millis(100);

enum Line {
    Out(String),
    Err(String),
}

/// Splits on `\n` and on the `\r` esptool ends a progress update with, and
/// decodes lossily: a reader that stopped early would close the pipe and
/// could kill the tool mid-flash.
fn relay<R: AsyncRead + Unpin + Send + 'static>(
    reader: Option<R>,
    tx: mpsc::UnboundedSender<Line>,
    wrap: fn(String) -> Line,
) {
    tokio::spawn(async move {
        let Some(reader) = reader else { return };
        let mut reader = BufReader::new(reader);
        let mut line = Vec::new();
        loop {
            let buf = match reader.fill_buf().await {
                Ok(buf) if !buf.is_empty() => buf,
                _ => break,
            };
            let end = buf.iter().position(|b| matches!(b, b'\n' | b'\r'));
            line.extend_from_slice(&buf[..end.unwrap_or(buf.len())]);
            let consumed = end.map_or(buf.len(), |i| i + 1);
            reader.consume(consumed);
            if end.is_some() && !line.is_empty() {
                let text = String::from_utf8_lossy(&std::mem::take(&mut line)).into_owned();
                if tx.send(wrap(text)).is_err() {
                    return;
                }
            }
        }
        if !line.is_empty() {
            let _ = tx.send(wrap(String::from_utf8_lossy(&line).into_owned()));
        }
    });
}

/// Run `cmd`, forward every non-blank stdout and stderr line to `progress`
/// as it arrives, and fail with stderr when it exits non-zero. A cancelled
/// `progress`, or dropping the future, kills the child.
pub async fn run_cmd_streaming(
    cmd: &mut Command,
    label: &str,
    progress: &mut dyn FlashProgress,
) -> Result<()> {
    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::piped());
    cmd.kill_on_drop(true);

    let mut child = cmd
        .spawn()
        .map_err(|e| FlashError::Message(format!("failed to spawn {label}: {e}")))?;

    let (tx, mut rx) = mpsc::unbounded_channel();
    relay(child.stdout.take(), tx.clone(), Line::Out);
    relay(child.stderr.take(), tx, Line::Err);

    let mut stderr_lines = Vec::new();
    loop {
        if progress.cancelled() {
            let _ = child.kill().await;
            return Err(FlashError::Cancelled);
        }
        let line = match timeout(CANCEL_POLL, rx.recv()).await {
            Ok(Some(line)) => line,
            Ok(None) => break,
            Err(_) => continue,
        };
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

    fn pid_from(log: &LogProgress) -> u32 {
        log.0[0].parse().expect("the child prints its pid first")
    }

    async fn wait_until_gone(pid: u32) {
        for _ in 0..50 {
            let out = std::process::Command::new("ps")
                .args(["-o", "stat=", "-p", &pid.to_string()])
                .output()
                .unwrap();
            let stat = String::from_utf8_lossy(&out.stdout);
            if stat.trim().is_empty() || stat.trim_start().starts_with('Z') {
                return;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        panic!("pid {pid} still running");
    }

    #[derive(Default)]
    struct CancelOnFirstLine(LogProgress);

    impl FlashProgress for CancelOnFirstLine {
        fn on_progress(&mut self, message: &str) {
            self.0.on_progress(message);
        }

        fn cancelled(&self) -> bool {
            !self.0.0.is_empty()
        }
    }

    #[tokio::test]
    async fn a_cancelled_sink_kills_the_child() {
        let mut cmd = Command::new("sh");
        cmd.args(["-c", "echo $$; exec sleep 30"]);
        let mut sink = CancelOnFirstLine::default();
        let started = std::time::Instant::now();
        let result = run_cmd_streaming(&mut cmd, "sh", &mut sink).await;
        assert_eq!(result, Err(FlashError::Cancelled));
        assert!(started.elapsed() < Duration::from_secs(5));
        wait_until_gone(pid_from(&sink.0)).await;
    }

    #[tokio::test]
    async fn dropping_the_future_kills_the_child() {
        let mut cmd = Command::new("sh");
        cmd.args(["-c", "echo $$; exec sleep 30"]);
        let mut log = LogProgress::default();
        let run = run_cmd_streaming(&mut cmd, "sh", &mut log);
        assert!(
            tokio::time::timeout(Duration::from_millis(500), run)
                .await
                .is_err()
        );
        wait_until_gone(pid_from(&log)).await;
    }

    #[tokio::test]
    async fn a_line_that_is_not_utf8_does_not_end_the_relay() {
        let mut cmd = Command::new("sh");
        cmd.args([
            "-c",
            r"printf 'one\n\377\n'; sleep 0.2; echo three; echo four 1>&2",
        ]);
        let mut log = LogProgress::default();
        run_cmd_streaming(&mut cmd, "sh", &mut log).await.unwrap();
        assert!(log.0.contains(&"three".to_string()), "{:?}", log.0);
        assert!(log.0.contains(&"four".to_string()), "{:?}", log.0);
    }

    #[tokio::test]
    async fn a_carriage_return_ends_a_line() {
        let mut cmd = Command::new("sh");
        cmd.args(["-c", r"printf '10 %%\r20 %%\r\n'"]);
        let mut log = LogProgress::default();
        run_cmd_streaming(&mut cmd, "sh", &mut log).await.unwrap();
        assert_eq!(log.0, ["10 %", "20 %"]);
    }
}
