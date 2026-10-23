use crate::error::{FlashError, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum FlashStage {
    Connecting,
    Erasing,
    Writing,
    Verifying,
    Resetting,
    Booting,
}

/// Sink for flash progress; every method but `on_progress` has a no-op default.
pub trait FlashProgress: Send {
    fn on_progress(&mut self, message: &str);

    fn on_stage(&mut self, _stage: FlashStage, message: &str) {
        self.on_progress(message);
    }

    fn on_target(&mut self, _chip: &str) {}

    fn on_bytes(&mut self, _done: u64, _total: u64) {}

    fn cancelled(&self) -> bool {
        false
    }
}

/// Collects every line it is given; for tests and simple CLIs.
#[derive(Debug, Default)]
pub struct LogProgress(pub Vec<String>);

impl FlashProgress for LogProgress {
    fn on_progress(&mut self, message: &str) {
        self.0.push(message.to_string());
    }
}

pub fn check_cancel(progress: &dyn FlashProgress) -> Result<()> {
    if progress.cancelled() {
        Err(FlashError::Cancelled)
    } else {
        Ok(())
    }
}
