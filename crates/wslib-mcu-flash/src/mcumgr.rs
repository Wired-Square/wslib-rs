//! An MCUboot image over SMP (mcumgr) on a caller's `wslib_mcumgr::Session`,
//! whichever transport it runs on. `async`, within the session's tokio runtime.

use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use futures_core::Stream;
use wslib_mcumgr::{Session, UploadOptions};

use crate::error::{FlashError, Result};
use crate::image;
use crate::progress::{FlashProgress, FlashStage, check_cancel};

const CANCEL_POLL: Duration = Duration::from_millis(100);

/// What follows the upload.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum Activation {
    /// Leave the image staged, with no reset.
    Leave,
    /// Boot the image once, on a reset; MCUboot reverts unless it is confirmed.
    #[default]
    Test,
    /// Boot the image from now on, from a reset.
    Confirm,
}

/// How [`flash`] uploads the image and what follows.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct McumgrOptions {
    pub upload: UploadOptions,
    pub activation: Activation,
}

/// Uploads the image at `image_path`, then activates it and resets as
/// `options.activation` says. A cancel once the reset is sent is too late.
pub async fn flash(
    session: &Session,
    image_path: &Path,
    options: &McumgrOptions,
    progress: &mut dyn FlashProgress,
) -> Result<()> {
    let firmware: Arc<[u8]> = image::load_flat(image_path)?.into();
    let total = firmware.len() as u64;

    progress.on_stage(
        FlashStage::Connecting,
        "Asking the device for its SMP buffers",
    );
    if let Err(e) = session.negotiate_params().await {
        progress.on_progress(&format!("Keeping the default chunk size: {e}"));
    }
    check_cancel(progress)?;

    progress.on_stage(
        FlashStage::Erasing,
        "Uploading; the device erases its slot first",
    );
    let mut upload = session.upload(firmware, options.upload.clone());
    let mut image_hash = None;
    let mut writing = false;
    while let Some(event) = next_unless_cancelled(&mut upload, progress).await? {
        let event = event.map_err(smp("upload"))?;
        if !std::mem::replace(&mut writing, true) {
            progress.on_stage(FlashStage::Writing, &format!("Writing {total} bytes"));
        }
        if let Some(offset) = event.resumed_from {
            progress.on_progress(&format!("Resuming the upload from offset {offset}"));
        }
        progress.on_bytes(event.bytes_sent as u64, total);
        image_hash = event.image_hash.or(image_hash);
    }
    let image_hash =
        image_hash.ok_or_else(|| FlashError::from("the upload ended without the image hash"))?;

    let confirm = match options.activation {
        Activation::Leave => return Ok(()),
        Activation::Test => false,
        Activation::Confirm => true,
    };
    check_cancel(progress)?;
    if confirm {
        progress.on_progress("Confirming the image");
        session.confirm(&image_hash).await.map_err(smp("confirm"))?;
    } else {
        progress.on_progress("Marking the image to boot once");
        session.test(&image_hash).await.map_err(smp("test"))?;
    }

    check_cancel(progress)?;
    progress.on_stage(FlashStage::Resetting, "Resetting into the new image");
    session.reset().await.map_err(smp("reset"))
}

/// `None` at the end of the stream; dropping the stream stops the upload.
async fn next_unless_cancelled<S: Stream + Unpin>(
    stream: &mut S,
    progress: &dyn FlashProgress,
) -> Result<Option<S::Item>> {
    loop {
        check_cancel(progress)?;
        let next = std::future::poll_fn(|cx| Pin::new(&mut *stream).poll_next(cx));
        if let Ok(item) = tokio::time::timeout(CANCEL_POLL, next).await {
            return Ok(item);
        }
    }
}

fn smp(step: &'static str) -> impl Fn(wslib_mcumgr::Error) -> FlashError {
    move |e| FlashError::Message(format!("SMP {step} failed: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, Ordering};

    use ciborium::Value;
    use serde::{Deserialize, Serialize, de::DeserializeOwned};
    use tokio::sync::mpsc;
    use wslib_mcumgr::{BoxFuture, Error, Group, HEADER_LEN, Header, Op, Transport};

    const CMD_STATE: u8 = 0;
    const CMD_UPLOAD: u8 = 1;
    const CMD_RESET: u8 = 5;
    const CMD_PARAMS: u8 = 6;
    const CHUNK: usize = 64;
    const HASH: [u8; 32] = [0xAB; 32];

    #[derive(Debug, PartialEq)]
    enum Seen {
        Params,
        Chunk,
        State { hash: Vec<u8>, confirm: bool },
        Reset,
    }

    #[derive(Deserialize)]
    struct ChunkRequest {
        off: usize,
        data: Value,
        len: Option<usize>,
    }

    #[derive(Serialize)]
    struct ChunkAck {
        off: usize,
        #[serde(rename = "match", skip_serializing_if = "Option::is_none")]
        matched: Option<bool>,
    }

    #[derive(Deserialize)]
    struct StateWrite {
        hash: Value,
        confirm: bool,
    }

    #[derive(Serialize)]
    struct Params {
        buf_size: usize,
        buf_count: usize,
    }

    #[derive(Serialize)]
    struct Images {
        images: [u8; 0],
    }

    #[derive(Serialize)]
    struct Empty {}

    /// An MCUboot device in process: it takes chunks in order and answers
    /// params, state writes and resets.
    struct FakeDevice {
        replies: mpsc::UnboundedSender<Vec<u8>>,
        inbox: tokio::sync::Mutex<mpsc::UnboundedReceiver<Vec<u8>>>,
        answers_chunks: bool,
        declared_len: Mutex<usize>,
        written: Mutex<Vec<u8>>,
        seen: Mutex<Vec<Seen>>,
    }

    impl FakeDevice {
        fn new(answers_chunks: bool) -> Arc<Self> {
            let (replies, inbox) = mpsc::unbounded_channel();
            Arc::new(Self {
                replies,
                inbox: tokio::sync::Mutex::new(inbox),
                answers_chunks,
                declared_len: Mutex::new(0),
                written: Mutex::new(Vec::new()),
                seen: Mutex::new(Vec::new()),
            })
        }

        fn seen(&self) -> std::sync::MutexGuard<'_, Vec<Seen>> {
            self.seen.lock().unwrap()
        }

        fn reply<T: Serialize>(&self, request: &Header, body: &T) {
            let op = match request.op {
                Op::Read => Op::ReadResponse,
                _ => Op::WriteResponse,
            };
            let mut payload = Vec::new();
            ciborium::into_writer(body, &mut payload).unwrap();
            let header = Header::new(
                op,
                request.group,
                request.command,
                request.seq,
                payload.len() as u16,
            );
            let mut frame = header.encode().to_vec();
            frame.extend_from_slice(&payload);
            let _ = self.replies.send(frame);
        }

        fn take_chunk(&self, chunk: ChunkRequest) -> ChunkAck {
            let mut declared = self.declared_len.lock().unwrap();
            if let Some(len) = chunk.len {
                *declared = len;
            }
            let mut written = self.written.lock().unwrap();
            if chunk.off == written.len() {
                written.extend_from_slice(chunk.data.as_bytes().unwrap());
            }
            ChunkAck {
                off: written.len(),
                matched: (written.len() == *declared).then_some(true),
            }
        }

        fn handle(&self, frame: &[u8]) {
            fn body<T: DeserializeOwned>(frame: &[u8]) -> T {
                ciborium::from_reader(&frame[HEADER_LEN..]).unwrap()
            }
            let header = Header::decode(frame).unwrap();
            match (header.group, header.command) {
                (Group::Os, CMD_PARAMS) => {
                    self.seen().push(Seen::Params);
                    let params = Params {
                        buf_size: 128 + CHUNK,
                        buf_count: 4,
                    };
                    self.reply(&header, &params);
                }
                (Group::Image, CMD_UPLOAD) => {
                    self.seen().push(Seen::Chunk);
                    if self.answers_chunks {
                        let ack = self.take_chunk(body(frame));
                        self.reply(&header, &ack);
                    }
                }
                (Group::Image, CMD_STATE) => {
                    let write: StateWrite = body(frame);
                    self.seen().push(Seen::State {
                        hash: write.hash.into_bytes().unwrap(),
                        confirm: write.confirm,
                    });
                    self.reply(&header, &Images { images: [] });
                }
                (Group::Os, CMD_RESET) => {
                    self.seen().push(Seen::Reset);
                    self.reply(&header, &Empty {});
                }
                other => panic!("unexpected request {other:?}"),
            }
        }
    }

    impl Transport for FakeDevice {
        fn send(&self, frame: Vec<u8>) -> BoxFuture<'_, std::result::Result<(), Error>> {
            self.handle(&frame);
            Box::pin(async { Ok(()) })
        }

        fn receive(&self) -> BoxFuture<'_, std::result::Result<Vec<u8>, Error>> {
            Box::pin(async {
                self.inbox
                    .lock()
                    .await
                    .recv()
                    .await
                    .ok_or(Error::LinkClosed)
            })
        }
    }

    struct Sink {
        stages: Vec<FlashStage>,
        bytes: Vec<u64>,
        cancel: Box<dyn Fn(&Sink) -> bool + Send>,
    }

    impl Sink {
        fn new(cancel: impl Fn(&Sink) -> bool + Send + 'static) -> Self {
            Self {
                stages: Vec::new(),
                bytes: Vec::new(),
                cancel: Box::new(cancel),
            }
        }
    }

    impl FlashProgress for Sink {
        fn on_progress(&mut self, _message: &str) {}

        fn on_stage(&mut self, stage: FlashStage, _message: &str) {
            self.stages.push(stage);
        }

        fn on_bytes(&mut self, done: u64, _total: u64) {
            self.bytes.push(done);
        }

        fn cancelled(&self) -> bool {
            (self.cancel)(self)
        }
    }

    /// MCUboot's layout as `image.h` has it: a 16-byte header, the body, then
    /// the TLV info and one SHA-256 TLV.
    fn mcuboot_image(body_len: usize) -> Vec<u8> {
        let mut bin = 0x96f3_b83d_u32.to_le_bytes().to_vec();
        bin.extend_from_slice(&[0; 4]);
        bin.extend_from_slice(&16_u16.to_le_bytes());
        bin.extend_from_slice(&[0; 2]);
        bin.extend_from_slice(&(body_len as u32).to_le_bytes());
        bin.extend((0..body_len).map(|i| i as u8));
        bin.extend_from_slice(&0x6907_u16.to_le_bytes());
        bin.extend_from_slice(&40_u16.to_le_bytes());
        bin.extend_from_slice(&[0x10, 0x00, 32, 0x00]);
        bin.extend_from_slice(&HASH);
        bin
    }

    async fn run(
        device: &Arc<FakeDevice>,
        image: &[u8],
        activation: Activation,
        sink: &mut Sink,
    ) -> Result<()> {
        let path = std::env::temp_dir().join(format!(
            "wslib-mcu-flash-mcumgr-{}-{}.bin",
            std::process::id(),
            std::thread::current()
                .name()
                .unwrap_or("test")
                .replace("::", "-")
        ));
        std::fs::write(&path, image).unwrap();
        let session = Session::new(device.clone(), CHUNK);
        let options = McumgrOptions {
            activation,
            ..McumgrOptions::default()
        };
        let result = flash(&session, &path, &options, sink).await;
        std::fs::remove_file(&path).unwrap();
        result
    }

    fn never(_: &Sink) -> bool {
        false
    }

    #[tokio::test]
    async fn a_test_flash_uploads_marks_the_image_to_boot_once_and_resets() {
        let device = FakeDevice::new(true);
        let image = mcuboot_image(10 * CHUNK);
        let mut sink = Sink::new(never);

        run(&device, &image, Activation::Test, &mut sink)
            .await
            .unwrap();

        assert_eq!(*device.written.lock().unwrap(), image);
        let seen = device.seen();
        assert_eq!(seen.first(), Some(&Seen::Params));
        let tail = [
            Seen::State {
                hash: HASH.to_vec(),
                confirm: false,
            },
            Seen::Reset,
        ];
        assert!(seen.ends_with(&tail), "{seen:?}");
        use FlashStage::*;
        assert_eq!(sink.stages, [Connecting, Erasing, Writing, Resetting]);
        assert_eq!(sink.bytes.last(), Some(&(image.len() as u64)));
    }

    #[tokio::test]
    async fn a_confirm_flash_confirms_the_image_before_the_reset() {
        let device = FakeDevice::new(true);
        let mut sink = Sink::new(never);

        run(
            &device,
            &mcuboot_image(CHUNK),
            Activation::Confirm,
            &mut sink,
        )
        .await
        .unwrap();

        let tail = [
            Seen::State {
                hash: HASH.to_vec(),
                confirm: true,
            },
            Seen::Reset,
        ];
        assert!(device.seen().ends_with(&tail), "{:?}", device.seen());
    }

    #[tokio::test]
    async fn leaving_the_image_staged_neither_marks_it_nor_resets() {
        let device = FakeDevice::new(true);
        let mut sink = Sink::new(never);

        run(&device, &mcuboot_image(CHUNK), Activation::Leave, &mut sink)
            .await
            .unwrap();

        assert_eq!(device.seen().last(), Some(&Seen::Chunk));
        assert!(!sink.stages.contains(&FlashStage::Resetting));
    }

    #[tokio::test]
    async fn a_cancel_mid_upload_stops_it_and_activates_nothing() {
        let device = FakeDevice::new(true);
        let image = mcuboot_image(200 * CHUNK);
        let mut sink = Sink::new(|sink| !sink.bytes.is_empty());

        let result = run(&device, &image, Activation::Test, &mut sink).await;

        assert_eq!(result, Err(FlashError::Cancelled));
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(device.written.lock().unwrap().len() < image.len());
        assert!(
            !device
                .seen()
                .iter()
                .any(|s| matches!(s, Seen::State { .. } | Seen::Reset))
        );
    }

    #[tokio::test]
    async fn a_cancel_is_seen_while_the_device_is_silent() {
        let device = FakeDevice::new(false);
        let stop = Arc::new(AtomicBool::new(false));
        let stopper = stop.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(300)).await;
            stopper.store(true, Ordering::Release);
        });
        let mut sink = Sink::new(move |_| stop.load(Ordering::Acquire));
        let started = std::time::Instant::now();

        let result = run(&device, &mcuboot_image(CHUNK), Activation::Test, &mut sink).await;

        assert_eq!(result, Err(FlashError::Cancelled));
        assert!(started.elapsed() < Duration::from_secs(2));
        assert!(device.seen().contains(&Seen::Chunk));
    }

    #[tokio::test]
    async fn an_image_that_is_not_mcuboot_is_refused_by_name() {
        let device = FakeDevice::new(true);
        let mut sink = Sink::new(never);

        let err = run(&device, &[0; 256], Activation::Test, &mut sink)
            .await
            .unwrap_err()
            .to_string();

        assert!(err.contains("not an MCUboot image"), "{err}");
    }
}
