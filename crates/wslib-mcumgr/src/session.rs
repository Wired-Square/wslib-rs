use std::collections::HashMap;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use futures_core::Stream;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::{Semaphore, mpsc};
use tracing::{debug, warn};

use crate::frame::{self, BytesRef, Empty, decode_reply};
use crate::header::{Header, Op};
use crate::image::{
    CMD_STATE, CMD_UPLOAD, ImageSlot, StateResponse, StateWrite, UploadAck, UploadChunk,
    UploadOptions, UploadProgress, mcuboot_image_hash,
};
use crate::router::{Replies, Router};
use crate::{Error, Group, Transport};

const CMD_ECHO: u8 = 0;
const CMD_RESET: u8 = 5;
const CMD_PARAMS: u8 = 6;

/// Room for the header and the CBOR around a first chunk's data.
pub(crate) const FRAME_OVERHEAD: usize = 128;
pub(crate) const MIN_CHUNK_SIZE: usize = 64;

const ROUND_TRIP_TIMEOUT: Duration = Duration::from_secs(10);

/// The device erases the whole slot before it answers the first chunk.
pub(crate) const FIRST_CHUNK_TIMEOUT: Duration = Duration::from_secs(40);
pub(crate) const CHUNK_TIMEOUT: Duration = Duration::from_secs(15);

const MAX_RESUMES_WITHOUT_PROGRESS: usize = 3;

pub(crate) const PROGRESS_CHANNEL_DEPTH: usize = 32;

/// Half the sequence numbers, so a pass's unanswered chunks and the next
/// pass's fit beside each other.
const MAX_WINDOW: usize = 128;

/// One device buffer stays free for the reply.
fn upload_window(transport_cap: usize, device_buf_count: usize) -> usize {
    transport_cap
        .min(device_buf_count.saturating_sub(1))
        .clamp(1, MAX_WINDOW)
}

/// What a device's `os/mcumgr-params` reports of its SMP buffers.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[non_exhaustive]
pub struct McumgrParams {
    /// The largest SMP message it takes, header included.
    pub buf_size: usize,
    pub buf_count: usize,
}

/// An SMP client on one transport. Requests may come from several tasks; one
/// task reads every reply and hands it to its request by sequence number.
pub struct Session {
    router: Arc<Router>,
    chunk_size: AtomicUsize,
    buf_count: AtomicUsize,
}

impl Session {
    /// `chunk_size` is the image data per upload request until
    /// [`negotiate_params`](Self::negotiate_params) learns the device's.
    ///
    /// Must be called within a tokio runtime: it spawns the task that reads
    /// the transport, which a receive error ends, closing the session.
    pub fn new(transport: Arc<dyn Transport>, chunk_size: usize) -> Self {
        Self {
            router: Router::start(transport),
            chunk_size: AtomicUsize::new(chunk_size),
            buf_count: AtomicUsize::new(1),
        }
    }

    pub async fn is_connected(&self) -> bool {
        self.router.is_open() && self.router.transport().is_connected().await
    }

    /// Sizes uploads to the device's buffers, within what the transport
    /// carries whole. A device without the command returns an error, and the
    /// session keeps the size it has.
    pub async fn negotiate_params(&self) -> Result<McumgrParams, Error> {
        let params: McumgrParams = self
            .request(Op::Read, Group::Os, CMD_PARAMS, &Empty {}, "mcumgr params")
            .await?;
        let chunk = params
            .buf_size
            .saturating_sub(FRAME_OVERHEAD)
            .min(self.router.transport().max_chunk_size())
            .max(MIN_CHUNK_SIZE);
        self.chunk_size.store(chunk, Ordering::Release);
        self.buf_count
            .store(params.buf_count.max(1), Ordering::Release);
        debug!(?params, chunk, "negotiated mcumgr params");
        Ok(params)
    }

    pub async fn echo(&self, text: &str) -> Result<String, Error> {
        #[derive(Serialize)]
        struct Request<'a> {
            d: &'a str,
        }
        #[derive(Deserialize)]
        struct Reply {
            r: String,
        }
        let reply: Reply = self
            .request(Op::Write, Group::Os, CMD_ECHO, &Request { d: text }, "echo")
            .await?;
        Ok(reply.r)
    }

    pub async fn list_images(&self) -> Result<Vec<ImageSlot>, Error> {
        let state: StateResponse = self
            .request(Op::Read, Group::Image, CMD_STATE, &Empty {}, "image state")
            .await?;
        Ok(state.images.into_iter().map(ImageSlot::from).collect())
    }

    /// Uploads `firmware` as `options.image`, one event per acknowledged
    /// chunk; the last carries the image hash.
    ///
    /// Dropping the stream cancels the upload: no chunk is sent after it.
    /// A device that stops answering mid-upload is resumed from the offset
    /// it reports, a few times before [`Error::UploadStalled`].
    ///
    /// Must be called within a tokio runtime: the upload runs as a task.
    pub fn upload(
        &self,
        firmware: Arc<[u8]>,
        options: UploadOptions,
    ) -> impl Stream<Item = Result<UploadProgress, Error>> + Send + Unpin + 'static {
        let (events, rx) = mpsc::channel(PROGRESS_CHANNEL_DEPTH);
        let upload = Upload {
            router: Arc::clone(&self.router),
            chunk_size: self.chunk_size.load(Ordering::Acquire),
            window: upload_window(
                self.router.transport().max_in_flight(),
                self.buf_count.load(Ordering::Acquire),
            ),
            firmware,
            options,
            events,
        };
        tokio::spawn(async move {
            if let Err(e) = upload.run().await {
                let _ = upload.events.send(Err(e)).await;
            }
        });
        Events(rx)
    }

    /// Marks the image whose hash is `hash` to boot once, on the next reset.
    pub async fn test(&self, hash: &[u8]) -> Result<(), Error> {
        self.write_state(hash, false, "state write (test)").await
    }

    /// Marks the image whose hash is `hash` to boot from now on.
    pub async fn confirm(&self, hash: &[u8]) -> Result<(), Error> {
        self.write_state(hash, true, "state write (confirm)").await
    }

    /// Makes the running image permanent, as after a test boot.
    pub async fn confirm_running(&self) -> Result<(), Error> {
        self.write_state(&[], true, "state write (confirm running)")
            .await
    }

    async fn write_state(&self, hash: &[u8], confirm: bool, context: &str) -> Result<(), Error> {
        let request = StateWrite {
            hash: BytesRef(hash),
            confirm,
        };
        self.request::<_, StateResponse>(Op::Write, Group::Image, CMD_STATE, &request, context)
            .await
            .map(drop)
    }

    /// Reboots the device. A reply refusing it is an error, but a link that
    /// fails or stays silent once the request is sent is not, since the
    /// device may restart before it answers.
    pub async fn reset(&self) -> Result<(), Error> {
        let mut replies = self.send(Group::Os, CMD_RESET, reset_frame).await?;
        match tokio::time::timeout(ROUND_TRIP_TIMEOUT, replies.next()).await {
            Ok(Ok(reply)) => decode_reply::<Empty>(&reply, "reset").map(drop),
            _ => {
                warn!("no reply to reset; the device has likely rebooted");
                Ok(())
            }
        }
    }

    pub(crate) fn router(&self) -> Arc<Router> {
        Arc::clone(&self.router)
    }

    pub(crate) fn chunk_budget(&self) -> usize {
        self.chunk_size.load(Ordering::Acquire)
    }

    pub(crate) async fn request<Q: Serialize, R: DeserializeOwned>(
        &self,
        op: Op,
        group: Group,
        command: u8,
        payload: &Q,
        context: &str,
    ) -> Result<R, Error> {
        let mut replies = self
            .send(group, command, |seq| {
                frame::encode(op, group, command, seq, payload)
            })
            .await?;
        let reply = tokio::time::timeout(ROUND_TRIP_TIMEOUT, replies.next())
            .await
            .map_err(|_| Error::Timeout)??;
        decode_reply(&reply, context)
    }

    /// Sends the frame `encode` builds for a free sequence number, whose
    /// reply then comes to the returned [`Replies`].
    async fn send(
        &self,
        group: Group,
        command: u8,
        encode: impl FnOnce(u8) -> Result<Vec<u8>, Error>,
    ) -> Result<Replies, Error> {
        let replies = self.router.replies();
        let frame = encode(replies.expect(group, command)?)?;
        self.router.send(frame).await?;
        Ok(replies)
    }
}

/// A stream of what a spawned task sends; dropping it closes the channel,
/// which the task watches.
pub(crate) struct Events<T>(pub(crate) mpsc::Receiver<T>);

impl<T> Stream for Events<T> {
    type Item = T;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<T>> {
        self.0.poll_recv(cx)
    }
}

struct Upload {
    router: Arc<Router>,
    chunk_size: usize,
    window: usize,
    firmware: Arc<[u8]>,
    options: UploadOptions,
    events: mpsc::Sender<Result<UploadProgress, Error>>,
}

struct ChunkInFlight {
    start: usize,
    end: usize,
}

#[derive(Default)]
struct Stalls {
    count: usize,
    last_at: usize,
}

impl Stalls {
    fn record(&mut self, at: usize, total: usize) -> Result<(), Error> {
        self.count = if at > self.last_at { 1 } else { self.count + 1 };
        self.last_at = at;
        if self.count > MAX_RESUMES_WITHOUT_PROGRESS {
            return Err(Error::UploadStalled { offset: at, total });
        }
        warn!(offset = at, "upload lost ground; resuming");
        Ok(())
    }
}

/// Ends a pipelined pass for the sender when the receiver stops.
struct EndPass<'a> {
    credits: &'a Semaphore,
    stop: &'a AtomicBool,
}

impl Drop for EndPass<'_> {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        self.credits.close();
    }
}

impl Upload {
    async fn emit(&self, progress: UploadProgress) -> bool {
        self.events.send(Ok(progress)).await.is_ok()
    }

    fn progress(&self, bytes_sent: usize) -> UploadProgress {
        UploadProgress {
            bytes_sent,
            total_bytes: self.firmware.len(),
            image_hash: None,
            resumed_from: None,
        }
    }

    fn chunk_frame(&self, seq: u8, off: usize, sha: Option<&[u8]>) -> Result<Vec<u8>, Error> {
        let end = (off + self.chunk_size).min(self.firmware.len());
        let first = off == 0;
        let chunk = UploadChunk {
            data: BytesRef(&self.firmware[off..end]),
            off,
            image: first.then_some(self.options.image),
            len: first.then_some(self.firmware.len()),
            sha: sha.filter(|_| first).map(BytesRef),
        };
        frame::encode(Op::Write, Group::Image, CMD_UPLOAD, seq, &chunk)
    }

    /// Each pass sends one chunk alone to learn where the device is, since
    /// a device keyed on the first chunk's `sha` resumes an upload it holds
    /// part of, then pipelines the rest.
    async fn run(&self) -> Result<(), Error> {
        let total = self.firmware.len();
        let sha = Sha256::digest(&self.firmware).to_vec();
        let image_hash = mcuboot_image_hash(&self.firmware)?;
        let complete = |resumed_from| UploadProgress {
            image_hash: Some(image_hash.clone()),
            resumed_from,
            ..self.progress(total)
        };
        let mut replies = self.router.replies();
        let mut probe_at = 0;
        let mut stalls = Stalls::default();
        let mut resumed_from = None;
        loop {
            if self.events.is_closed() {
                return Ok(());
            }
            if probe_at >= total {
                warn!("the device holds the whole image already; it gave no hash verdict");
                self.emit(complete(resumed_from)).await;
                return Ok(());
            }
            let seq = replies.expect(Group::Image, CMD_UPLOAD)?;
            self.router
                .send(self.chunk_frame(seq, probe_at, Some(&sha))?)
                .await?;
            let timeout = if probe_at == 0 {
                self.options.first_chunk_timeout
            } else {
                self.options.chunk_timeout
            };
            let Some(ack) = self.probe_ack(&mut replies, seq, probe_at, timeout).await? else {
                if self.events.is_closed() {
                    return Ok(());
                }
                stalls.record(probe_at, total)?;
                resumed_from = Some(probe_at);
                continue;
            };
            if ack.off == 0 && probe_at != 0 {
                stalls.record(probe_at, total)?;
                resumed_from = Some(probe_at);
                probe_at = 0;
                continue;
            }
            if ack.off > total {
                return Err(beyond_image(ack.off, total));
            }
            if ack.off == total {
                match ack.matched {
                    Some(false) => return Err(Error::HashMismatch),
                    None => warn!("a repeated chunk completed the upload; no hash verdict"),
                    Some(true) => {}
                }
                self.emit(complete(resumed_from)).await;
                return Ok(());
            }
            let event = UploadProgress {
                resumed_from: resumed_from.take(),
                ..self.progress(ack.off)
            };
            if !self.emit(event).await {
                return Ok(());
            }
            let Some(resume_from) = self.pipeline(&mut replies, ack.off, &image_hash).await? else {
                return Ok(());
            };
            stalls.record(resume_from, total)?;
            resumed_from = Some(resume_from);
            probe_at = resume_from;
        }
    }

    /// `None` when the chunk timer runs out or the stream is dropped first.
    /// The replies still due from earlier passes are stale once it answers.
    async fn probe_ack(
        &self,
        replies: &mut Replies,
        seq: u8,
        off: usize,
        timeout: Duration,
    ) -> Result<Option<UploadAck>, Error> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let received = tokio::select! {
                received = tokio::time::timeout_at(deadline, replies.next()) => received,
                () = self.events.closed() => return Ok(None),
            };
            let Ok(frame) = received else {
                return Ok(None);
            };
            let frame = frame?;
            if Header::decode(&frame)?.seq == seq {
                replies.forget();
                return ack_or_lost(&frame, off);
            }
            reject_stale_mismatch(&frame)?;
        }
    }

    /// Sends from `start` to the end, at most `window` chunks unanswered.
    /// `Some(offset)` when the device lost ground, to resume from there.
    async fn pipeline(
        &self,
        replies: &mut Replies,
        start: usize,
        image_hash: &[u8],
    ) -> Result<Option<usize>, Error> {
        let Replies { sequences, inbox } = replies;
        let total = self.firmware.len();
        let in_flight = std::sync::Mutex::new(HashMap::<u8, ChunkInFlight>::new());
        let in_flight = || in_flight.lock().expect("in-flight chunks lock");
        let credits = Semaphore::new(self.window);
        let stop = AtomicBool::new(false);

        let sender = async {
            let mut off = start;
            while off < total {
                let Ok(permit) = credits.acquire().await else {
                    return Ok(());
                };
                permit.forget();
                if stop.load(Ordering::Acquire) || self.events.is_closed() {
                    return Ok(());
                }
                let seq = sequences.expect(Group::Image, CMD_UPLOAD)?;
                let end = (off + self.chunk_size).min(total);
                let frame = self.chunk_frame(seq, off, None)?;
                in_flight().insert(seq, ChunkInFlight { start: off, end });
                self.router.send(frame).await?;
                off = end;
            }
            Ok::<_, Error>(())
        };

        let receiver = async {
            let _end = EndPass {
                credits: &credits,
                stop: &stop,
            };
            loop {
                let received = tokio::select! {
                    received = tokio::time::timeout(self.options.chunk_timeout, inbox.next()) => received,
                    _ = self.events.closed() => return Ok(None),
                };
                let Ok(frame) = received else {
                    let lowest = in_flight().values().map(|c| c.start).min();
                    return Ok(Some(lowest.unwrap_or(start)));
                };
                let frame = frame?;
                let seq = Header::decode(&frame)?.seq;
                let Some(chunk) = in_flight().remove(&seq) else {
                    reject_stale_mismatch(&frame)?;
                    continue;
                };
                let Some(ack) = ack_or_lost(&frame, chunk.start)? else {
                    return Ok(Some(chunk.start));
                };
                if ack.matched == Some(false) {
                    return Err(Error::HashMismatch);
                }
                if ack.off > total {
                    return Err(beyond_image(ack.off, total));
                }
                if ack.off != chunk.end {
                    return Ok(Some(ack.off));
                }
                credits.add_permits(1);
                let last = chunk.end == total;
                let event = UploadProgress {
                    image_hash: last.then(|| image_hash.to_vec()),
                    ..self.progress(ack.off)
                };
                if !self.emit(event).await || last {
                    return Ok(None);
                }
            }
        };

        let ((), outcome) = tokio::try_join!(sender, receiver)?;
        Ok(outcome)
    }
}

fn reset_frame(seq: u8) -> Result<Vec<u8>, Error> {
    #[derive(Serialize)]
    struct Reset {
        force: u8,
    }
    frame::encode(Op::Write, Group::Os, CMD_RESET, seq, &Reset { force: 0 })
}

/// An ack that does not decode is as good as lost: the next probe learns
/// where the device is.
fn ack_or_lost(frame: &[u8], off: usize) -> Result<Option<UploadAck>, Error> {
    match decode_reply(frame, &format!("upload chunk at {off}")) {
        Ok(ack) => Ok(Some(ack)),
        Err(Error::Decode(e)) => {
            warn!("an undecodable upload ack: {e}");
            Ok(None)
        }
        Err(e) => Err(e),
    }
}

/// A late final ack from an earlier pass still carries the device's verdict.
fn reject_stale_mismatch(frame: &[u8]) -> Result<(), Error> {
    match frame::decode::<UploadAck>(frame) {
        Ok((_, ack)) if ack.matched == Some(false) => Err(Error::HashMismatch),
        _ => Ok(()),
    }
}

fn beyond_image(off: usize, total: usize) -> Error {
    Error::UnexpectedReply(format!(
        "the device reports offset {off}, past the {total}-byte image"
    ))
}

#[cfg(test)]
pub(crate) async fn next<S: Stream + Unpin>(stream: &mut S) -> Option<S::Item> {
    std::future::poll_fn(|cx| Pin::new(&mut *stream).poll_next(cx)).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::BoxFuture;
    use crate::frame::Bytes;
    use crate::header::HEADER_LEN;
    use crate::image::make_image;
    use std::collections::VecDeque;
    use tokio::sync::Notify;

    const TEST_CHUNK: usize = 64;
    const TEST_CHUNK_TIMEOUT: Duration = Duration::from_millis(200);
    const DEVICE_BUFFERS: usize = 4;
    const SETTLE: Duration = Duration::from_millis(150);
    const HELD_ACK_TIMEOUT: Duration = Duration::from_secs(5);
    const STALE_SEQ: u8 = 0xEE;
    const RC_REFUSED: i32 = 1;
    const CBOR_BREAK: u8 = 0xff;

    // The spec's upload request: {data, off} plus {image, len, sha} on the first,
    // hand-encoded per RFC 8949; framelink-rs's previous codec sent the same bytes.
    #[tokio::test]
    async fn a_first_chunk_carries_image_len_and_sha_and_a_later_one_does_not() {
        let (events, _rx) = mpsc::channel(1);
        let upload = Upload {
            router: Router::start(Arc::new(ImageDevice::default())),
            chunk_size: 3,
            window: 1,
            firmware: Arc::from(&[1u8, 2, 3, 4][..]),
            options: UploadOptions::default(),
            events,
        };
        let first = upload.chunk_frame(7, 0, Some(&[0x11; 4])).unwrap();
        let mut want = vec![0x02, 0x00, 0x00, 0x24, 0x00, 0x01, 0x07, 0x01, 0xa5];
        want.extend_from_slice(&[0x64, b'd', b'a', b't', b'a', 0x43, 1, 2, 3]);
        want.extend_from_slice(&[0x63, b'o', b'f', b'f', 0x00]);
        want.extend_from_slice(&[0x65, b'i', b'm', b'a', b'g', b'e', 0x00]);
        want.extend_from_slice(&[0x63, b'l', b'e', b'n', 0x04]);
        want.extend_from_slice(&[0x63, b's', b'h', b'a', 0x44, 0x11, 0x11, 0x11, 0x11]);
        assert_eq!(first, want);

        let later = upload.chunk_frame(8, 3, Some(&[0x11; 4])).unwrap();
        let mut want = vec![0x02, 0x00, 0x00, 0x0d, 0x00, 0x01, 0x08, 0x01, 0xa2];
        want.extend_from_slice(&[0x64, b'd', b'a', b't', b'a', 0x41, 4]);
        want.extend_from_slice(&[0x63, b'o', b'f', b'f', 0x03]);
        assert_eq!(later, want);
    }

    // Matches the bytes framelink-rs's codec sends today (observed).
    #[test]
    fn a_state_write_confirming_the_running_image_sends_an_empty_hash() {
        let write = StateWrite {
            hash: BytesRef(&[]),
            confirm: true,
        };
        let frame = frame::encode(Op::Write, Group::Image, CMD_STATE, 7, &write).unwrap();
        let mut want = vec![0x02, 0x00, 0x00, 0x10, 0x00, 0x01, 0x07, 0x00, 0xa2];
        want.extend_from_slice(&[0x64, b'h', b'a', b's', b'h', 0x40]);
        want.extend_from_slice(&[0x67, b'c', b'o', b'n', b'f', b'i', b'r', b'm', 0xf5]);
        assert_eq!(frame, want);
    }

    // Matches the bytes framelink-rs's codec sends today (observed).
    #[test]
    fn a_state_write_for_test_carries_the_hash() {
        let write = StateWrite {
            hash: BytesRef(&[0xab; 4]),
            confirm: false,
        };
        let frame = frame::encode(Op::Write, Group::Image, CMD_STATE, 7, &write).unwrap();
        let mut want = vec![0x02, 0x00, 0x00, 0x14, 0x00, 0x01, 0x07, 0x00, 0xa2];
        want.extend_from_slice(&[0x64, b'h', b'a', b's', b'h', 0x44, 0xab, 0xab, 0xab, 0xab]);
        want.extend_from_slice(&[0x67, b'c', b'o', b'n', b'f', b'i', b'r', b'm', 0xf4]);
        assert_eq!(frame, want);
    }

    // Matches the bytes framelink-rs's codec sends today (observed).
    #[test]
    fn a_reset_sends_force_zero() {
        let mut want = vec![0x02, 0x00, 0x00, 0x08, 0x00, 0x00, 0x07, 0x05, 0xa1];
        want.extend_from_slice(&[0x65, b'f', b'o', b'r', b'c', b'e', 0x00]);
        assert_eq!(reset_frame(7).unwrap(), want);
    }

    #[test]
    fn upload_window_leaves_one_device_buffer_for_the_response() {
        assert_eq!(upload_window(usize::MAX, 4), 3);
        assert_eq!(upload_window(1, 4), 1);
        assert_eq!(upload_window(usize::MAX, 1), 1);
        assert_eq!(upload_window(usize::MAX, 0), 1);
        assert_eq!(upload_window(usize::MAX, 400), MAX_WINDOW);
    }

    #[derive(Deserialize)]
    struct ChunkRequest {
        off: usize,
        data: Bytes,
        len: Option<usize>,
    }

    #[derive(Serialize)]
    struct ChunkAck {
        off: usize,
        #[serde(rename = "match", skip_serializing_if = "Option::is_none")]
        matched: Option<bool>,
    }

    #[derive(Default)]
    struct ImageDevice {
        declared_len: std::sync::Mutex<Option<usize>>,
        verdict: Option<bool>,
        written: std::sync::Mutex<Vec<u8>>,
        offsets_seen: std::sync::Mutex<Vec<usize>>,
        drops: std::sync::Mutex<VecDeque<usize>>,
        drop_always_at: Option<usize>,
        hold_continuation_acks: std::sync::Mutex<bool>,
        forget_once_at: std::sync::Mutex<Option<usize>>,
        garble_once_at: std::sync::Mutex<VecDeque<usize>>,
        held: std::sync::Mutex<Vec<Vec<u8>>>,
        responses: std::sync::Mutex<VecDeque<Vec<u8>>>,
        wake: Notify,
    }

    impl ImageDevice {
        fn dropping_once_at(offsets: &[usize]) -> Arc<Self> {
            Arc::new(Self {
                drops: std::sync::Mutex::new(offsets.iter().copied().collect()),
                ..Self::default()
            })
        }

        fn dropping_always_at(offset: usize) -> Arc<Self> {
            Arc::new(Self {
                drop_always_at: Some(offset),
                ..Self::default()
            })
        }

        fn reporting_a_hash_mismatch() -> Arc<Self> {
            Arc::new(Self {
                verdict: Some(false),
                ..Self::default()
            })
        }

        fn forgetting_the_upload_when_probed_at(offset: usize) -> Arc<Self> {
            Arc::new(Self {
                drops: std::sync::Mutex::new(VecDeque::from([offset])),
                forget_once_at: std::sync::Mutex::new(Some(offset)),
                ..Self::default()
            })
        }

        fn garbling_the_ack_once_at(offsets: &[usize]) -> Arc<Self> {
            Arc::new(Self {
                garble_once_at: std::sync::Mutex::new(offsets.iter().copied().collect()),
                ..Self::default()
            })
        }

        fn holding_continuation_acks() -> Arc<Self> {
            Arc::new(Self {
                hold_continuation_acks: std::sync::Mutex::new(true),
                ..Self::default()
            })
        }

        fn release_held_acks(&self) {
            *self.hold_continuation_acks.lock().unwrap() = false;
            let held = std::mem::take(&mut *self.held.lock().unwrap());
            self.responses.lock().unwrap().extend(held);
            self.wake.notify_one();
        }

        fn times_seen(&self, offset: usize) -> usize {
            self.offsets_seen
                .lock()
                .unwrap()
                .iter()
                .filter(|&&o| o == offset)
                .count()
        }

        fn should_drop(&self, offset: usize) -> bool {
            if self.drop_always_at == Some(offset) {
                return true;
            }
            let mut drops = self.drops.lock().unwrap();
            match drops.iter().position(|&o| o == offset) {
                Some(i) => {
                    drops.remove(i);
                    true
                }
                None => false,
            }
        }

        fn handle(&self, frame: &[u8]) {
            let (header, chunk): (_, ChunkRequest) =
                frame::decode(frame).expect("fake device: undecodable chunk");
            self.offsets_seen.lock().unwrap().push(chunk.off);
            let in_order = chunk.off == self.written.lock().unwrap().len();
            if in_order && self.should_drop(chunk.off) {
                return;
            }
            let device_off = {
                let mut written = self.written.lock().unwrap();
                let mut forget_once_at = self.forget_once_at.lock().unwrap();
                if in_order && *forget_once_at == Some(chunk.off) {
                    forget_once_at.take();
                    written.clear();
                    *self.declared_len.lock().unwrap() = None;
                }
                if chunk.off == 0 && chunk.len.is_some() {
                    written.clear();
                    *self.declared_len.lock().unwrap() = chunk.len;
                }
                if chunk.off == written.len() {
                    written.extend_from_slice(&chunk.data.0);
                }
                written.len()
            };
            let ack = ChunkAck {
                off: device_off,
                matched: (Some(device_off) == *self.declared_len.lock().unwrap())
                    .then_some(self.verdict)
                    .flatten(),
            };
            let mut ack = frame::encode(
                Op::WriteResponse,
                Group::Image,
                CMD_UPLOAD,
                header.seq,
                &ack,
            )
            .unwrap();
            let mut garble = self.garble_once_at.lock().unwrap();
            if let Some(i) = garble.iter().position(|&o| o == chunk.off) {
                garble.remove(i);
                ack[HEADER_LEN] = CBOR_BREAK;
            }
            if chunk.off != 0 && *self.hold_continuation_acks.lock().unwrap() {
                self.held.lock().unwrap().push(ack);
            } else {
                self.responses.lock().unwrap().push_back(ack);
                self.wake.notify_one();
            }
        }
    }

    impl Transport for ImageDevice {
        fn send(&self, frame: Vec<u8>) -> BoxFuture<'_, Result<(), Error>> {
            self.handle(&frame);
            Box::pin(async { Ok(()) })
        }

        fn receive(&self) -> BoxFuture<'_, Result<Vec<u8>, Error>> {
            Box::pin(async {
                loop {
                    if let Some(bytes) = self.responses.lock().unwrap().pop_front() {
                        return Ok(bytes);
                    }
                    self.wake.notified().await;
                }
            })
        }
    }

    fn session_on(device: Arc<ImageDevice>) -> Session {
        let session = Session::new(device, TEST_CHUNK);
        session.buf_count.store(DEVICE_BUFFERS, Ordering::Release);
        session
    }

    fn test_image() -> Arc<[u8]> {
        let body: Vec<u8> = (0..900u32).map(|i| (i % 253) as u8).collect();
        Arc::from(make_image([0x5A; 32], &body))
    }

    async fn run_upload(
        session: &Session,
        image: &Arc<[u8]>,
        chunk_timeout: Duration,
    ) -> Result<Vec<UploadProgress>, Error> {
        let options = UploadOptions::default().with_chunk_timeout(chunk_timeout);
        let mut stream = session.upload(Arc::clone(image), options);
        let mut reported = Vec::new();
        while let Some(event) = next(&mut stream).await {
            reported.push(event?);
        }
        Ok(reported)
    }

    #[derive(Serialize, Deserialize)]
    struct EchoPayload {
        #[serde(alias = "d")]
        r: String,
    }

    #[derive(Serialize)]
    struct RcReply {
        rc: i32,
    }

    /// Answers echoes `batch` at a time, last first, each after an image
    /// state reply under its sequence number if `stale_reply_first`; never
    /// answers an image chunk; answers a reset with `reset_rc`, or closes the
    /// link at it.
    #[derive(Default)]
    struct OsDevice {
        batch: usize,
        stale_reply_first: bool,
        reset_rc: Option<i32>,
        held: std::sync::Mutex<Vec<Vec<u8>>>,
        received: std::sync::Mutex<VecDeque<Result<Vec<u8>, Error>>>,
        wake: Notify,
    }

    impl OsDevice {
        fn answering_echoes_in_batches_of(batch: usize) -> Arc<Self> {
            Arc::new(Self {
                batch,
                ..Self::default()
            })
        }

        fn answering_echoes_after_a_stale_reply() -> Arc<Self> {
            Arc::new(Self {
                batch: 1,
                stale_reply_first: true,
                ..Self::default()
            })
        }

        fn answering_reset_with(rc: Option<i32>) -> Arc<Self> {
            Arc::new(Self {
                reset_rc: rc,
                ..Self::default()
            })
        }

        fn deliver(&self, received: Result<Vec<u8>, Error>) {
            self.received.lock().unwrap().push_back(received);
            self.wake.notify_one();
        }

        fn close(&self) {
            self.deliver(Err(Error::LinkClosed));
        }
    }

    impl Transport for OsDevice {
        fn send(&self, frame: Vec<u8>) -> BoxFuture<'_, Result<(), Error>> {
            let header = Header::decode(&frame).unwrap();
            match (header.group, header.command) {
                (Group::Os, CMD_ECHO) => {
                    let (_, echo): (_, EchoPayload) = frame::decode(&frame).unwrap();
                    if self.stale_reply_first {
                        self.deliver(frame::encode(
                            Op::ReadResponse,
                            Group::Image,
                            CMD_STATE,
                            header.seq,
                            &Empty {},
                        ));
                    }
                    let reply =
                        frame::encode(Op::WriteResponse, Group::Os, CMD_ECHO, header.seq, &echo)
                            .unwrap();
                    let mut held = self.held.lock().unwrap();
                    held.push(reply);
                    if held.len() >= self.batch {
                        held.drain(..).rev().for_each(|r| self.deliver(Ok(r)));
                    }
                }
                (Group::Os, CMD_RESET) => match self.reset_rc {
                    Some(rc) => self.deliver(frame::encode(
                        Op::WriteResponse,
                        Group::Os,
                        CMD_RESET,
                        header.seq,
                        &RcReply { rc },
                    )),
                    None => self.close(),
                },
                _ => {}
            }
            Box::pin(async { Ok(()) })
        }

        fn receive(&self) -> BoxFuture<'_, Result<Vec<u8>, Error>> {
            Box::pin(async {
                loop {
                    if let Some(received) = self.received.lock().unwrap().pop_front() {
                        return received;
                    }
                    self.wake.notified().await;
                }
            })
        }
    }

    #[tokio::test]
    async fn concurrent_requests_each_get_their_own_reply() {
        let session = Session::new(OsDevice::answering_echoes_in_batches_of(2), TEST_CHUNK);

        let (a, b) = tokio::join!(session.echo("a"), session.echo("b"));

        assert_eq!(a.unwrap(), "a");
        assert_eq!(b.unwrap(), "b");
    }

    #[tokio::test]
    async fn a_reply_under_the_right_sequence_number_to_another_command_is_ignored() {
        let session = Session::new(OsDevice::answering_echoes_after_a_stale_reply(), TEST_CHUNK);

        assert_eq!(session.echo("hi").await.unwrap(), "hi");
    }

    #[tokio::test]
    async fn a_dropped_upload_stops_waiting_and_leaves_the_next_request_its_reply() {
        let session = Session::new(OsDevice::answering_echoes_in_batches_of(1), TEST_CHUNK);
        let stream = session.upload(test_image(), UploadOptions::default());
        tokio::time::sleep(SETTLE).await;
        assert_eq!(
            session.router.awaited(),
            1,
            "the first chunk awaits its ack"
        );

        drop(stream);
        tokio::time::sleep(SETTLE).await;

        assert_eq!(session.router.awaited(), 0);
        assert_eq!(session.echo("hi").await.unwrap(), "hi");
    }

    #[tokio::test]
    async fn a_closed_link_fails_the_waiting_request_and_every_later_one() {
        let device = OsDevice::answering_echoes_in_batches_of(usize::MAX);
        let session = Session::new(Arc::clone(&device) as Arc<dyn Transport>, TEST_CHUNK);
        let waiting = session.echo("never answered");
        let close = async {
            tokio::time::sleep(SETTLE).await;
            device.close();
        };

        let (result, ()) = tokio::join!(waiting, close);

        assert!(matches!(result, Err(Error::LinkClosed)), "{result:?}");
        assert!(!session.is_connected().await);
        assert!(matches!(session.echo("hi").await, Err(Error::LinkClosed)));
    }

    /// Takes a moment over each write, and counts the frames it finishes.
    #[derive(Default)]
    struct SlowLink {
        written: std::sync::Mutex<Vec<Vec<u8>>>,
    }

    impl Transport for SlowLink {
        fn send(&self, frame: Vec<u8>) -> BoxFuture<'_, Result<(), Error>> {
            Box::pin(async move {
                tokio::time::sleep(SETTLE).await;
                self.written.lock().unwrap().push(frame);
                Ok(())
            })
        }

        fn receive(&self) -> BoxFuture<'_, Result<Vec<u8>, Error>> {
            Box::pin(std::future::pending())
        }
    }

    #[tokio::test]
    async fn a_request_dropped_mid_write_still_writes_its_whole_frame() {
        let link = Arc::new(SlowLink::default());
        let session = Session::new(Arc::clone(&link) as Arc<dyn Transport>, TEST_CHUNK);

        let dropped = tokio::time::timeout(SETTLE / 3, session.echo("hi")).await;
        assert!(dropped.is_err());
        tokio::time::sleep(SETTLE * 2).await;

        assert_eq!(link.written.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn a_reset_the_device_refuses_is_an_error() {
        let session = Session::new(OsDevice::answering_reset_with(Some(RC_REFUSED)), TEST_CHUNK);

        let result = session.reset().await;

        assert!(
            matches!(result, Err(Error::Rejected { rc: RC_REFUSED, .. })),
            "{result:?}"
        );
    }

    #[tokio::test]
    async fn a_reset_the_device_accepts_succeeds() {
        let session = Session::new(OsDevice::answering_reset_with(Some(0)), TEST_CHUNK);

        session.reset().await.unwrap();
    }

    #[tokio::test]
    async fn a_reset_that_takes_the_link_down_is_not_an_error() {
        let session = Session::new(OsDevice::answering_reset_with(None), TEST_CHUNK);

        session.reset().await.unwrap();
    }

    #[tokio::test]
    async fn upload_resumes_from_the_device_offset_after_a_dropped_chunk() {
        let dropped_at = 3 * TEST_CHUNK;
        let device = ImageDevice::dropping_once_at(&[dropped_at]);
        let session = session_on(Arc::clone(&device));
        let image = test_image();

        let reported = run_upload(&session, &image, TEST_CHUNK_TIMEOUT)
            .await
            .unwrap();

        assert_eq!(*device.written.lock().unwrap(), image.to_vec());
        assert_eq!(
            device.times_seen(dropped_at),
            2,
            "the dropped chunk must be sent again, and nothing before it"
        );
        let offsets: Vec<usize> = reported.iter().map(|p| p.bytes_sent).collect();
        assert!(
            offsets.windows(2).all(|pair| pair[0] <= pair[1]),
            "only device-confirmed offsets are reported, so progress never falls back: {offsets:?}"
        );
        assert_eq!(offsets.last().copied(), Some(image.len()));
        assert_eq!(
            reported.last().unwrap().image_hash.as_deref(),
            Some(&[0x5A; 32][..])
        );
        let recoveries: Vec<usize> = reported.iter().filter_map(|p| p.resumed_from).collect();
        assert_eq!(
            recoveries,
            vec![dropped_at],
            "one recovery, reported on the first event after it, naming the lost offset"
        );
    }

    #[tokio::test]
    async fn two_losses_at_one_offset_report_one_recovery() {
        let lost_at = 3 * TEST_CHUNK;
        let device = ImageDevice::dropping_once_at(&[lost_at, lost_at]);
        let session = session_on(Arc::clone(&device));
        let image = test_image();

        let reported = run_upload(&session, &image, TEST_CHUNK_TIMEOUT)
            .await
            .unwrap();

        assert_eq!(*device.written.lock().unwrap(), image.to_vec());
        assert_eq!(
            device.times_seen(lost_at),
            3,
            "the chunk, the unanswered probe, and the probe that got through"
        );
        let recoveries: Vec<usize> = reported.iter().filter_map(|p| p.resumed_from).collect();
        assert_eq!(recoveries, vec![lost_at]);
    }

    #[tokio::test]
    async fn a_device_that_forgets_the_upload_reports_the_offset_it_fell_from() {
        let lost_at = 3 * TEST_CHUNK;
        let device = ImageDevice::forgetting_the_upload_when_probed_at(lost_at);
        let session = session_on(Arc::clone(&device));
        let image = test_image();

        let reported = run_upload(&session, &image, TEST_CHUNK_TIMEOUT)
            .await
            .unwrap();

        assert_eq!(*device.written.lock().unwrap(), image.to_vec());
        let recovery = reported
            .iter()
            .find(|p| p.resumed_from.is_some())
            .expect("the restart must be reported");
        assert_eq!(recovery.resumed_from, Some(lost_at));
        assert!(
            recovery.bytes_sent < lost_at,
            "the event names where ground was lost while showing the upload back near the start: {recovery:?}"
        );
    }

    #[tokio::test]
    async fn a_leftover_frame_from_another_request_does_not_abort_the_next_upload() {
        let device = ImageDevice::default();
        let leftover = frame::encode(
            Op::ReadResponse,
            Group::Image,
            CMD_STATE,
            STALE_SEQ,
            &Empty {},
        )
        .unwrap();
        device.responses.lock().unwrap().push_back(leftover);
        let device = Arc::new(device);
        let session = session_on(Arc::clone(&device));
        let image = test_image();

        run_upload(&session, &image, TEST_CHUNK_TIMEOUT)
            .await
            .unwrap();

        assert_eq!(*device.written.lock().unwrap(), image.to_vec());
    }

    #[tokio::test]
    async fn an_undecodable_ack_is_a_stall_the_upload_recovers_from() {
        let device = ImageDevice::garbling_the_ack_once_at(&[0, 3 * TEST_CHUNK]);
        let session = session_on(Arc::clone(&device));
        let image = test_image();

        run_upload(&session, &image, TEST_CHUNK_TIMEOUT)
            .await
            .unwrap();

        assert_eq!(*device.written.lock().unwrap(), image.to_vec());
        assert!(device.garble_once_at.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn upload_keeps_one_device_buffer_free_for_the_response() {
        let device = ImageDevice::holding_continuation_acks();
        let image = test_image();

        let upload = tokio::spawn({
            let device = Arc::clone(&device);
            let image = Arc::clone(&image);
            async move { run_upload(&session_on(device), &image, HELD_ACK_TIMEOUT).await }
        });
        tokio::time::sleep(SETTLE).await;

        let outstanding = device.offsets_seen.lock().unwrap().len() - 1;
        assert_eq!(outstanding, DEVICE_BUFFERS - 1);

        device.release_held_acks();
        upload.await.unwrap().unwrap();
        assert_eq!(*device.written.lock().unwrap(), image.to_vec());
    }

    #[tokio::test]
    async fn dropping_the_stream_sends_no_further_chunk() {
        let device = ImageDevice::holding_continuation_acks();
        let session = session_on(Arc::clone(&device));
        let options = UploadOptions::default().with_chunk_timeout(HELD_ACK_TIMEOUT);
        let mut stream = session.upload(test_image(), options);
        next(&mut stream).await.unwrap().unwrap();
        tokio::time::sleep(SETTLE).await;
        let sent = device.offsets_seen.lock().unwrap().len();

        drop(stream);
        device.release_held_acks();
        tokio::time::sleep(SETTLE).await;

        assert_eq!(device.offsets_seen.lock().unwrap().len(), sent);
    }

    #[tokio::test]
    async fn upload_fails_when_the_device_reports_a_hash_mismatch() {
        let device = ImageDevice::reporting_a_hash_mismatch();
        let session = session_on(Arc::clone(&device));

        let result = run_upload(&session, &test_image(), TEST_CHUNK_TIMEOUT).await;

        assert!(matches!(result, Err(Error::HashMismatch)), "got {result:?}");
    }

    #[tokio::test]
    async fn upload_refuses_an_image_that_is_not_mcuboot() {
        let session = session_on(Arc::new(ImageDevice::default()));

        let result = run_upload(&session, &Arc::from(&[0u8; 64][..]), TEST_CHUNK_TIMEOUT).await;

        assert!(
            matches!(result, Err(Error::NotMcuboot(_))),
            "got {result:?}"
        );
    }

    #[tokio::test]
    async fn upload_gives_up_after_repeated_stalls_at_one_offset() {
        let dropped_at = 3 * TEST_CHUNK;
        let device = ImageDevice::dropping_always_at(dropped_at);
        let session = session_on(Arc::clone(&device));

        let result = run_upload(&session, &test_image(), TEST_CHUNK_TIMEOUT).await;

        assert!(
            matches!(result, Err(Error::UploadStalled { offset, .. }) if offset == dropped_at),
            "got {result:?}"
        );
        assert_eq!(
            device.times_seen(dropped_at),
            MAX_RESUMES_WITHOUT_PROGRESS + 1,
            "the chunk is tried once, then resumed a bounded number of times"
        );
    }

    #[tokio::test]
    async fn a_dropped_final_chunk_is_resent_after_the_chunk_timer() {
        let image = test_image();
        let last_start = (image.len() - 1) / TEST_CHUNK * TEST_CHUNK;
        let device = ImageDevice::dropping_once_at(&[last_start]);
        let session = session_on(Arc::clone(&device));
        let started = std::time::Instant::now();

        run_upload(&session, &image, TEST_CHUNK_TIMEOUT)
            .await
            .unwrap();

        assert!(
            started.elapsed() >= TEST_CHUNK_TIMEOUT,
            "with no later chunk to expose the loss, only the chunk timer can"
        );
        assert_eq!(device.times_seen(last_start), 2);
        assert_eq!(*device.written.lock().unwrap(), image.to_vec());
    }

    #[tokio::test]
    async fn stall_budget_resets_once_the_upload_advances() {
        let drops: Vec<usize> = (2..2 + MAX_RESUMES_WITHOUT_PROGRESS + 1)
            .map(|n| n * 2 * TEST_CHUNK)
            .collect();
        let device = ImageDevice::dropping_once_at(&drops);
        let session = session_on(Arc::clone(&device));
        let image = test_image();

        run_upload(&session, &image, TEST_CHUNK_TIMEOUT)
            .await
            .unwrap();

        assert_eq!(*device.written.lock().unwrap(), image.to_vec());
        assert!(device.drops.lock().unwrap().is_empty());
    }
}
