//! The TCP link under a session: a reader task that unframes and parses every
//! frame onto one channel, and a writer task that batches outbound frames.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use wslib_framelink_protocol::frame::{self, Frame, HEADER_SIZE};
use wslib_framing::cobs::{self, CobsDecoder};

use crate::Error;

/// The longest stuffed block a frame can be: the header and a payload as
/// long as its `u16` length field allows. A longer block is abandoned.
pub(crate) const MAX_STUFFED_FRAME: usize = cobs::max_stuffed_len(HEADER_SIZE + u16::MAX as usize);

/// Frames dropped before they reached a reply or the stream, since the
/// session opened.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FramingStats {
    /// Blocks longer than any frame, abandoned up to the next delimiter.
    pub abandoned_frames: u64,
    /// Blocks that were not valid COBS.
    pub malformed_frames: u64,
    /// Streamed frames dropped because the stream channel was full.
    pub stream_dropped: u64,
}

#[derive(Debug, Default)]
pub(crate) struct FramingCounters {
    abandoned: AtomicU64,
    malformed: AtomicU64,
    stream_dropped: AtomicU64,
}

impl FramingCounters {
    pub(crate) fn snapshot(&self) -> FramingStats {
        FramingStats {
            abandoned_frames: self.abandoned.load(Ordering::Relaxed),
            malformed_frames: self.malformed.load(Ordering::Relaxed),
            stream_dropped: self.stream_dropped.load(Ordering::Relaxed),
        }
    }

    pub(crate) fn stream_dropped(&self) {
        self.stream_dropped.fetch_add(1, Ordering::Relaxed);
    }

    fn record(&self, decoder: &CobsDecoder) {
        self.abandoned
            .store(decoder.abandoned_frames(), Ordering::Relaxed);
        self.malformed
            .store(decoder.malformed_frames(), Ordering::Relaxed);
    }
}

#[derive(Clone)]
pub(crate) struct FrameSender {
    write_tx: mpsc::Sender<Vec<u8>>,
    tx_seq: Arc<AtomicU8>,
}

impl FrameSender {
    pub(crate) async fn send(&self, msg_type: u8, flags: u8, payload: &[u8]) -> Result<u8, Error> {
        let (seq, wire) = self.frame(msg_type, flags, payload);
        self.write(wire).await?;
        Ok(seq)
    }

    pub(crate) fn frame(&self, msg_type: u8, flags: u8, payload: &[u8]) -> (u8, Vec<u8>) {
        let seq = self.tx_seq.fetch_add(1, Ordering::Relaxed);
        (seq, frame::build_frame(msg_type, flags, seq, payload))
    }

    pub(crate) async fn write(&self, wire: Vec<u8>) -> Result<(), Error> {
        self.write_tx
            .send(wire)
            .await
            .map_err(|_| Error::SendFailed)
    }
}

pub(crate) struct FrameLinkClient {
    addr: SocketAddr,
    sender: FrameSender,
    framing: Arc<FramingCounters>,
    reader_handle: JoinHandle<()>,
    writer_handle: JoinHandle<()>,
}

impl Drop for FrameLinkClient {
    fn drop(&mut self) {
        self.reader_handle.abort();
        self.writer_handle.abort();
    }
}

impl FrameLinkClient {
    /// The receiver carries every frame the device sends.
    pub(crate) async fn connect(
        addr: SocketAddr,
        timeout: Duration,
    ) -> Result<(Self, mpsc::Receiver<Frame>), Error> {
        let stream = tokio::time::timeout(timeout, TcpStream::connect(addr))
            .await
            .map_err(|_| Error::Timeout(timeout))??;
        stream.set_nodelay(true)?;
        let (read_half, write_half) = stream.into_split();

        const WRITE_CHANNEL_CAP: usize = 64;
        const RESPONSE_CHANNEL_CAP: usize = 4096;
        let (write_tx, write_rx) = mpsc::channel::<Vec<u8>>(WRITE_CHANNEL_CAP);
        let (response_tx, response_rx) = mpsc::channel::<Frame>(RESPONSE_CHANNEL_CAP);

        let framing = Arc::new(FramingCounters::default());
        let reader_handle = tokio::spawn(reader_task(read_half, response_tx, framing.clone()));
        let writer_handle = tokio::spawn(writer_task(write_half, write_rx));

        let sender = FrameSender {
            write_tx,
            tx_seq: Arc::new(AtomicU8::new(0)),
        };
        Ok((
            Self {
                addr,
                sender,
                framing,
                reader_handle,
                writer_handle,
            },
            response_rx,
        ))
    }

    pub(crate) fn addr(&self) -> SocketAddr {
        self.addr
    }

    pub(crate) fn sender(&self) -> FrameSender {
        self.sender.clone()
    }

    pub(crate) fn framing_stats(&self) -> FramingStats {
        self.framing.snapshot()
    }

    pub(crate) fn counters(&self) -> Arc<FramingCounters> {
        self.framing.clone()
    }
}

async fn reader_task(
    mut read_half: OwnedReadHalf,
    response_tx: mpsc::Sender<Frame>,
    framing: Arc<FramingCounters>,
) {
    let mut decoder = CobsDecoder::with_max_frame_len(MAX_STUFFED_FRAME);
    let mut tmp = [0u8; 4096];
    loop {
        let n = match read_half.read(&mut tmp).await {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        let released = decoder.feed(&tmp[..n]);
        framing.record(&decoder);
        for framed in released {
            let Ok(frame) = frame::parse_unstuffed(&framed.bytes) else {
                continue;
            };
            match response_tx.try_send(frame) {
                Ok(()) => {}
                Err(mpsc::error::TrySendError::Full(frame)) => {
                    if response_tx.send(frame).await.is_err() {
                        return;
                    }
                }
                Err(mpsc::error::TrySendError::Closed(_)) => return,
            }
        }
    }
}

/// Batches every frame already queued into one write, to pack segments.
async fn writer_task(mut write_half: OwnedWriteHalf, mut write_rx: mpsc::Receiver<Vec<u8>>) {
    let mut batch = Vec::with_capacity(4096);
    while let Some(data) = write_rx.recv().await {
        batch.extend_from_slice(&data);
        while let Ok(data) = write_rx.try_recv() {
            batch.extend_from_slice(&data);
        }
        if write_half.write_all(&batch).await.is_err() {
            break;
        }
        batch.clear();
    }
}
