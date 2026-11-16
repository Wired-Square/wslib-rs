//! The link under a session, TCP or ISO-TP: a reader task that unframes and
//! parses every frame onto one channel, and a writer task that sends outbound
//! frames.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use wslib_framelink_protocol::Error as ProtocolError;
use wslib_framelink_protocol::frame::{self, Frame, HEADER_SIZE};
use wslib_framing::Framed;
use wslib_framing::cobs::{self, CobsDecoder};
#[cfg(feature = "can")]
use {
    wslib_can::{CanOptions, CanTask},
    wslib_can_bus::CanBus,
    wslib_framelink_protocol::can_id::{
        DEVICE_ID_SHIFT, DeviceId as CanDeviceId, SLOT_ISOTP_D2H, SLOT_ISOTP_H2D, can_id,
    },
    wslib_isotp::{IsoTpLink, LinkConfig, Messages},
};

use crate::{Error, Peer};

/// The longest stuffed block a frame can be: the header and a payload as
/// long as its `u16` length field allows. A longer block is abandoned.
pub(crate) const MAX_STUFFED_FRAME: usize = cobs::max_stuffed_len(HEADER_SIZE + u16::MAX as usize);

const READ_BUFFER: usize = 4096;
const WRITE_BATCH: usize = 4096;
const WRITE_CHANNEL_CAP: usize = 64;
const RESPONSE_CHANNEL_CAP: usize = 4096;
const VERSION_MASK: u64 = u8::MAX as u64;
const COUNT_SHIFT: u32 = u8::BITS;
const ONE_FRAME: u64 = 1 << COUNT_SHIFT;
#[cfg(feature = "can")]
const ADAPTER_CHANNEL: u8 = 0;

/// Frames the link dropped in either direction since the session opened.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct FramingStats {
    /// Blocks longer than any frame, abandoned up to the next delimiter.
    pub abandoned_frames: u64,
    /// Blocks that were not valid COBS.
    pub malformed_frames: u64,
    /// Streamed frames dropped because the stream channel was full.
    pub stream_dropped: u64,
    /// Frames an ISO-TP link failed to send. One the adapter took but never
    /// confirmed may still have reached the device. Always 0 on TCP.
    pub send_failures: u64,
    /// ISO-TP messages received whole and dropped because the session's queue
    /// was full. Always 0 on TCP.
    pub messages_dropped: u64,
    /// Frames on another FrameLink protocol version.
    pub other_version_frames: u64,
    /// The version of the last such frame.
    pub last_other_version: Option<u8>,
    /// Frames that unstuffed but didn't parse for another reason.
    pub unparsed_frames: u64,
}

#[derive(Default)]
pub(crate) struct FramingCounters {
    abandoned: AtomicU64,
    malformed: AtomicU64,
    stream_dropped: AtomicU64,
    send_failures: AtomicU64,
    other_version: AtomicU64,
    unparsed: AtomicU64,
    #[cfg(feature = "can")]
    isotp: Option<IsoTpLink>,
}

impl FramingCounters {
    #[cfg(feature = "can")]
    fn over_isotp(link: IsoTpLink) -> Self {
        Self {
            isotp: Some(link),
            ..Self::default()
        }
    }

    pub(crate) fn snapshot(&self) -> FramingStats {
        let other_version = self.other_version.load(Ordering::Acquire);
        let other_version_frames = other_version >> COUNT_SHIFT;
        FramingStats {
            abandoned_frames: self.abandoned.load(Ordering::Relaxed),
            malformed_frames: self.malformed.load(Ordering::Relaxed),
            stream_dropped: self.stream_dropped.load(Ordering::Relaxed),
            send_failures: self.send_failures.load(Ordering::Relaxed),
            messages_dropped: self.messages_dropped(),
            other_version_frames,
            last_other_version: (other_version_frames > 0)
                .then_some((other_version & VERSION_MASK) as u8),
            unparsed_frames: self.unparsed.load(Ordering::Relaxed),
        }
    }

    fn on_other_version(&self, peer: u8) {
        let packed = self.other_version.load(Ordering::Acquire);
        let next = (packed & !VERSION_MASK).wrapping_add(ONE_FRAME) | u64::from(peer);
        self.other_version.store(next, Ordering::Release);
    }

    fn unparsed(&self) {
        self.unparsed.fetch_add(1, Ordering::Relaxed);
    }

    #[cfg(feature = "can")]
    fn messages_dropped(&self) -> u64 {
        self.isotp
            .as_ref()
            .map_or(0, |link| link.stats().messages_dropped)
    }

    #[cfg(not(feature = "can"))]
    fn messages_dropped(&self) -> u64 {
        0
    }

    pub(crate) fn stream_dropped(&self) {
        self.stream_dropped.fetch_add(1, Ordering::Relaxed);
    }

    #[cfg(feature = "can")]
    fn send_failed(&self) {
        self.send_failures.fetch_add(1, Ordering::Relaxed);
    }

    fn record(&self, decoder: &CobsDecoder) {
        self.abandoned
            .store(decoder.abandoned_frames(), Ordering::Relaxed);
        self.malformed
            .store(decoder.malformed_frames(), Ordering::Relaxed);
    }
}

pub(crate) enum Received {
    Frame(Frame),
    PeerVersion(u8),
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

/// The [`LinkConfig`] for a host's ISO-TP link to `device` on an adapter's
/// first channel. It sends on the device's host-to-device slot with the host
/// bit set, and receives on its device-to-host slot, with 29-bit ids.
#[cfg(feature = "can")]
pub fn can_link_config(device: CanDeviceId) -> LinkConfig {
    let base = device.get() << DEVICE_ID_SHIFT;
    LinkConfig::new(
        ADAPTER_CHANNEL,
        can_id(base, SLOT_ISOTP_H2D, true),
        can_id(base, SLOT_ISOTP_D2H, false),
    )
}

#[cfg(feature = "can")]
pub(crate) fn can_options() -> CanOptions {
    let mut options = CanOptions::default();
    options.reopen = None;
    options
}

enum Inbound {
    Tcp {
        read_half: OwnedReadHalf,
        buffer: Box<[u8]>,
    },
    #[cfg(feature = "can")]
    IsoTp(Messages),
}

impl Inbound {
    async fn next(&mut self, decoder: &mut CobsDecoder) -> Option<Vec<Framed>> {
        match self {
            Inbound::Tcp { read_half, buffer } => match read_half.read(buffer).await {
                Ok(0) | Err(_) => None,
                Ok(n) => Some(decoder.feed(&buffer[..n])),
            },
            #[cfg(feature = "can")]
            Inbound::IsoTp(messages) => messages.recv().await.map(|message| decoder.feed(&message)),
        }
    }
}

enum Outbound {
    Tcp(OwnedWriteHalf),
    #[cfg(feature = "can")]
    IsoTp {
        link: IsoTpLink,
        framing: Arc<FramingCounters>,
    },
}

impl Outbound {
    async fn run(self, write_rx: mpsc::Receiver<Vec<u8>>) {
        match self {
            Outbound::Tcp(write_half) => write_batches(write_half, write_rx).await,
            #[cfg(feature = "can")]
            Outbound::IsoTp { link, framing } => send_each(link, write_rx, &framing).await,
        }
    }
}

pub(crate) struct FrameLinkClient {
    peer: Peer,
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

type Opened = (FrameLinkClient, mpsc::Receiver<Received>);

impl FrameLinkClient {
    /// The receiver carries every frame the device sends.
    pub(crate) async fn connect(addr: SocketAddr, timeout: Duration) -> Result<Opened, Error> {
        let stream = tokio::time::timeout(timeout, TcpStream::connect(addr))
            .await
            .map_err(|_| Error::Timeout(timeout))??;
        stream.set_nodelay(true)?;
        let (read_half, write_half) = stream.into_split();
        let inbound = Inbound::Tcp {
            read_half,
            buffer: vec![0; READ_BUFFER].into_boxed_slice(),
        };
        let framing = Arc::new(FramingCounters::default());
        Ok(Self::start(
            Peer::Tcp(addr),
            inbound,
            Outbound::Tcp(write_half),
            framing,
        ))
    }

    #[cfg(feature = "can")]
    pub(crate) fn isotp(
        link: IsoTpLink,
        messages: Messages,
        bus: CanBus,
        device: CanDeviceId,
    ) -> Opened {
        let framing = Arc::new(FramingCounters::over_isotp(link.clone()));
        let outbound = Outbound::IsoTp {
            link,
            framing: framing.clone(),
        };
        Self::start(
            Peer::Can { bus, device },
            Inbound::IsoTp(messages),
            outbound,
            framing,
        )
    }

    #[cfg(feature = "can")]
    pub(crate) async fn can(
        bus: &CanBus,
        device: CanDeviceId,
        bitrate: Option<u32>,
        timeout: Duration,
    ) -> Result<Opened, Error> {
        let opening = wslib_can_bus::open(bus, bitrate, can_options());
        let task = tokio::time::timeout(timeout, opening)
            .await
            .map_err(|_| Error::Timeout(timeout))??;
        Ok(Self::over_can_task(task, bus.clone(), device))
    }

    #[cfg(feature = "can")]
    pub(crate) fn over_can_task(task: CanTask, bus: CanBus, device: CanDeviceId) -> Opened {
        let (link, messages) = IsoTpLink::over(task, can_link_config(device));
        Self::isotp(link, messages, bus, device)
    }

    fn start(
        peer: Peer,
        inbound: Inbound,
        outbound: Outbound,
        framing: Arc<FramingCounters>,
    ) -> Opened {
        let (write_tx, write_rx) = mpsc::channel::<Vec<u8>>(WRITE_CHANNEL_CAP);
        let (response_tx, response_rx) = mpsc::channel::<Received>(RESPONSE_CHANNEL_CAP);
        let reader_handle = tokio::spawn(reader_task(inbound, response_tx, framing.clone()));
        let writer_handle = tokio::spawn(outbound.run(write_rx));
        let sender = FrameSender {
            write_tx,
            tx_seq: Arc::new(AtomicU8::new(0)),
        };
        let client = Self {
            peer,
            sender,
            framing,
            reader_handle,
            writer_handle,
        };
        (client, response_rx)
    }

    pub(crate) fn peer(&self) -> &Peer {
        &self.peer
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
    mut inbound: Inbound,
    response_tx: mpsc::Sender<Received>,
    framing: Arc<FramingCounters>,
) {
    let mut decoder = CobsDecoder::with_max_frame_len(MAX_STUFFED_FRAME);
    while let Some(released) = inbound.next(&mut decoder).await {
        framing.record(&decoder);
        for framed in released {
            let received = match frame::parse_unstuffed(&framed.bytes) {
                Ok(frame) => Received::Frame(frame),
                Err(ProtocolError::UnsupportedVersion(peer)) => {
                    tracing::debug!(peer, "frame on another FrameLink protocol version");
                    framing.on_other_version(peer);
                    Received::PeerVersion(peer)
                }
                Err(error) => {
                    tracing::debug!(%error, "frame that doesn't parse");
                    framing.unparsed();
                    continue;
                }
            };
            match response_tx.try_send(received) {
                Ok(()) => {}
                Err(mpsc::error::TrySendError::Full(received)) => {
                    if response_tx.send(received).await.is_err() {
                        return;
                    }
                }
                Err(mpsc::error::TrySendError::Closed(_)) => return,
            }
        }
    }
}

/// Batches every frame already queued into one write, to pack segments.
async fn write_batches(mut write_half: OwnedWriteHalf, mut write_rx: mpsc::Receiver<Vec<u8>>) {
    let mut batch = Vec::with_capacity(WRITE_BATCH);
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

#[cfg(feature = "can")]
async fn send_each(
    link: IsoTpLink,
    mut write_rx: mpsc::Receiver<Vec<u8>>,
    framing: &FramingCounters,
) {
    while let Some(wire) = write_rx.recv().await {
        if let Err(error) = link.send(&wire).await {
            tracing::debug!(%error, "ISO-TP send failed");
            framing.send_failed();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const V3: u8 = 3;
    const V5: u8 = 5;
    const MANY: u64 = 300;

    #[test]
    fn other_version_frames_and_the_last_version_read_as_one() {
        let counters = FramingCounters::default();
        let stats = counters.snapshot();
        assert_eq!(
            (stats.other_version_frames, stats.last_other_version),
            (0, None)
        );
        counters.on_other_version(V3);
        counters.on_other_version(V5);
        let stats = counters.snapshot();
        assert_eq!(
            (stats.other_version_frames, stats.last_other_version),
            (2, Some(V5))
        );
        for _ in 0..MANY {
            counters.on_other_version(u8::MAX);
        }
        let stats = counters.snapshot();
        assert_eq!(
            (stats.other_version_frames, stats.last_other_version),
            (2 + MANY, Some(u8::MAX))
        );
    }
}
