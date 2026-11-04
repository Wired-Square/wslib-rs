//! One device's connection: a task serialises each request with its reply,
//! under a timeout, and routes FRAME_RX to the stream channel.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use wslib_framelink_board::editable::ActiveRuleIds;
use wslib_framelink_protocol::frame::Frame;
use wslib_framelink_protocol::stream::{
    self, StreamFrame, build_stream_start, build_stream_stop, parse_frame_rx,
};
use wslib_framelink_protocol::types::{
    self, FLAG_ACK_REQ, FLAG_NONE, MSG_ACK, MSG_BRIDGE_LIST, MSG_CAPABILITIES_REQ,
    MSG_CAPABILITIES_RESP, MSG_DSIG_LIST, MSG_DSIG_LIST_RESP, MSG_FRAME_DEF_LIST, MSG_FRAME_RX,
    MSG_FRAME_TX, MSG_FRAME_TX_BATCH, MSG_GEN_LIST, MSG_NACK, MSG_STREAM_START, MSG_STREAM_STOP,
    MSG_XFORM_LIST,
};
use wslib_framelink_protocol::{bridge, capabilities, dsig, frame_def, generator, xform};

use crate::Error;
use crate::client::{FrameLinkClient, FrameSender, FramingCounters, FramingStats};

enum SessionCommand {
    Request {
        msg_type: u8,
        flags: u8,
        payload: Vec<u8>,
        expect: Expect,
        resends: usize,
        result_tx: oneshot::Sender<Result<Answer, Error>>,
    },
    RequestMulti {
        msg_type: u8,
        flags: u8,
        payload: Vec<u8>,
        result_tx: oneshot::Sender<Result<Vec<Frame>, Error>>,
    },
    SendBatch {
        messages: Vec<(u8, u8, Vec<u8>)>,
        result_tx: oneshot::Sender<Result<Vec<Frame>, Error>>,
    },
    TransmitStream {
        entries: Vec<stream::BatchFrameEntry>,
        queue_depth: usize,
        result_tx: oneshot::Sender<Result<TransmitStats, Error>>,
    },
}

const FILE_STEP_RESENDS: usize = 3;

const FILE_RESTARTS: usize = 2;

const MAX_FILE_DATA_CHUNK: usize =
    u16::MAX as usize - wslib_framelink_protocol::file_xfer::DATA_OFFSET_LEN;

const UNLOCK_ATTEMPTS: usize = 3;

#[derive(Clone, Copy)]
enum Expect {
    AckOrNack,
    Reply(u8),
    Any,
}

struct Outgoing<'a> {
    msg_type: u8,
    flags: u8,
    payload: &'a [u8],
    expect: Expect,
    resends: usize,
}

struct Answer {
    frame: Frame,
    resent: bool,
}

enum UnlockAttempt {
    Unlocked,
    NonceStale,
    Refused(u8),
}

enum FileStep {
    Acked,
    SessionLost,
    Unresolved,
}

/// `bytes_done` drops back to zero when the upload has to start over.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileProgress {
    pub bytes_done: usize,
    pub total_bytes: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileUploadOutcome {
    /// Accepted, not yet installed: the install reports through device signals.
    Committed,
    /// Not a failure: a rebooting target can't answer, so read back its running build.
    Unknown,
}

#[derive(Debug, Clone)]
pub struct TransmitStats {
    pub sent: usize,
    pub acked: usize,
    pub nacked: usize,
}

pub struct SessionConfig {
    /// How long the TCP connect may take; 5 seconds by default.
    pub connect_timeout: Duration,
    /// How long one reply may take; 15 seconds by default.
    pub command_timeout: Duration,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(5),
            command_timeout: Duration::from_secs(15),
        }
    }
}

/// A connection to one FrameLink device. A request refused as WRITE_LOCKED
/// is unlocked and sent again.
pub struct FrameLinkSession {
    addr: SocketAddr,
    cmd_tx: mpsc::Sender<SessionCommand>,
    stream_rx: tokio::sync::Mutex<mpsc::Receiver<StreamFrame>>,
    client: FrameLinkClient,
    task_handle: JoinHandle<()>,
}

impl Drop for FrameLinkSession {
    fn drop(&mut self) {
        self.task_handle.abort();
    }
}

impl FrameLinkSession {
    pub async fn connect(addr: SocketAddr) -> Result<Arc<Self>, Error> {
        Self::connect_with_config(addr, SessionConfig::default()).await
    }

    pub async fn connect_with_config(
        addr: SocketAddr,
        config: SessionConfig,
    ) -> Result<Arc<Self>, Error> {
        let (client, response_rx) = FrameLinkClient::connect(addr, config.connect_timeout).await?;
        let sender = client.sender();
        let command_timeout = config.command_timeout;

        const STREAM_CHANNEL_CAP: usize = 4096;
        let (stream_tx, stream_rx) = mpsc::channel::<StreamFrame>(STREAM_CHANNEL_CAP);

        let (cmd_tx, cmd_rx) = mpsc::channel(64);

        let task_handle = tokio::spawn(session_task(
            sender,
            response_rx,
            cmd_rx,
            command_timeout,
            StreamSink {
                tx: stream_tx,
                counters: client.counters(),
            },
        ));

        Ok(Arc::new(Self {
            addr: client.addr(),
            cmd_tx,
            stream_rx: tokio::sync::Mutex::new(stream_rx),
            client,
            task_handle,
        }))
    }

    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    pub fn is_alive(&self) -> bool {
        !self.task_handle.is_finished()
    }

    /// Frames the link has dropped before they could reach a reply or the
    /// stream.
    pub fn framing_stats(&self) -> FramingStats {
        self.client.framing_stats()
    }

    /// Sends a request and waits for its reply, which must be `expected`: a
    /// NACK is [`Error::Nack`], any other type [`Error::UnexpectedReply`].
    pub async fn request_reply(
        &self,
        msg_type: u8,
        flags: u8,
        payload: &[u8],
        expected: u8,
    ) -> Result<Frame, Error> {
        let reply = self.request(msg_type, flags, payload).await?;
        expect_reply(msg_type, expected, reply)
    }

    /// Sends a request and waits for its one reply, whatever it is.
    pub async fn request(&self, msg_type: u8, flags: u8, payload: &[u8]) -> Result<Frame, Error> {
        self.exchange(msg_type, flags, payload, Expect::Any, 0)
            .await
            .map(|answer| answer.frame)
    }

    async fn exchange(
        &self,
        msg_type: u8,
        flags: u8,
        payload: &[u8],
        expect: Expect,
        resends: usize,
    ) -> Result<Answer, Error> {
        self.command(|result_tx| SessionCommand::Request {
            msg_type,
            flags,
            payload: payload.to_vec(),
            expect,
            resends,
            result_tx,
        })
        .await
    }

    async fn command<T>(
        &self,
        command: impl FnOnce(oneshot::Sender<Result<T, Error>>) -> SessionCommand,
    ) -> Result<T, Error> {
        let (result_tx, result_rx) = oneshot::channel();
        self.cmd_tx
            .send(command(result_tx))
            .await
            .map_err(|_| Error::ConnectionClosed)?;
        result_rx.await.map_err(|_| Error::ConnectionClosed)?
    }

    /// The next frame the device streamed; `None` once the connection closes.
    /// Every caller shares one reader.
    pub async fn recv_stream_frame(&self) -> Option<StreamFrame> {
        let mut rx = self.stream_rx.lock().await;
        rx.recv().await
    }

    /// Discards the stream frames already received.
    pub fn drain_stream_frames(&self) {
        if let Ok(mut rx) = self.stream_rx.try_lock() {
            while rx.try_recv().is_ok() {}
        }
    }

    pub async fn start_stream(&self, iface_index: u8) -> Result<Frame, Error> {
        let payload = build_stream_start(iface_index, None);
        self.request(MSG_STREAM_START, FLAG_ACK_REQ, &payload).await
    }

    /// Waits for the device's answer, if any, so it is not taken for the next
    /// request's.
    pub async fn stop_stream(&self, iface_index: u8) -> Result<(), Error> {
        let payload = build_stream_stop(iface_index);
        let _ = self.request(MSG_STREAM_STOP, FLAG_NONE, &payload).await;
        Ok(())
    }

    /// Transmits one frame and waits for its ACK; `transmit_stream` pipelines.
    pub async fn transmit(&self, data: &[u8]) -> Result<(), Error> {
        self.request_reply(MSG_FRAME_TX, FLAG_ACK_REQ, data, MSG_ACK)
            .await?;
        Ok(())
    }

    /// Sends the frames in FRAME_TX_BATCH messages of up to `queue_depth`
    /// each, as fast as TCP takes them: a full device TX queue stalls the
    /// device's TCP receive, which is the flow control.
    pub async fn transmit_stream(
        &self,
        entries: Vec<stream::BatchFrameEntry>,
        queue_depth: usize,
    ) -> Result<TransmitStats, Error> {
        self.command(|result_tx| SessionCommand::TransmitStream {
            entries,
            queue_depth,
            result_tx,
        })
        .await
    }

    /// Sends a request and collects its replies until the ACK.
    pub async fn request_multi(
        &self,
        msg_type: u8,
        flags: u8,
        payload: &[u8],
    ) -> Result<Vec<Frame>, Error> {
        self.command(|result_tx| SessionCommand::RequestMulti {
            msg_type,
            flags,
            payload: payload.to_vec(),
            result_tx,
        })
        .await
    }

    /// Sends the messages pipelined and returns each one's reply, in order.
    pub async fn send_batch(&self, messages: &[(u8, u8, Vec<u8>)]) -> Result<Vec<Frame>, Error> {
        self.command(|result_tx| SessionCommand::SendBatch {
            messages: messages.to_vec(),
            result_tx,
        })
        .await
    }

    pub async fn list_frame_defs(&self) -> Result<Vec<frame_def::FrameDefInfo>, Error> {
        let payload = frame_def::build_frame_def_list();
        self.list(
            MSG_FRAME_DEF_LIST,
            &payload,
            frame_def::parse_frame_def_resp,
        )
        .await
    }

    pub async fn list_bridges(&self) -> Result<Vec<bridge::BridgeInfo>, Error> {
        let payload = bridge::build_bridge_list();
        self.list(MSG_BRIDGE_LIST, &payload, bridge::parse_bridge_resp)
            .await
    }

    pub async fn list_transformers(&self) -> Result<Vec<xform::TransformerInfo>, Error> {
        let payload = xform::build_xform_list();
        self.list(MSG_XFORM_LIST, &payload, xform::parse_xform_resp)
            .await
    }

    pub async fn list_generators(&self) -> Result<Vec<generator::GeneratorInfo>, Error> {
        let payload = generator::build_gen_list();
        self.list(MSG_GEN_LIST, &payload, generator::parse_gen_resp)
            .await
    }

    async fn list<T>(
        &self,
        msg_type: u8,
        payload: &[u8],
        parse: fn(&[u8]) -> Result<T, wslib_framelink_protocol::Error>,
    ) -> Result<Vec<T>, Error> {
        let frames = self.request_multi(msg_type, FLAG_ACK_REQ, payload).await?;
        Ok(frames
            .iter()
            .map(|f| parse(&f.payload))
            .collect::<Result<_, _>>()?)
    }

    pub async fn capabilities(&self) -> Result<capabilities::Capabilities, Error> {
        let frame = self
            .request_reply(
                MSG_CAPABILITIES_REQ,
                FLAG_ACK_REQ,
                &[],
                MSG_CAPABILITIES_RESP,
            )
            .await?;
        Ok(capabilities::decode_capabilities(&frame.payload)?)
    }

    /// Every device signal, over as many pages as the device sends.
    pub async fn list_all_signals(&self) -> Result<Vec<dsig::SignalInfo>, Error> {
        let mut all_signals = Vec::new();
        let mut offset: u16 = 0;
        loop {
            let frame = self
                .request_reply(
                    MSG_DSIG_LIST,
                    0,
                    &dsig::build_list_request(offset),
                    MSG_DSIG_LIST_RESP,
                )
                .await?;
            let chunk = dsig::parse_list_response(&frame.payload)?;
            let complete = chunk.is_complete();
            offset = chunk.next_offset();
            all_signals.extend(chunk.signals);
            if complete {
                break;
            }
        }
        Ok(all_signals)
    }

    pub async fn upload_file(
        &self,
        target: u8,
        data: &[u8],
        progress: Option<mpsc::Sender<FileProgress>>,
    ) -> Result<FileUploadOutcome, Error> {
        use wslib_framelink_protocol::file_xfer::{FileBegin, file_crc32, pack_begin};

        let size = u32::try_from(data.len()).map_err(|_| {
            Error::Protocol(format!(
                "a {}-byte file is larger than FILE_BEGIN can declare",
                data.len()
            ))
        })?;
        let chunk_size = self
            .capabilities()
            .await?
            .max_file_chunk()
            .filter(|&chunk| chunk > 0)
            .ok_or_else(|| {
                Error::Protocol(
                    "device advertises no file chunk size, so it has no file transfer".to_string(),
                )
            })?;
        let chunk_size = usize::try_from(chunk_size)
            .unwrap_or(MAX_FILE_DATA_CHUNK)
            .min(MAX_FILE_DATA_CHUNK);

        let begin = pack_begin(&FileBegin {
            target,
            size,
            crc32: file_crc32(data),
        });

        for _ in 0..=FILE_RESTARTS {
            if let Some(outcome) = self
                .try_upload(&begin, data, chunk_size, progress.as_ref())
                .await?
            {
                return Ok(outcome);
            }
        }
        Err(Error::Protocol(
            "device kept dropping the file session".to_string(),
        ))
    }

    /// Does not undo a commit that already happened.
    pub async fn abort_file(&self) -> Result<(), Error> {
        use wslib_framelink_protocol::file_xfer::{FileAction, pack_end};
        use wslib_framelink_protocol::types::MSG_FILE_END;

        match self
            .file_step(MSG_FILE_END, &pack_end(FileAction::Abort))
            .await?
        {
            FileStep::Acked | FileStep::SessionLost => Ok(()),
            FileStep::Unresolved => Err(Error::Protocol("FILE_END abort went unanswered".into())),
        }
    }

    async fn try_upload(
        &self,
        begin: &[u8],
        data: &[u8],
        chunk_size: usize,
        progress: Option<&mpsc::Sender<FileProgress>>,
    ) -> Result<Option<FileUploadOutcome>, Error> {
        use wslib_framelink_protocol::file_xfer::{FileAction, FileData, pack_data, pack_end};
        use wslib_framelink_protocol::types::{MSG_FILE_BEGIN, MSG_FILE_DATA, MSG_FILE_END};

        let total = data.len();
        match self.file_step(MSG_FILE_BEGIN, begin).await? {
            FileStep::Acked => {}
            FileStep::SessionLost => return Ok(None),
            FileStep::Unresolved => {
                return Err(Error::Protocol("FILE_BEGIN went unanswered".into()));
            }
        }
        report_progress(progress, 0, total).await;

        let mut offset = 0usize;
        while offset < total {
            let end = std::cmp::min(offset + chunk_size, total);
            let payload = pack_data(&FileData {
                offset: offset as u32,
                data: data[offset..end].to_vec(),
            });
            match self.file_step(MSG_FILE_DATA, &payload).await? {
                FileStep::Acked => {}
                FileStep::SessionLost => return Ok(None),
                FileStep::Unresolved => {
                    return Err(Error::Protocol("FILE_DATA went unanswered".into()));
                }
            }
            offset = end;
            report_progress(progress, offset, total).await;
        }

        match self
            .file_step(MSG_FILE_END, &pack_end(FileAction::Commit))
            .await?
        {
            FileStep::Acked => Ok(Some(FileUploadOutcome::Committed)),
            FileStep::Unresolved => Ok(Some(FileUploadOutcome::Unknown)),
            FileStep::SessionLost => Ok(None),
        }
    }

    async fn file_step(&self, msg_type: u8, payload: &[u8]) -> Result<FileStep, Error> {
        use wslib_framelink_protocol::types::{
            ERR_INVALID_STATE, ERR_WRITE_LOCKED, MSG_FILE_BEGIN, MSG_FILE_END,
        };

        let answer = match self
            .exchange(
                msg_type,
                FLAG_ACK_REQ,
                payload,
                Expect::AckOrNack,
                FILE_STEP_RESENDS,
            )
            .await
        {
            Ok(answer) => answer,
            Err(e @ (Error::Protocol(_) | Error::WriteLocked(_))) => return Err(e),
            Err(_) => return Ok(FileStep::Unresolved),
        };
        if answer.frame.msg_type == MSG_ACK {
            return Ok(FileStep::Acked);
        }
        let code = types::nack_code(&answer.frame.payload);
        if msg_type == MSG_FILE_END && answer.resent && code == ERR_INVALID_STATE {
            return Ok(FileStep::Unresolved);
        }
        let session_gone =
            code == ERR_WRITE_LOCKED || (code == ERR_INVALID_STATE && msg_type != MSG_FILE_BEGIN);
        if session_gone {
            return Ok(FileStep::SessionLost);
        }
        Err(Error::Nack {
            request: msg_type,
            code,
        })
    }

    pub async fn collect_active_rule_ids(&self) -> Result<ActiveRuleIds, Error> {
        use std::collections::HashSet;

        let frame_defs: HashSet<u16> = self
            .list_frame_defs()
            .await?
            .iter()
            .map(|fd| fd.frame_def_id)
            .collect();

        let generators: HashSet<u16> = self
            .list_generators()
            .await?
            .iter()
            .map(|g| g.generator_id)
            .collect();

        let transformers: HashSet<u16> = self
            .list_transformers()
            .await?
            .iter()
            .map(|x| x.transformer_id)
            .collect();

        Ok(ActiveRuleIds {
            frame_defs,
            generators,
            transformers,
        })
    }
}

async fn session_task(
    sender: FrameSender,
    mut response_rx: mpsc::Receiver<Frame>,
    mut cmd_rx: mpsc::Receiver<SessionCommand>,
    command_timeout: Duration,
    stream_tx: StreamSink,
) {
    loop {
        tokio::select! {
            // Commands first, or a gapless stream would starve them.
            biased;

            cmd = cmd_rx.recv() => {
                match cmd {
                    Some(c) => {
                        handle_command(
                            &sender, &mut response_rx, command_timeout, c, &stream_tx,
                        ).await;
                    }
                    None => return,
                }
            }

            // FRAME_RX between commands would otherwise wait for the next one.
            frame = response_rx.recv() => match frame {
                Some(frame) => forward_frame_rx(&frame, &stream_tx),
                None => return,
            }
        }
    }
}

async fn report_progress(
    progress: Option<&mpsc::Sender<FileProgress>>,
    bytes_done: usize,
    total_bytes: usize,
) {
    if let Some(tx) = progress {
        let _ = tx
            .send(FileProgress {
                bytes_done,
                total_bytes,
            })
            .await;
    }
}

async fn handle_command(
    sender: &FrameSender,
    response_rx: &mut mpsc::Receiver<Frame>,
    command_timeout: Duration,
    cmd: SessionCommand,
    stream_tx: &StreamSink,
) {
    drain_stale(response_rx, stream_tx);
    match cmd {
        SessionCommand::Request {
            msg_type,
            flags,
            payload,
            expect,
            resends,
            result_tx,
        } => {
            let outgoing = Outgoing {
                msg_type,
                flags,
                payload: &payload,
                expect,
                resends,
            };
            let result =
                send_request(sender, response_rx, stream_tx, command_timeout, &outgoing).await;
            drain_stale(response_rx, stream_tx);
            let _ = result_tx.send(result);
        }
        SessionCommand::RequestMulti {
            msg_type,
            flags,
            payload,
            result_tx,
        } => {
            let result = collect_multi(
                sender,
                response_rx,
                stream_tx,
                command_timeout,
                msg_type,
                flags,
                &payload,
            )
            .await;
            drain_stale(response_rx, stream_tx);
            let _ = result_tx.send(result);
        }
        SessionCommand::SendBatch {
            messages,
            result_tx,
        } => {
            let result =
                do_send_batch(sender, response_rx, stream_tx, command_timeout, &messages).await;
            drain_stale(response_rx, stream_tx);
            let _ = result_tx.send(result);
        }
        SessionCommand::TransmitStream {
            entries,
            queue_depth,
            result_tx,
        } => {
            let result = transmit_pipeline(
                sender,
                response_rx,
                stream_tx,
                command_timeout,
                &entries,
                queue_depth,
            )
            .await;
            drain_stale(response_rx, stream_tx);
            let _ = result_tx.send(result);
        }
    }
}

/// The next frame that is not FRAME_RX; FRAME_RX is forwarded, or dropped
/// when the stream channel is full.
async fn recv_response(
    response_rx: &mut mpsc::Receiver<Frame>,
    stream_tx: &StreamSink,
    deadline: tokio::time::Instant,
    command_timeout: Duration,
) -> Result<Frame, Error> {
    loop {
        let frame = match tokio::time::timeout_at(deadline, response_rx.recv()).await {
            Ok(Some(f)) => f,
            Ok(None) => return Err(Error::ConnectionClosed),
            Err(_) => return Err(Error::Timeout(command_timeout)),
        };
        if frame.msg_type == MSG_FRAME_RX {
            forward_frame_rx(&frame, stream_tx);
            continue;
        }
        return Ok(frame);
    }
}

/// Where FRAME_RX goes. A frame finding the channel full is dropped and
/// counted: the link is never held up for a slow reader.
struct StreamSink {
    tx: mpsc::Sender<StreamFrame>,
    counters: Arc<FramingCounters>,
}

fn forward_frame_rx(frame: &Frame, stream_tx: &StreamSink) {
    if frame.msg_type == MSG_FRAME_RX
        && let Ok(frames) = parse_frame_rx(&frame.payload)
    {
        for sf in frames {
            if stream_tx.tx.try_send(sf).is_err() {
                stream_tx.counters.stream_dropped();
            }
        }
    }
}

fn drain_stale(response_rx: &mut mpsc::Receiver<Frame>, stream_tx: &StreamSink) {
    while let Ok(frame) = response_rx.try_recv() {
        forward_frame_rx(&frame, stream_tx);
    }
}

async fn send_request(
    sender: &FrameSender,
    response_rx: &mut mpsc::Receiver<Frame>,
    stream_tx: &StreamSink,
    command_timeout: Duration,
    outgoing: &Outgoing<'_>,
) -> Result<Answer, Error> {
    let answer = transact(sender, response_rx, stream_tx, command_timeout, outgoing).await?;
    if !is_write_locked(&answer.frame) {
        return Ok(answer);
    }
    unlock_after_refusal(sender, response_rx, stream_tx, command_timeout).await?;
    transact(sender, response_rx, stream_tx, command_timeout, outgoing).await
}

async fn transact(
    sender: &FrameSender,
    response_rx: &mut mpsc::Receiver<Frame>,
    stream_tx: &StreamSink,
    command_timeout: Duration,
    outgoing: &Outgoing<'_>,
) -> Result<Answer, Error> {
    let (seq, wire) = sender.frame(outgoing.msg_type, outgoing.flags, outgoing.payload);
    let mut resends = 0;
    loop {
        sender.write(wire.clone()).await?;
        match recv_answer(
            response_rx,
            stream_tx,
            command_timeout,
            seq,
            outgoing.expect,
        )
        .await
        {
            Err(Error::Timeout(_)) if resends < outgoing.resends => resends += 1,
            result => {
                return result.map(|frame| Answer {
                    frame,
                    resent: resends > 0,
                });
            }
        }
    }
}

async fn recv_answer(
    response_rx: &mut mpsc::Receiver<Frame>,
    stream_tx: &StreamSink,
    command_timeout: Duration,
    seq: u8,
    expect: Expect,
) -> Result<Frame, Error> {
    let deadline = tokio::time::Instant::now() + command_timeout;
    loop {
        let frame = recv_response(response_rx, stream_tx, deadline, command_timeout).await?;
        if answers(&frame, seq, expect) {
            return Ok(frame);
        }
    }
}

fn answers(frame: &Frame, seq: u8, expect: Expect) -> bool {
    let is_reply = frame.flags & types::FLAG_RESPONSE != 0 && frame.seq == seq;
    match (frame.msg_type, expect) {
        (MSG_NACK, _) => is_reply,
        (MSG_ACK, Expect::Reply(_)) => false,
        (MSG_ACK, _) => is_reply,
        (_, Expect::AckOrNack) => false,
        (msg_type, Expect::Reply(wanted)) => is_reply && msg_type == wanted,
        (_, Expect::Any) => is_reply,
    }
}

pub(crate) fn expect_reply(request: u8, expected: u8, reply: Frame) -> Result<Frame, Error> {
    match reply.msg_type {
        msg_type if msg_type == expected => Ok(reply),
        MSG_NACK => Err(Error::Nack {
            request,
            code: types::nack_code(&reply.payload),
        }),
        msg_type => Err(Error::UnexpectedReply {
            request,
            reply: msg_type,
        }),
    }
}

fn is_write_locked(frame: &Frame) -> bool {
    use wslib_framelink_protocol::types::ERR_WRITE_LOCKED;

    frame.msg_type == MSG_NACK && types::nack_code(&frame.payload) == ERR_WRITE_LOCKED
}

async fn unlock_after_refusal(
    sender: &FrameSender,
    response_rx: &mut mpsc::Receiver<Frame>,
    stream_tx: &StreamSink,
    command_timeout: Duration,
) -> Result<(), Error> {
    unlock_writes(sender, response_rx, stream_tx, command_timeout)
        .await
        .map_err(|e| match e {
            Error::WriteLocked(_) => e,
            other => Error::WriteLocked(format!("unlock after WRITE_LOCKED failed: {other}")),
        })
}

async fn unlock_writes(
    sender: &FrameSender,
    response_rx: &mut mpsc::Receiver<Frame>,
    stream_tx: &StreamSink,
    command_timeout: Duration,
) -> Result<(), Error> {
    use wslib_framelink_protocol::types::{ERR_WRITE_LOCKED, error_name};

    let stale = || {
        Error::WriteLocked(format!(
            "unlock failed: {} after {UNLOCK_ATTEMPTS} attempts",
            error_name(ERR_WRITE_LOCKED),
        ))
    };
    let mut last_failure = stale();
    for _ in 0..UNLOCK_ATTEMPTS {
        last_failure = match try_unlock(sender, response_rx, stream_tx, command_timeout).await {
            Ok(UnlockAttempt::Unlocked) => return Ok(()),
            Ok(UnlockAttempt::NonceStale) => stale(),
            Ok(UnlockAttempt::Refused(code)) => {
                return Err(Error::WriteLocked(format!(
                    "unlock failed: {}",
                    error_name(code),
                )));
            }
            Err(e @ Error::Timeout(_)) => e,
            Err(e) => return Err(e),
        };
    }
    Err(last_failure)
}

async fn try_unlock(
    sender: &FrameSender,
    response_rx: &mut mpsc::Receiver<Frame>,
    stream_tx: &StreamSink,
    command_timeout: Duration,
) -> Result<UnlockAttempt, Error> {
    use wslib_framelink_protocol::dsig;
    use wslib_framelink_protocol::types::{
        ERR_WRITE_LOCKED, MSG_WRITE_CHALLENGE, MSG_WRITE_CHALLENGE_RESP, MSG_WRITE_UNLOCK,
    };

    let challenge = transact(
        sender,
        response_rx,
        stream_tx,
        command_timeout,
        &Outgoing {
            msg_type: MSG_WRITE_CHALLENGE,
            flags: FLAG_ACK_REQ,
            payload: &[],
            expect: Expect::Reply(MSG_WRITE_CHALLENGE_RESP),
            resends: 0,
        },
    )
    .await?
    .frame;
    if challenge.msg_type == MSG_NACK {
        return Ok(UnlockAttempt::Refused(types::nack_code(&challenge.payload)));
    }
    let nonce = dsig::parse_challenge_response(&challenge.payload)
        .map_err(|e| Error::Protocol(format!("challenge parse failed: {e}")))?;

    let verdict = transact(
        sender,
        response_rx,
        stream_tx,
        command_timeout,
        &Outgoing {
            msg_type: MSG_WRITE_UNLOCK,
            flags: FLAG_ACK_REQ,
            payload: &dsig::build_unlock_request(nonce),
            expect: Expect::AckOrNack,
            resends: 0,
        },
    )
    .await?
    .frame;
    if verdict.msg_type == MSG_ACK {
        return Ok(UnlockAttempt::Unlocked);
    }
    match types::nack_code(&verdict.payload) {
        ERR_WRITE_LOCKED => Ok(UnlockAttempt::NonceStale),
        code => Ok(UnlockAttempt::Refused(code)),
    }
}

async fn collect_multi(
    sender: &FrameSender,
    response_rx: &mut mpsc::Receiver<Frame>,
    stream_tx: &StreamSink,
    command_timeout: Duration,
    msg_type: u8,
    flags: u8,
    payload: &[u8],
) -> Result<Vec<Frame>, Error> {
    let seq = sender.send(msg_type, flags, payload).await?;
    let mut frames = Vec::new();
    let mut deadline = tokio::time::Instant::now() + command_timeout;
    loop {
        let frame = recv_response(response_rx, stream_tx, deadline, command_timeout).await?;
        if !answers(&frame, seq, Expect::Any) {
            continue;
        }
        deadline = tokio::time::Instant::now() + command_timeout;
        if frame.msg_type == MSG_ACK {
            return Ok(frames);
        }
        if frame.msg_type == MSG_NACK {
            return Err(Error::Nack {
                request: msg_type,
                code: types::nack_code(&frame.payload),
            });
        }
        frames.push(frame);
    }
}

async fn do_send_batch(
    sender: &FrameSender,
    response_rx: &mut mpsc::Receiver<Frame>,
    stream_tx: &StreamSink,
    command_timeout: Duration,
    messages: &[(u8, u8, Vec<u8>)],
) -> Result<Vec<Frame>, Error> {
    let mut responses =
        send_and_collect(sender, response_rx, stream_tx, command_timeout, messages).await?;

    let locked_out: Vec<usize> = responses
        .iter()
        .enumerate()
        .filter(|(_, frame)| is_write_locked(frame))
        .map(|(i, _)| i)
        .collect();
    if locked_out.is_empty() {
        return Ok(responses);
    }

    unlock_after_refusal(sender, response_rx, stream_tx, command_timeout).await?;

    let retry: Vec<(u8, u8, Vec<u8>)> = locked_out.iter().map(|&i| messages[i].clone()).collect();
    let retried = send_and_collect(sender, response_rx, stream_tx, command_timeout, &retry).await?;
    for (&index, frame) in locked_out.iter().zip(retried) {
        responses[index] = frame;
    }
    Ok(responses)
}

async fn send_and_collect(
    sender: &FrameSender,
    response_rx: &mut mpsc::Receiver<Frame>,
    stream_tx: &StreamSink,
    command_timeout: Duration,
    messages: &[(u8, u8, Vec<u8>)],
) -> Result<Vec<Frame>, Error> {
    if messages.len() > MAX_BATCH_MESSAGES {
        return Err(Error::Protocol(format!(
            "batch of {} messages exceeds the {MAX_BATCH_MESSAGES} that fit one sequence space with their unlock attempts and retry",
            messages.len()
        )));
    }
    let mut seqs = Vec::with_capacity(messages.len());
    for (msg_type, flags, payload) in messages {
        seqs.push(sender.send(*msg_type, *flags, payload).await?);
    }
    let mut replies: std::collections::HashMap<u8, Frame> =
        std::collections::HashMap::with_capacity(seqs.len());
    let mut deadline = tokio::time::Instant::now() + command_timeout;
    while replies.len() < seqs.len() {
        let frame = recv_response(response_rx, stream_tx, deadline, command_timeout).await?;
        let is_reply = frame.flags & types::FLAG_RESPONSE != 0;
        if is_reply && seqs.contains(&frame.seq) && !replies.contains_key(&frame.seq) {
            replies.insert(frame.seq, frame);
            deadline = tokio::time::Instant::now() + command_timeout;
        }
    }
    Ok(seqs
        .iter()
        .map(|seq| {
            replies
                .remove(seq)
                .expect("the loop ends only once every outstanding seq has a reply")
        })
        .collect())
}

const UNLOCK_EXCHANGE_MESSAGES: usize = 2;

const MAX_BATCH_MESSAGES: usize =
    (u8::MAX as usize + 1 - UNLOCK_ATTEMPTS * UNLOCK_EXCHANGE_MESSAGES) / 2;

const MAX_BATCH_PAYLOAD: usize = 1432;
const BATCH_HEADER_SIZE: usize = 2;
const MAX_ENTRY_OVERHEAD: usize = 10;

async fn transmit_pipeline(
    sender: &FrameSender,
    response_rx: &mut mpsc::Receiver<Frame>,
    stream_tx: &StreamSink,
    _command_timeout: Duration,
    entries: &[stream::BatchFrameEntry],
    queue_depth: usize,
) -> Result<TransmitStats, Error> {
    if entries.is_empty() {
        return Ok(TransmitStats {
            sent: 0,
            acked: 0,
            nacked: 0,
        });
    }

    let batch_cap = {
        let entry_size = MAX_ENTRY_OVERHEAD + entries[0].data.len();
        let max_by_payload = ((MAX_BATCH_PAYLOAD - BATCH_HEADER_SIZE) / entry_size).max(1);
        queue_depth.min(max_by_payload)
    };

    let mut pos: usize = 0;

    while pos < entries.len() {
        let batch_size = batch_cap.min(entries.len() - pos);
        let batch = &entries[pos..pos + batch_size];
        let payload = stream::build_frame_tx_batch(batch);
        sender.send(MSG_FRAME_TX_BATCH, FLAG_NONE, &payload).await?;
        pos += batch_size;

        while let Ok(frame) = response_rx.try_recv() {
            forward_frame_rx(&frame, stream_tx);
        }
    }

    let sent = entries.len();
    Ok(TransmitStats {
        sent,
        acked: sent,
        nacked: 0,
    })
}
