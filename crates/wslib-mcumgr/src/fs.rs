use std::collections::BTreeMap;
use std::sync::Arc;

use futures_core::Stream;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::mpsc;

use crate::frame::{self, Bytes, BytesRef, Empty, decode_reply};
use crate::header::Op;
use crate::session::{
    CHUNK_TIMEOUT, Events, FIRST_CHUNK_TIMEOUT, MIN_CHUNK_SIZE, PROGRESS_CHANNEL_DEPTH,
};
use crate::{Error, Group, Session};

const CMD_FILE: u8 = 0;
const CMD_STATUS: u8 = 1;
const CMD_HASH: u8 = 2;
const CMD_SUPPORTED_HASHES: u8 = 3;

/// A device built with `CONFIG_MCUMGR_GRP_FS_MAX_FILE_SIZE_64KB` cannot
/// address past this offset.
const SMALL_OFFSET_LIMIT: usize = 64 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct FsProgress {
    pub bytes_done: usize,
    pub total_bytes: usize,
}

impl FsProgress {
    pub fn percent(&self) -> f32 {
        if self.total_bytes == 0 {
            100.0
        } else {
            self.bytes_done as f32 / self.total_bytes as f32 * 100.0
        }
    }

    pub fn is_complete(&self) -> bool {
        self.bytes_done >= self.total_bytes
    }
}

/// How [`Session::fs_verify`] checked a file.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum FsVerification {
    Sha256,
    Crc32,
    /// The device could hash neither way, so the file was read back.
    Downloaded,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum FsHashAlgorithm {
    Sha256,
    Crc32,
}

impl FsHashAlgorithm {
    fn wire_name(self) -> &'static str {
        match self {
            Self::Sha256 => "sha256",
            Self::Crc32 => "crc32",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct FsHash {
    pub algorithm: FsHashAlgorithm,
    /// A CRC-32 is big-endian here; compare with `to_be_bytes()`.
    pub value: Vec<u8>,
}

#[derive(Serialize)]
struct NameRequest<'a> {
    name: &'a str,
}

#[derive(Serialize)]
struct HashRequest<'a> {
    name: &'a str,
    r#type: &'a str,
}

/// A checksum comes back as a number, a hash as a byte string.
#[derive(Deserialize)]
struct HashReply {
    output: ciborium::Value,
}

#[derive(Deserialize)]
struct SupportedHashes {
    types: BTreeMap<String, ciborium::Value>,
}

#[derive(Serialize)]
struct WriteRequest<'a> {
    off: usize,
    data: BytesRef<'a>,
    name: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    len: Option<usize>,
}

#[derive(Serialize)]
struct ReadRequest<'a> {
    off: usize,
    name: &'a str,
}

#[derive(Deserialize)]
struct Offset {
    off: usize,
}

/// `len` comes with the first chunk only.
#[derive(Deserialize)]
struct ReadReply {
    off: usize,
    data: Bytes,
    #[serde(default)]
    len: Option<usize>,
}

#[derive(Deserialize)]
struct StatusReply {
    len: u64,
}

fn context_at(operation: &str, offset: usize) -> String {
    let mut context = format!("fs {operation} at offset {offset}");
    if offset >= SMALL_OFFSET_LIMIT {
        context.push_str(&format!(
            " (past {SMALL_OFFSET_LIMIT} bytes, which a device built with \
             CONFIG_MCUMGR_GRP_FS_MAX_FILE_SIZE_64KB cannot address; it needs \
             CONFIG_MCUMGR_GRP_FS_MAX_FILE_SIZE_4GB)"
        ));
    }
    context
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

impl Session {
    /// Writes `data` to `remote_path`, one event per acknowledged chunk.
    /// Completion means acknowledged, not correct: follow with
    /// [`fs_verify`](Self::fs_verify). Dropping the stream cancels it.
    ///
    /// Must be called within a tokio runtime: the upload runs as a task.
    pub fn fs_upload(
        &self,
        data: Arc<[u8]>,
        remote_path: String,
    ) -> impl Stream<Item = Result<FsProgress, Error>> + Send + Unpin + 'static {
        let router = self.router();
        let budget = self.fs_chunk_budget(&remote_path);
        let (events, rx) = mpsc::channel(PROGRESS_CHANNEL_DEPTH);
        let run = {
            let events = events.clone();
            async move {
                let budget = budget?;
                let total = data.len();
                let mut replies = router.replies();
                let mut offset = 0;
                loop {
                    let request = WriteRequest {
                        off: offset,
                        data: BytesRef(&data[offset..(offset + budget).min(total)]),
                        name: &remote_path,
                        len: (offset == 0).then_some(total),
                    };
                    let seq = replies.expect()?;
                    router
                        .send(frame::encode(
                            Op::Write,
                            Group::Fs,
                            CMD_FILE,
                            seq,
                            &request,
                        )?)
                        .await?;
                    let timeout = if offset == 0 {
                        FIRST_CHUNK_TIMEOUT
                    } else {
                        CHUNK_TIMEOUT
                    };
                    let reply = tokio::select! {
                        reply = tokio::time::timeout(timeout, replies.next()) => reply,
                        () = events.closed() => return Ok(()),
                    };
                    let reply = reply.map_err(|_| Error::UploadStalled { offset, total })??;
                    let ack: Offset = decode_reply(&reply, &context_at("upload", offset))?;
                    if ack.off <= offset && total > 0 {
                        return Err(Error::FsNoProgress { offset });
                    }
                    if ack.off > total {
                        return Err(Error::UnexpectedReply(format!(
                            "fs upload: the device reports offset {}, past the {total}-byte file",
                            ack.off
                        )));
                    }
                    offset = ack.off;
                    let progress = FsProgress {
                        bytes_done: offset,
                        total_bytes: total,
                    };
                    if events.send(Ok(progress)).await.is_err() || offset >= total {
                        return Ok(());
                    }
                }
            }
        };
        tokio::spawn(async move {
            if let Err(e) = run.await {
                let _ = events.send(Err(e)).await;
            }
        });
        Events(rx)
    }

    /// Reads `remote_path` whole, sending progress to `progress` per chunk.
    pub async fn fs_download(
        &self,
        remote_path: &str,
        progress: Option<mpsc::Sender<FsProgress>>,
    ) -> Result<Vec<u8>, Error> {
        let mut contents = Vec::new();
        let mut total = None;
        loop {
            let request = ReadRequest {
                off: contents.len(),
                name: remote_path,
            };
            let reply: ReadReply = self
                .request(
                    Op::Read,
                    Group::Fs,
                    CMD_FILE,
                    &request,
                    &context_at("download", contents.len()),
                )
                .await?;
            if reply.off != contents.len() {
                return Err(Error::UnexpectedReply(format!(
                    "fs download: asked for offset {}, the device answered from {}",
                    contents.len(),
                    reply.off
                )));
            }
            total = reply.len.or(total);
            let file_len = total.ok_or_else(|| {
                Error::UnexpectedReply("fs download: the device never gave the file length".into())
            })?;
            if reply.data.0.is_empty() && contents.len() < file_len {
                return Err(Error::FsNoProgress {
                    offset: contents.len(),
                });
            }
            contents.extend_from_slice(&reply.data.0);
            if contents.len() > file_len {
                return Err(Error::UnexpectedReply(format!(
                    "fs download: the device sent {} bytes of a {file_len}-byte file",
                    contents.len()
                )));
            }
            if let Some(tx) = &progress {
                let _ = tx
                    .send(FsProgress {
                        bytes_done: contents.len(),
                        total_bytes: file_len,
                    })
                    .await;
            }
            if contents.len() == file_len {
                return Ok(contents);
            }
        }
    }

    /// Checks `remote_path` against `local`: its length, then the best hash
    /// the device offers, else every byte read back.
    pub async fn fs_verify(
        &self,
        remote_path: &str,
        local: &[u8],
    ) -> Result<FsVerification, Error> {
        let mismatch = |expected: String, found: String| Error::FsVerifyMismatch {
            path: remote_path.to_owned(),
            expected,
            found,
        };
        let device_len = self.fs_status(remote_path).await?;
        if device_len != local.len() as u64 {
            return Err(mismatch(
                format!("{} bytes", local.len()),
                format!("{device_len} bytes"),
            ));
        }
        let Some(algorithm) = self.fs_preferred_hash().await else {
            let device = self.fs_download(remote_path, None).await?;
            if let Some(at) = device.iter().zip(local).position(|(a, b)| a != b) {
                return Err(mismatch(
                    format!("byte {:#04x} at offset {at}", local[at]),
                    format!("byte {:#04x}", device[at]),
                ));
            }
            return Ok(FsVerification::Downloaded);
        };
        let (expected, verification) = match algorithm {
            FsHashAlgorithm::Sha256 => (Sha256::digest(local).to_vec(), FsVerification::Sha256),
            FsHashAlgorithm::Crc32 => (
                wslib_checksum::crc32(local).to_be_bytes().to_vec(),
                FsVerification::Crc32,
            ),
        };
        let found = self.fs_hash(remote_path, algorithm).await?.value;
        if found != expected {
            return Err(mismatch(hex(&expected), hex(&found)));
        }
        Ok(verification)
    }

    async fn fs_preferred_hash(&self) -> Option<FsHashAlgorithm> {
        let supported: SupportedHashes = self
            .request(
                Op::Read,
                Group::Fs,
                CMD_SUPPORTED_HASHES,
                &Empty {},
                "fs supported hashes",
            )
            .await
            .ok()?;
        [FsHashAlgorithm::Sha256, FsHashAlgorithm::Crc32]
            .into_iter()
            .find(|a| supported.types.contains_key(a.wire_name()))
    }

    pub async fn fs_hash(
        &self,
        remote_path: &str,
        algorithm: FsHashAlgorithm,
    ) -> Result<FsHash, Error> {
        let request = HashRequest {
            name: remote_path,
            r#type: algorithm.wire_name(),
        };
        let reply: HashReply = self
            .request(Op::Read, Group::Fs, CMD_HASH, &request, "fs hash")
            .await?;
        let value = match reply.output {
            ciborium::Value::Bytes(bytes) => bytes,
            ciborium::Value::Integer(n) => u32::try_from(n)
                .map_err(|_| Error::Decode("fs hash: a checksum wider than 32 bits".into()))?
                .to_be_bytes()
                .to_vec(),
            other => return Err(Error::Decode(format!("fs hash: output {other:?}"))),
        };
        Ok(FsHash { algorithm, value })
    }

    pub async fn fs_status(&self, remote_path: &str) -> Result<u64, Error> {
        let reply: StatusReply = self
            .request(
                Op::Read,
                Group::Fs,
                CMD_STATUS,
                &NameRequest { name: remote_path },
                "fs status",
            )
            .await?;
        Ok(reply.len)
    }

    /// The path rides in every request, so it comes out of the data's room.
    fn fs_chunk_budget(&self, remote_path: &str) -> Result<usize, Error> {
        let budget = self.chunk_budget();
        match budget.checked_sub(remote_path.len()) {
            Some(room) if room >= MIN_CHUNK_SIZE => Ok(room),
            _ => Err(Error::FsPathTooLong {
                path_len: remote_path.len(),
                limit: budget.saturating_sub(MIN_CHUNK_SIZE),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::BoxFuture;
    use crate::Transport;
    use crate::header::HEADER_LEN;
    use crate::session::{FRAME_OVERHEAD, next};
    use std::collections::{HashMap, VecDeque};
    use std::sync::Mutex;
    use std::time::Duration;
    use tokio::sync::Notify;

    const TEST_CHUNK_BUDGET: usize = 512;
    const TEST_DEVICE_BUF_SIZE: usize = TEST_CHUNK_BUDGET + FRAME_OVERHEAD;
    const FS_GROUP: u16 = 8;
    const FS_ERR_FILE_NOT_FOUND: i32 = 3;
    const RC_SEEK_FAILED: i32 = 6;
    const RC_NO_ENTRY: i32 = 5;
    const RC_INVALID: i32 = 3;
    const RC_NOT_SUPPORTED: i32 = 8;
    const READ_CHUNK: usize = 400;
    const STALE_SEQ: u8 = 0xEE;
    const STALE_SEQ_OFFSET: u8 = 0x80;
    const SETTLE: Duration = Duration::from_millis(100);

    // The spec's file upload request, hand-encoded per RFC 8949.
    #[test]
    fn a_first_file_write_carries_off_data_name_and_len() {
        let request = WriteRequest {
            off: 0,
            data: BytesRef(&[0xaa]),
            name: "/a",
            len: Some(1),
        };
        let mut out = Vec::new();
        ciborium::into_writer(&request, &mut out).unwrap();
        let mut want = vec![0xa4, 0x63, b'o', b'f', b'f', 0x00];
        want.extend_from_slice(&[0x64, b'd', b'a', b't', b'a', 0x41, 0xaa]);
        want.extend_from_slice(&[0x64, b'n', b'a', b'm', b'e', 0x62, b'/', b'a']);
        want.extend_from_slice(&[0x63, b'l', b'e', b'n', 0x01]);
        assert_eq!(out, want);
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum HashSupport {
        Sha256AndCrc32,
        Crc32Only,
        None,
    }

    #[derive(Deserialize)]
    struct AnyRequest {
        #[serde(default)]
        name: Option<String>,
        #[serde(default)]
        off: Option<usize>,
        #[serde(default)]
        data: Option<Bytes>,
        #[serde(default)]
        len: Option<usize>,
        #[serde(default, rename = "type")]
        hash_type: Option<String>,
    }

    #[derive(Serialize)]
    struct LenReply {
        len: u64,
    }

    #[derive(Serialize)]
    struct OffReply {
        off: usize,
    }

    #[derive(Serialize)]
    struct DataReply {
        off: usize,
        data: Bytes,
        #[serde(skip_serializing_if = "Option::is_none")]
        len: Option<usize>,
    }

    #[derive(Serialize)]
    struct RcReply {
        rc: i32,
    }

    #[derive(Serialize)]
    struct GroupErrorReply {
        err: GroupError,
    }

    #[derive(Serialize)]
    struct GroupError {
        group: u16,
        rc: i32,
    }

    #[derive(Serialize)]
    struct HashTypeInfo {
        format: u8,
        size: u8,
    }

    #[derive(Serialize)]
    struct SupportedReply {
        types: HashMap<String, HashTypeInfo>,
    }

    #[derive(Serialize)]
    #[serde(untagged)]
    enum HashOutput {
        Number(u64),
        Bytes(Bytes),
    }

    #[derive(Serialize)]
    struct HashReplyOut {
        r#type: String,
        off: u64,
        len: u64,
        output: HashOutput,
    }

    struct FakeFsDevice {
        files: Mutex<HashMap<String, Vec<u8>>>,
        responses: Mutex<VecDeque<Vec<u8>>>,
        hash_support: HashSupport,
        accept_per_write: usize,
        offset_cap: Option<usize>,
        largest_request: Mutex<usize>,
        v2_errors: bool,
        silent_writes: bool,
        stale_before_each_write_reply: bool,
        wake: Notify,
    }

    impl FakeFsDevice {
        fn build(
            accept_per_write: usize,
            hash_support: HashSupport,
            offset_cap: Option<usize>,
        ) -> Self {
            Self {
                files: Mutex::default(),
                responses: Mutex::default(),
                hash_support,
                accept_per_write,
                offset_cap,
                largest_request: Mutex::new(0),
                v2_errors: false,
                silent_writes: false,
                stale_before_each_write_reply: false,
                wake: Notify::new(),
            }
        }

        fn new() -> Arc<Self> {
            Self::accepting(usize::MAX)
        }

        fn accepting(accept_per_write: usize) -> Arc<Self> {
            Arc::new(Self::build(
                accept_per_write,
                HashSupport::Sha256AndCrc32,
                None,
            ))
        }

        fn with_hashes(hash_support: HashSupport) -> Arc<Self> {
            Arc::new(Self::build(usize::MAX, hash_support, None))
        }

        fn with_offset_cap(cap: usize) -> Arc<Self> {
            Arc::new(Self::build(
                usize::MAX,
                HashSupport::Sha256AndCrc32,
                Some(cap),
            ))
        }

        fn with_v2_errors() -> Arc<Self> {
            Arc::new(Self {
                v2_errors: true,
                ..Self::build(usize::MAX, HashSupport::Sha256AndCrc32, None)
            })
        }

        fn with_silent_writes() -> Arc<Self> {
            Arc::new(Self {
                silent_writes: true,
                ..Self::build(usize::MAX, HashSupport::Sha256AndCrc32, None)
            })
        }

        fn with_a_stale_reply_before_each_write_reply() -> Arc<Self> {
            Arc::new(Self {
                stale_before_each_write_reply: true,
                ..Self::build(usize::MAX, HashSupport::Sha256AndCrc32, None)
            })
        }

        fn push(&self, frame: Vec<u8>) {
            self.responses.lock().unwrap().push_back(frame);
            self.wake.notify_one();
        }

        fn put(&self, path: &str, contents: Vec<u8>) {
            self.files.lock().unwrap().insert(path.to_owned(), contents);
        }

        fn contents(&self, path: &str) -> Vec<u8> {
            self.files
                .lock()
                .unwrap()
                .get(path)
                .cloned()
                .unwrap_or_default()
        }

        fn reply<T: Serialize>(&self, op: Op, seq: u8, command: u8, payload: T) {
            self.push(frame::encode(op, Group::Fs, command, seq, &payload).unwrap());
        }

        fn handle_supported_hashes(&self, seq: u8) {
            let mut types = HashMap::new();
            let crc = HashTypeInfo { format: 0, size: 4 };
            match self.hash_support {
                HashSupport::Sha256AndCrc32 => {
                    types.insert("crc32".to_owned(), crc);
                    types.insert(
                        "sha256".to_owned(),
                        HashTypeInfo {
                            format: 1,
                            size: 32,
                        },
                    );
                }
                HashSupport::Crc32Only => {
                    types.insert("crc32".to_owned(), crc);
                }
                HashSupport::None => {
                    let rc = RcReply {
                        rc: RC_NOT_SUPPORTED,
                    };
                    return self.reply(Op::ReadResponse, seq, CMD_SUPPORTED_HASHES, rc);
                }
            }
            self.reply(
                Op::ReadResponse,
                seq,
                CMD_SUPPORTED_HASHES,
                SupportedReply { types },
            );
        }

        fn handle_hash(&self, seq: u8, request: AnyRequest) {
            if self.hash_support == HashSupport::None {
                let rc = RcReply {
                    rc: RC_NOT_SUPPORTED,
                };
                return self.reply(Op::ReadResponse, seq, CMD_HASH, rc);
            }
            let name = request.name.expect("hash request without a name");
            let algo = request.hash_type.expect("hash request without a type");
            let Some(file) = self.files.lock().unwrap().get(&name).cloned() else {
                return self.reply(Op::ReadResponse, seq, CMD_HASH, RcReply { rc: RC_NO_ENTRY });
            };
            let output = match algo.as_str() {
                "sha256" => {
                    assert_eq!(self.hash_support, HashSupport::Sha256AndCrc32);
                    HashOutput::Bytes(Bytes(Sha256::digest(&file).to_vec()))
                }
                "crc32" => HashOutput::Number(u64::from(wslib_checksum::crc32(&file))),
                other => panic!("fake device: unknown hash type {other}"),
            };
            let reply = HashReplyOut {
                r#type: algo,
                off: 0,
                len: file.len() as u64,
                output,
            };
            self.reply(Op::ReadResponse, seq, CMD_HASH, reply);
        }

        fn handle_read(&self, seq: u8, request: AnyRequest) {
            let name = request.name.expect("read request without a name");
            let off = request.off.expect("read request without an offset");
            if self.offset_cap.is_some_and(|cap| off >= cap) {
                return self.reply(Op::ReadResponse, seq, CMD_FILE, RcReply { rc: RC_INVALID });
            }
            let Some(file) = self.files.lock().unwrap().get(&name).cloned() else {
                return self.reply(Op::ReadResponse, seq, CMD_FILE, RcReply { rc: RC_NO_ENTRY });
            };
            let end = (off + READ_CHUNK).min(file.len());
            let reply = DataReply {
                off,
                data: Bytes(file[off..end].to_vec()),
                len: (off == 0).then_some(file.len()),
            };
            self.reply(Op::ReadResponse, seq, CMD_FILE, reply);
        }

        fn handle_write(&self, seq: u8, request: AnyRequest) {
            if self.silent_writes {
                return;
            }
            if self.stale_before_each_write_reply {
                let stale = seq.wrapping_add(STALE_SEQ_OFFSET);
                self.reply(Op::WriteResponse, stale, CMD_FILE, OffReply { off: 1 });
            }
            let name = request.name.expect("write request without a name");
            let off = request.off.expect("write request without an offset");
            if self.offset_cap.is_some_and(|cap| off >= cap) {
                return self.reply(Op::WriteResponse, seq, CMD_FILE, RcReply { rc: RC_INVALID });
            }
            let data = request.data.expect("write request without data").0;
            let new_len = {
                let mut files = self.files.lock().unwrap();
                let file = files.entry(name).or_default();
                if off == 0 {
                    assert!(request.len.is_some(), "a first write must carry the length");
                    file.clear();
                }
                if off != file.len() {
                    None
                } else {
                    file.extend_from_slice(&data[..data.len().min(self.accept_per_write)]);
                    Some(file.len())
                }
            };
            match new_len {
                Some(off) => self.reply(Op::WriteResponse, seq, CMD_FILE, OffReply { off }),
                None => self.reply(
                    Op::WriteResponse,
                    seq,
                    CMD_FILE,
                    RcReply { rc: RC_SEEK_FAILED },
                ),
            }
        }

        fn handle_status(&self, seq: u8, request: AnyRequest) {
            let name = request.name.expect("status request without a name");
            let len = self
                .files
                .lock()
                .unwrap()
                .get(&name)
                .map(|f| f.len() as u64);
            match len {
                Some(len) => self.reply(Op::ReadResponse, seq, CMD_STATUS, LenReply { len }),
                None if self.v2_errors => {
                    let err = GroupError {
                        group: FS_GROUP,
                        rc: FS_ERR_FILE_NOT_FOUND,
                    };
                    self.reply(Op::ReadResponse, seq, CMD_STATUS, GroupErrorReply { err })
                }
                None => self.reply(
                    Op::ReadResponse,
                    seq,
                    CMD_STATUS,
                    RcReply { rc: RC_NO_ENTRY },
                ),
            }
        }
    }

    impl Transport for FakeFsDevice {
        fn send(&self, frame: Vec<u8>) -> BoxFuture<'_, Result<(), Error>> {
            {
                let mut largest = self.largest_request.lock().unwrap();
                *largest = (*largest).max(frame.len());
            }
            let (header, request): (_, AnyRequest) =
                frame::decode(&frame).expect("fake device: undecodable request");
            match (header.command, header.op) {
                (CMD_STATUS, _) => self.handle_status(header.seq, request),
                (CMD_FILE, Op::Write) => self.handle_write(header.seq, request),
                (CMD_FILE, Op::Read) => self.handle_read(header.seq, request),
                (CMD_HASH, _) => self.handle_hash(header.seq, request),
                (CMD_SUPPORTED_HASHES, _) => self.handle_supported_hashes(header.seq),
                other => panic!("fake device: unexpected fs request {other:?}"),
            }
            Box::pin(async { Ok(()) })
        }

        fn receive(&self) -> BoxFuture<'_, Result<Vec<u8>, Error>> {
            Box::pin(async {
                loop {
                    if let Some(frame) = self.responses.lock().unwrap().pop_front() {
                        return Ok(frame);
                    }
                    self.wake.notified().await;
                }
            })
        }

        fn max_in_flight(&self) -> usize {
            1
        }
    }

    fn session_for(device: Arc<FakeFsDevice>) -> Session {
        Session::new(device, TEST_CHUNK_BUDGET)
    }

    async fn upload_to_completion(
        session: &Session,
        data: Vec<u8>,
        remote_path: &str,
    ) -> Result<Vec<FsProgress>, Error> {
        let mut stream = session.fs_upload(Arc::from(data), remote_path.to_owned());
        let mut events = Vec::new();
        while let Some(event) = next(&mut stream).await {
            events.push(event?);
        }
        Ok(events)
    }

    #[tokio::test]
    async fn fs_upload_writes_every_byte_across_several_chunks() {
        let device = FakeFsDevice::new();
        let session = session_for(Arc::clone(&device));
        let contents: Vec<u8> = (0..5000u32).map(|i| (i % 251) as u8).collect();

        let events = upload_to_completion(&session, contents.clone(), "/lfs/target1.bin")
            .await
            .unwrap();

        assert_eq!(device.contents("/lfs/target1.bin"), contents);
        assert!(events.last().unwrap().is_complete());
        assert!(events.len() > 1);
    }

    #[tokio::test]
    async fn fs_upload_continues_from_the_offset_a_short_write_reports() {
        let device = FakeFsDevice::accepting(100);
        let session = session_for(Arc::clone(&device));
        let contents: Vec<u8> = (0..1000u32).map(|i| (i % 251) as u8).collect();

        upload_to_completion(&session, contents.clone(), "/lfs/target1.bin")
            .await
            .unwrap();

        assert_eq!(device.contents("/lfs/target1.bin"), contents);
    }

    #[tokio::test]
    async fn fs_upload_gives_up_when_the_device_accepts_nothing() {
        let session = session_for(FakeFsDevice::accepting(0));

        let result = upload_to_completion(&session, vec![0x5A; 256], "/lfs/target1.bin").await;

        assert!(
            matches!(result, Err(Error::FsNoProgress { offset: 0 })),
            "a device that accepts no bytes must fail, not spin: {result:?}"
        );
    }

    #[tokio::test]
    async fn fs_upload_overwrites_a_longer_existing_file() {
        let device = FakeFsDevice::new();
        device.put("/lfs/target1.bin", vec![0xFF; 4096]);
        let session = session_for(Arc::clone(&device));

        upload_to_completion(&session, vec![0x11; 300], "/lfs/target1.bin")
            .await
            .unwrap();

        assert_eq!(device.contents("/lfs/target1.bin"), vec![0x11; 300]);
    }

    #[tokio::test]
    async fn fs_upload_keeps_requests_within_the_device_buffer_for_a_long_path() {
        let device = FakeFsDevice::new();
        let session = session_for(Arc::clone(&device));
        let long_path = format!("/lfs/{}.bin", "d".repeat(180));

        upload_to_completion(&session, vec![0x22; 4096], &long_path)
            .await
            .unwrap();

        let largest = *device.largest_request.lock().unwrap();
        assert!(
            largest <= TEST_DEVICE_BUF_SIZE,
            "a {largest}-byte request overflows the device's {TEST_DEVICE_BUF_SIZE}-byte buffer"
        );
    }

    #[tokio::test]
    async fn fs_upload_past_a_device_offset_cap_names_the_offset_and_the_cap() {
        let session = session_for(FakeFsDevice::with_offset_cap(SMALL_OFFSET_LIMIT));

        let result = upload_to_completion(
            &session,
            vec![0x99; SMALL_OFFSET_LIMIT + 4096],
            "/lfs/target1.bin",
        )
        .await;

        let Err(Error::Rejected { rc, reason, .. }) = result else {
            panic!("a capped device must reject the upload, got {result:?}");
        };
        assert_eq!(rc, RC_INVALID);
        assert!(reason.contains("at offset "), "{reason}");
        assert!(reason.contains("MAX_FILE_SIZE"), "{reason}");
    }

    #[tokio::test]
    async fn fs_download_past_a_device_offset_cap_names_the_offset() {
        let device = FakeFsDevice::with_offset_cap(SMALL_OFFSET_LIMIT);
        device.put("/lfs/target1.bin", vec![0xAA; SMALL_OFFSET_LIMIT + 4096]);
        let session = session_for(Arc::clone(&device));

        let result = session.fs_download("/lfs/target1.bin", None).await;

        let Err(Error::Rejected { reason, .. }) = result else {
            panic!("a capped device must reject the download, got {result:?}");
        };
        assert!(reason.contains("at offset "), "{reason}");
    }

    #[tokio::test]
    async fn fs_upload_under_a_device_offset_cap_still_succeeds() {
        let device = FakeFsDevice::with_offset_cap(SMALL_OFFSET_LIMIT);
        let session = session_for(Arc::clone(&device));
        let contents = vec![0xBB; SMALL_OFFSET_LIMIT - 1];

        upload_to_completion(&session, contents.clone(), "/lfs/target1.bin")
            .await
            .unwrap();

        assert_eq!(device.contents("/lfs/target1.bin"), contents);
    }

    #[tokio::test]
    async fn fs_verify_confirms_a_matching_file_with_the_device_hash() {
        let device = FakeFsDevice::new();
        device.put("/lfs/target1.bin", vec![0x44; 2048]);
        let session = session_for(Arc::clone(&device));

        let how = session
            .fs_verify("/lfs/target1.bin", &[0x44; 2048])
            .await
            .unwrap();

        assert_eq!(how, FsVerification::Sha256);
    }

    #[tokio::test]
    async fn fs_verify_uses_crc32_when_the_device_has_no_sha256() {
        let device = FakeFsDevice::with_hashes(HashSupport::Crc32Only);
        device.put("/lfs/target1.bin", vec![0x55; 2048]);
        let session = session_for(Arc::clone(&device));

        let how = session
            .fs_verify("/lfs/target1.bin", &[0x55; 2048])
            .await
            .unwrap();

        assert_eq!(how, FsVerification::Crc32);
    }

    #[tokio::test]
    async fn fs_verify_downloads_the_file_when_the_device_cannot_hash() {
        let device = FakeFsDevice::with_hashes(HashSupport::None);
        device.put("/lfs/target1.bin", vec![0x66; 2048]);
        let session = session_for(Arc::clone(&device));

        let how = session
            .fs_verify("/lfs/target1.bin", &[0x66; 2048])
            .await
            .unwrap();

        assert_eq!(how, FsVerification::Downloaded);
    }

    #[tokio::test]
    async fn fs_verify_rejects_a_file_whose_bytes_differ() {
        for support in [
            HashSupport::Sha256AndCrc32,
            HashSupport::Crc32Only,
            HashSupport::None,
        ] {
            let device = FakeFsDevice::with_hashes(support);
            let mut on_device = vec![0x77; 2048];
            on_device[1000] ^= 0xFF;
            device.put("/lfs/target1.bin", on_device);
            let session = session_for(Arc::clone(&device));

            let result = session.fs_verify("/lfs/target1.bin", &[0x77; 2048]).await;

            assert!(
                matches!(result, Err(Error::FsVerifyMismatch { .. })),
                "{support:?}: {result:?}"
            );
        }
    }

    #[tokio::test]
    async fn fs_verify_rejects_a_truncated_file() {
        let device = FakeFsDevice::with_hashes(HashSupport::None);
        device.put("/lfs/target1.bin", vec![0x88; 1000]);
        let session = session_for(Arc::clone(&device));

        let result = session.fs_verify("/lfs/target1.bin", &[0x88; 2048]).await;

        assert!(
            matches!(result, Err(Error::FsVerifyMismatch { .. })),
            "{result:?}"
        );
    }

    #[tokio::test]
    async fn fs_download_returns_the_whole_file() {
        let device = FakeFsDevice::new();
        let contents: Vec<u8> = (0..3000u32).map(|i| (i % 251) as u8).collect();
        device.put("/lfs/target1.bin", contents.clone());
        let session = session_for(Arc::clone(&device));

        let got = session.fs_download("/lfs/target1.bin", None).await.unwrap();

        assert_eq!(got, contents);
    }

    #[tokio::test]
    async fn fs_download_reports_progress_as_chunks_arrive() {
        let device = FakeFsDevice::new();
        device.put("/lfs/target1.bin", vec![0x33; 3000]);
        let session = session_for(Arc::clone(&device));
        let (tx, mut rx) = mpsc::channel(PROGRESS_CHANNEL_DEPTH);

        session
            .fs_download("/lfs/target1.bin", Some(tx))
            .await
            .unwrap();

        let mut events = Vec::new();
        while let Ok(event) = rx.try_recv() {
            events.push(event);
        }
        assert!(events.len() > 1, "{events:?}");
        assert!(events.last().unwrap().is_complete());
    }

    #[tokio::test]
    async fn fs_download_surfaces_the_device_rejection_for_a_missing_file() {
        let session = session_for(FakeFsDevice::new());

        let result = session.fs_download("/lfs/absent.bin", None).await;

        assert!(
            matches!(
                result,
                Err(Error::Rejected {
                    rc: RC_NO_ENTRY,
                    ..
                })
            ),
            "{result:?}"
        );
    }

    #[tokio::test]
    async fn fs_status_surfaces_an_smp_v2_group_error() {
        let session = session_for(FakeFsDevice::with_v2_errors());

        let result = session.fs_status("/lfs/absent.bin").await;

        assert!(
            matches!(
                result,
                Err(Error::Rejected {
                    rc: FS_ERR_FILE_NOT_FOUND,
                    group: Some(FS_GROUP),
                    ..
                })
            ),
            "{result:?}"
        );
    }

    #[tokio::test]
    async fn fs_upload_refuses_a_path_that_leaves_no_room_for_data() {
        let device = FakeFsDevice::new();
        let session = session_for(Arc::clone(&device));
        let path = format!("/lfs/{}", "p".repeat(TEST_CHUNK_BUDGET));

        let result = upload_to_completion(&session, vec![0x33; 100], &path).await;

        assert!(
            matches!(result, Err(Error::FsPathTooLong { .. })),
            "{result:?}"
        );
        assert_eq!(*device.largest_request.lock().unwrap(), 0);
    }

    #[tokio::test]
    async fn a_stale_reply_left_in_the_transport_is_skipped_by_the_next_request() {
        let device = FakeFsDevice::new();
        device.put("/lfs/target1.bin", vec![0xAB; 1234]);
        device.reply(Op::ReadResponse, STALE_SEQ, CMD_STATUS, LenReply { len: 1 });
        let session = session_for(Arc::clone(&device));

        let len = session.fs_status("/lfs/target1.bin").await.unwrap();

        assert_eq!(len, 1234);
    }

    #[tokio::test]
    async fn a_reply_too_short_to_carry_a_sequence_number_is_dropped() {
        let device = FakeFsDevice::new();
        device.put("/lfs/target1.bin", vec![0xAB; 1234]);
        device.push(vec![0; HEADER_LEN - 2]);
        let session = session_for(Arc::clone(&device));

        let len = session.fs_status("/lfs/target1.bin").await.unwrap();

        assert_eq!(len, 1234);
    }

    #[tokio::test]
    async fn fs_upload_takes_only_its_own_reply_as_the_ack() {
        let device = FakeFsDevice::with_a_stale_reply_before_each_write_reply();
        let session = session_for(Arc::clone(&device));
        let contents: Vec<u8> = (0..2000u32).map(|i| (i % 251) as u8).collect();

        upload_to_completion(&session, contents.clone(), "/lfs/target1.bin")
            .await
            .unwrap();

        assert_eq!(device.contents("/lfs/target1.bin"), contents);
    }

    #[tokio::test]
    async fn a_dropped_fs_upload_stops_waiting_and_leaves_the_next_request_its_reply() {
        let device = FakeFsDevice::with_silent_writes();
        device.put("/lfs/target1.bin", vec![0xAB; 1234]);
        let session = session_for(Arc::clone(&device));
        let stream = session.fs_upload(Arc::from(vec![0x11; 300]), "/lfs/target2.bin".into());
        tokio::time::sleep(SETTLE).await;
        assert_eq!(
            session.router().awaited(),
            1,
            "the first chunk awaits its ack"
        );

        drop(stream);
        tokio::time::sleep(SETTLE).await;

        assert_eq!(session.router().awaited(), 0);
        assert_eq!(session.fs_status("/lfs/target1.bin").await.unwrap(), 1234);
    }

    #[tokio::test]
    async fn fs_hash_carries_a_crc32_big_endian() {
        let device = FakeFsDevice::with_hashes(HashSupport::Crc32Only);
        device.put("/lfs/target1.bin", vec![0x12; 777]);
        let session = session_for(Arc::clone(&device));

        let hash = session
            .fs_hash("/lfs/target1.bin", FsHashAlgorithm::Crc32)
            .await
            .unwrap();

        assert_eq!(
            hash.value,
            wslib_checksum::crc32(&[0x12; 777]).to_be_bytes()
        );
    }
}
