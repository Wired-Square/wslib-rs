//! A device's stored board definition, and its signals for a picker.

use wslib_framelink_board::BoardDef;
use wslib_framelink_board::compress::{compress_board_toml, decompress_board_toml};
use wslib_framelink_board::selectable::{SelectableSignal, categorise_signals};
use wslib_framelink_protocol::board_def;
use wslib_framelink_protocol::types::{
    MSG_ACK, MSG_BOARD_DEF_DOWNLOAD, MSG_BOARD_DEF_UPLOAD, MSG_NACK,
};

use crate::session::expect_reply;
use crate::{Error, FrameLinkSession};

const CHUNK_SIZE: u16 = 400;

/// Gzips `toml` and stores it on the device, a chunk at a time.
pub async fn upload_board_def(session: &FrameLinkSession, toml: &str) -> Result<(), Error> {
    let compressed = compress_board_toml(toml.as_bytes())?;
    let total = compressed.len() as u32;
    for (i, chunk) in compressed.chunks(CHUNK_SIZE.into()).enumerate() {
        let offset = i as u32 * u32::from(CHUNK_SIZE);
        let payload = board_def::build_board_def_upload(offset, total, chunk);
        session
            .request_reply(MSG_BOARD_DEF_UPLOAD, 0, &payload, MSG_ACK)
            .await?;
    }
    Ok(())
}

/// The board TOML the device stores, or `None` when it has none.
pub async fn download_board_def(session: &FrameLinkSession) -> Result<Option<String>, Error> {
    let mut blob = Vec::new();
    let mut offset: u32 = 0;
    loop {
        let payload = board_def::build_board_def_download_req(offset, CHUNK_SIZE);
        let reply = session.request(MSG_BOARD_DEF_DOWNLOAD, 0, &payload).await?;
        if reply.msg_type == MSG_NACK {
            return Ok(None);
        }
        let frame = expect_reply(MSG_BOARD_DEF_DOWNLOAD, MSG_BOARD_DEF_DOWNLOAD, reply)?;
        let chunk = board_def::parse_board_def_download_resp(&frame.payload)?;
        blob.extend_from_slice(&chunk.data);
        let end = chunk.offset + chunk.data.len() as u32;
        if chunk.data.is_empty() || end >= chunk.total_size {
            break;
        }
        offset = end;
    }
    Ok(Some(decompress_board_toml(&blob)?))
}

/// The device's frame definitions and signals, sorted into tiers and named.
pub async fn list_selectable_signals(
    session: &FrameLinkSession,
    board_def: Option<&BoardDef>,
) -> Result<Vec<SelectableSignal>, Error> {
    let frame_defs = session.list_frame_defs().await?;
    let device_signals = session.list_all_signals().await?;
    Ok(categorise_signals(&frame_defs, &device_signals, board_def))
}
