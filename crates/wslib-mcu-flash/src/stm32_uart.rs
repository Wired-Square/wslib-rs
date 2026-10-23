//! ST AN3155, the system bootloader in ROM on every STM32, spoken directly
//! over `serialport` (the published loader crates are unmaintained and
//! target embedded-hal, not a desktop port). Blocks on the port; wrap calls
//! in `spawn_blocking`. A cancel mid-frame desyncs the bootloader, which a
//! reset clears.

use std::io::Write as _;
use std::path::Path;
use std::str::FromStr;
use std::thread::sleep;
use std::time::Duration;

use serialport::{DataBits, FlowControl, Parity, SerialPort, StopBits};

use crate::chip::lookup_stm32_pid;
use crate::error::{FlashError, Result};
use crate::image::{self, pad_word_with_ff};
use crate::output;
use crate::progress::{FlashProgress, FlashStage, check_cancel};

const SYNC_BYTE: u8 = 0x7F;
const ACK: u8 = 0x79;
const NACK: u8 = 0x1F;

const CMD_GET: u8 = 0x00;
const CMD_GET_ID: u8 = 0x02;
const CMD_READ_MEMORY: u8 = 0x11;
const CMD_WRITE_MEMORY: u8 = 0x31;
const CMD_ERASE: u8 = 0x43;
const CMD_EXTENDED_ERASE: u8 = 0x44;

pub const DEFAULT_BAUD: u32 = 115_200;
pub const DEFAULT_FLASH_BASE: u32 = 0x0800_0000;
const CHUNK: usize = 256;

const ACK_TIMEOUT: Duration = Duration::from_millis(2_000);
const ERASE_TIMEOUT: Duration = Duration::from_secs(60);

/// A modem-control line the host can drive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pin {
    Rts,
    Dtr,
}

impl FromStr for Pin {
    type Err = FlashError;

    fn from_str(s: &str) -> Result<Self> {
        match s.to_ascii_lowercase().as_str() {
            "rts" => Ok(Pin::Rts),
            "dtr" => Ok(Pin::Dtr),
            other => Err(FlashError::Message(format!("Unknown pin {other:?}"))),
        }
    }
}

/// `"rts"` / `"dtr"` as that pin, `"none"` or empty as no pin, anything else as `default`.
pub fn parse_pin(s: Option<&str>, default: Option<Pin>) -> Option<Pin> {
    match s.map(str::trim) {
        Some("") => None,
        Some(text) if text.eq_ignore_ascii_case("none") => None,
        Some(text) => text.parse().ok().or(default),
        None => default,
    }
}

/// Bootloader-entry wiring and baud; the default is stm32flash's
/// (DTR drives BOOT0, RTS drives an active-low NRST).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stm32UartOptions {
    pub boot0: Option<Pin>,
    pub reset: Option<Pin>,
    pub boot0_invert: bool,
    pub reset_invert: bool,
    pub baud: u32,
}

impl Default for Stm32UartOptions {
    fn default() -> Self {
        Self {
            boot0: Some(Pin::Dtr),
            reset: Some(Pin::Rts),
            boot0_invert: false,
            reset_invert: true,
            baud: DEFAULT_BAUD,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Stm32ChipInfo {
    pub chip: String,
    pub pid: u16,
    pub bootloader_version: String,
    pub flash_size_kb: Option<u32>,
    pub rdp_level: Option<String>,
}

pub fn detect_chip(port: &str, options: &Stm32UartOptions) -> Result<Stm32ChipInfo> {
    let mut session = connect(port, options)?;
    let rdp_level = match cmd_read_memory(session.port.as_mut(), DEFAULT_FLASH_BASE, 1) {
        Ok(_) => "0",
        Err(_) => "1 (locked)",
    };
    let (chip, flash_size_kb) = lookup_stm32_pid(session.pid);
    Ok(Stm32ChipInfo {
        chip: chip.to_string(),
        pid: session.pid,
        bootloader_version: session.bootloader_version(),
        flash_size_kb,
        rdp_level: Some(rdp_level.to_string()),
    })
}

pub fn flash(
    port: &str,
    image_path: &Path,
    address: u32,
    options: &Stm32UartOptions,
    progress: &mut dyn FlashProgress,
) -> Result<()> {
    progress.on_stage(FlashStage::Connecting, &format!("Opening {port}"));
    let mut session = connect(port, options)?;

    let (chip_name, flash_size_kb) = lookup_stm32_pid(session.pid);
    progress.on_progress(&format!(
        "Connected: {chip_name} (PID 0x{:04X}, BL v{}{})",
        session.pid,
        session.bootloader_version(),
        flash_size_kb
            .map(|kb| format!(", {kb} KB flash"))
            .unwrap_or_default(),
    ));

    let spans = image::load_spans(image_path, address)?;
    let total: u64 = spans.iter().map(|s| s.data.len() as u64).sum();
    if total == 0 {
        return Err("Firmware image is empty".into());
    }

    check_cancel(progress)?;
    progress.on_stage(FlashStage::Erasing, "Mass-erasing flash…");
    session.mass_erase()?;
    check_cancel(progress)?;

    progress.on_stage(FlashStage::Writing, &format!("Writing {total} bytes"));
    let p = session.port.as_mut();
    let mut done: u64 = 0;
    for span in &spans {
        let mut addr = span.address;
        for chunk in span.data.chunks(CHUNK) {
            check_cancel(progress)?;
            let padded = pad_word_with_ff(chunk);
            cmd_write_memory(p, addr, &padded)?;
            addr = addr.wrapping_add(padded.len() as u32);
            done += chunk.len() as u64;
            progress.on_bytes(done, total);
        }
    }

    progress.on_stage(FlashStage::Resetting, "Flash complete; reset to run");
    Ok(())
}

pub fn read_flash(
    port: &str,
    output_path: &Path,
    offset: u32,
    size: Option<u32>,
    options: &Stm32UartOptions,
    progress: &mut dyn FlashProgress,
) -> Result<()> {
    progress.on_stage(FlashStage::Connecting, &format!("Opening {port}"));
    let mut session = connect(port, options)?;

    let resolved_size = match size {
        Some(s) if s > 0 => s,
        _ => lookup_stm32_pid(session.pid)
            .1
            .map(|kb| kb * 1024)
            .ok_or_else(|| {
                FlashError::Message(
                    "Flash size unknown for this chip; specify a size manually".to_string(),
                )
            })?,
    };

    let total = resolved_size as u64;
    progress.on_stage(
        FlashStage::Writing,
        &format!(
            "Reading {total} bytes from 0x{offset:08X} to {}",
            output_path.display()
        ),
    );

    read_memory_to(
        session.port.as_mut(),
        output_path,
        offset,
        resolved_size,
        progress,
    )
}

fn read_memory_to(
    p: &mut dyn SerialPort,
    output_path: &Path,
    offset: u32,
    resolved_size: u32,
    progress: &mut dyn FlashProgress,
) -> Result<()> {
    let total = resolved_size as u64;
    output::replace_with(output_path, |file| {
        let mut bytes_done: u64 = 0;
        let mut current_offset = offset;
        let mut remaining = resolved_size;

        while remaining > 0 {
            check_cancel(progress)?;
            let chunk_len = remaining.min(CHUNK as u32) as usize;
            let chunk = cmd_read_memory(p, current_offset, chunk_len)?;
            file.write_all(&chunk).map_err(|e| {
                FlashError::Message(format!("Failed to write {}: {e}", output_path.display()))
            })?;
            let n = chunk.len() as u32;
            bytes_done += n as u64;
            current_offset = current_offset.saturating_add(n);
            remaining = remaining.saturating_sub(n);
            progress.on_bytes(bytes_done, total);
        }
        Ok(())
    })?;

    progress.on_progress(&format!("Saved {total} bytes to {}", output_path.display()));
    Ok(())
}

pub fn erase(
    port: &str,
    options: &Stm32UartOptions,
    progress: &mut dyn FlashProgress,
) -> Result<()> {
    progress.on_stage(FlashStage::Connecting, &format!("Opening {port}"));
    let mut session = connect(port, options)?;
    progress.on_stage(
        FlashStage::Erasing,
        "Mass-erasing flash — this can take a minute…",
    );
    session.mass_erase()
}

struct Session {
    port: Box<dyn SerialPort>,
    bootloader_version: u8,
    supported_cmds: Vec<u8>,
    pid: u16,
}

impl Session {
    fn bootloader_version(&self) -> String {
        format!(
            "{}.{}",
            self.bootloader_version >> 4,
            self.bootloader_version & 0x0F
        )
    }

    fn mass_erase(&mut self) -> Result<()> {
        let p = self.port.as_mut();
        if self.supported_cmds.contains(&CMD_EXTENDED_ERASE) {
            send_command(p, CMD_EXTENDED_ERASE)?;
            write_all(p, &[0xFF, 0xFF, 0x00])?;
        } else if self.supported_cmds.contains(&CMD_ERASE) {
            send_command(p, CMD_ERASE)?;
            write_all(p, &[0xFF, 0x00])?;
        } else {
            return Err("Bootloader supports neither ERASE nor EXTENDED_ERASE".into());
        }
        with_timeout(p, ERASE_TIMEOUT, wait_ack)
    }
}

fn connect(port: &str, opts: &Stm32UartOptions) -> Result<Session> {
    let mut p = serialport::new(port, opts.baud)
        .data_bits(DataBits::Eight)
        .parity(Parity::Even)
        .stop_bits(StopBits::One)
        .flow_control(FlowControl::None)
        .timeout(ACK_TIMEOUT)
        .open()
        .map_err(|e| FlashError::Message(format!("Failed to open {port}: {e}")))?;
    enter_bootloader(p.as_mut(), opts)?;
    autobaud(p.as_mut())?;
    let (bootloader_version, supported_cmds) = cmd_get(p.as_mut())?;
    let pid = cmd_get_id(p.as_mut())?;
    Ok(Session {
        port: p,
        bootloader_version,
        supported_cmds,
        pid,
    })
}

fn drive(p: &mut dyn SerialPort, pin: Option<Pin>, asserted: bool, invert: bool) -> Result<()> {
    let level = asserted ^ invert;
    match pin {
        Some(Pin::Rts) => p
            .write_request_to_send(level)
            .map_err(|e| FlashError::Message(format!("Failed to set RTS: {e}"))),
        Some(Pin::Dtr) => p
            .write_data_terminal_ready(level)
            .map_err(|e| FlashError::Message(format!("Failed to set DTR: {e}"))),
        None => Ok(()),
    }
}

/// stm32flash's entry sequence: hold reset with BOOT0 high, release reset
/// so the chip samples BOOT0, then release BOOT0.
fn enter_bootloader(p: &mut dyn SerialPort, opts: &Stm32UartOptions) -> Result<()> {
    if opts.boot0.is_none() && opts.reset.is_none() {
        return Ok(());
    }
    drive(p, opts.reset, true, opts.reset_invert)?;
    drive(p, opts.boot0, true, opts.boot0_invert)?;
    sleep(Duration::from_millis(50));
    drive(p, opts.reset, false, opts.reset_invert)?;
    sleep(Duration::from_millis(150));
    drive(p, opts.boot0, false, opts.boot0_invert)?;
    let _ = p.clear(serialport::ClearBuffer::Input);
    Ok(())
}

fn write_all(p: &mut dyn SerialPort, buf: &[u8]) -> Result<()> {
    p.write_all(buf)
        .map_err(|e| FlashError::Message(format!("Serial write: {e}")))?;
    p.flush()
        .map_err(|e| FlashError::Message(format!("Serial flush: {e}")))
}

fn read_exact(p: &mut dyn SerialPort, buf: &mut [u8]) -> Result<()> {
    let mut filled = 0;
    while filled < buf.len() {
        let n = p
            .read(&mut buf[filled..])
            .map_err(|e| FlashError::Message(format!("Serial read: {e}")))?;
        if n == 0 {
            return Err("Serial read returned 0 bytes (timeout)".into());
        }
        filled += n;
    }
    Ok(())
}

fn read_byte(p: &mut dyn SerialPort) -> Result<u8> {
    let mut buf = [0u8; 1];
    read_exact(p, &mut buf)?;
    Ok(buf[0])
}

fn wait_ack(p: &mut dyn SerialPort) -> Result<()> {
    match read_byte(p)? {
        ACK => Ok(()),
        NACK => Err("Device returned NACK".into()),
        other => Err(FlashError::Message(format!(
            "Unexpected byte 0x{other:02X} (expected ACK/NACK)"
        ))),
    }
}

fn autobaud(p: &mut dyn SerialPort) -> Result<()> {
    write_all(p, &[SYNC_BYTE])?;
    wait_ack(p).map_err(|e| {
        FlashError::Message(format!(
            "Bootloader handshake failed: {e}. \
             Check BOOT0/RESET wiring or hold BOOT0 manually before connecting."
        ))
    })
}

fn send_command(p: &mut dyn SerialPort, cmd: u8) -> Result<()> {
    write_all(p, &[cmd, cmd ^ 0xFF])?;
    wait_ack(p)
}

fn send_address(p: &mut dyn SerialPort, addr: u32) -> Result<()> {
    let bytes = addr.to_be_bytes();
    let xor = bytes.iter().fold(0u8, |a, b| a ^ b);
    write_all(p, &[bytes[0], bytes[1], bytes[2], bytes[3], xor])?;
    wait_ack(p)
}

fn send_data(p: &mut dyn SerialPort, data: &[u8]) -> Result<()> {
    if data.is_empty() || data.len() > 256 {
        return Err(FlashError::Message(format!(
            "send_data: invalid length {}",
            data.len()
        )));
    }
    let n = (data.len() - 1) as u8;
    let xor = data.iter().fold(n, |a, b| a ^ b);
    let mut framed = Vec::with_capacity(data.len() + 2);
    framed.push(n);
    framed.extend_from_slice(data);
    framed.push(xor);
    write_all(p, &framed)
}

/// Reply framing: `ACK | N | version | cmd1..cmdN | ACK`.
fn cmd_get(p: &mut dyn SerialPort) -> Result<(u8, Vec<u8>)> {
    send_command(p, CMD_GET)?;
    let payload = read_counted(p)?;
    Ok((payload[0], payload[1..].to_vec()))
}

/// Reply framing: `ACK | N=1 | PID_MSB | PID_LSB | ACK`.
fn cmd_get_id(p: &mut dyn SerialPort) -> Result<u16> {
    send_command(p, CMD_GET_ID)?;
    let payload = read_counted(p)?;
    if payload.len() < 2 {
        return Err(FlashError::Message(format!(
            "GET_ID returned {} bytes, expected >= 2",
            payload.len()
        )));
    }
    Ok(((payload[0] as u16) << 8) | payload[1] as u16)
}

fn read_counted(p: &mut dyn SerialPort) -> Result<Vec<u8>> {
    let n = read_byte(p)?;
    let mut payload = vec![0u8; (n as usize) + 1];
    read_exact(p, &mut payload)?;
    wait_ack(p)?;
    Ok(payload)
}

fn cmd_read_memory(p: &mut dyn SerialPort, addr: u32, len: usize) -> Result<Vec<u8>> {
    if !(1..=CHUNK).contains(&len) {
        return Err(FlashError::Message(format!(
            "cmd_read_memory: invalid length {len}"
        )));
    }
    send_command(p, CMD_READ_MEMORY).map_err(rdp_hint_on_nack)?;
    send_address(p, addr).map_err(rdp_hint_on_nack)?;
    let n = (len - 1) as u8;
    write_all(p, &[n, n ^ 0xFF])?;
    wait_ack(p).map_err(rdp_hint_on_nack)?;
    let mut buf = vec![0u8; len];
    read_exact(p, &mut buf)?;
    Ok(buf)
}

fn rdp_hint_on_nack(err: FlashError) -> FlashError {
    if err.to_string().contains("NACK") {
        "Read protected (RDP Level 1) — disable readout protection to back up flash".into()
    } else {
        err
    }
}

fn cmd_write_memory(p: &mut dyn SerialPort, addr: u32, data: &[u8]) -> Result<()> {
    if !data.len().is_multiple_of(4) {
        return Err(FlashError::Message(format!(
            "cmd_write_memory: length {} not word-aligned",
            data.len()
        )));
    }
    send_command(p, CMD_WRITE_MEMORY)?;
    send_address(p, addr)?;
    send_data(p, data)?;
    wait_ack(p)
}

fn with_timeout<T>(
    p: &mut dyn SerialPort,
    new_timeout: Duration,
    f: impl FnOnce(&mut dyn SerialPort) -> Result<T>,
) -> Result<T> {
    let saved = p.timeout();
    p.set_timeout(new_timeout)
        .map_err(|e| FlashError::Message(format!("set_timeout: {e}")))?;
    let result = f(p);
    let _ = p.set_timeout(saved);
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::progress::LogProgress;

    #[test]
    fn parse_pin_round_trip() {
        assert_eq!(parse_pin(Some("rts"), None), Some(Pin::Rts));
        assert_eq!(parse_pin(Some("DTR"), None), Some(Pin::Dtr));
        assert_eq!(parse_pin(Some("none"), Some(Pin::Rts)), None);
        assert_eq!(parse_pin(Some(""), Some(Pin::Rts)), None);
        assert_eq!(parse_pin(None, Some(Pin::Dtr)), Some(Pin::Dtr));
        assert_eq!(parse_pin(Some("xyz"), Some(Pin::Rts)), Some(Pin::Rts));
    }

    #[test]
    fn default_options_are_stm32flash_wiring() {
        let opts = Stm32UartOptions::default();
        assert_eq!(opts.boot0, Some(Pin::Dtr));
        assert_eq!(opts.reset, Some(Pin::Rts));
        assert!(!opts.boot0_invert);
        assert!(opts.reset_invert);
        assert_eq!(opts.baud, DEFAULT_BAUD);
    }

    #[test]
    fn nack_on_read_becomes_an_rdp_hint() {
        let hinted = rdp_hint_on_nack("Device returned NACK".into()).to_string();
        assert!(hinted.contains("RDP"), "{hinted}");
        let other = rdp_hint_on_nack("Serial read: timeout".into()).to_string();
        assert_eq!(other, "Serial read: timeout");
    }

    struct FakePort {
        replies: std::collections::VecDeque<u8>,
        written: Vec<u8>,
    }

    impl FakePort {
        fn acking_reads_then_nack(chunks: &[usize]) -> Self {
            let mut replies = std::collections::VecDeque::new();
            for &len in chunks {
                replies.extend([ACK, ACK, ACK]);
                replies.extend(std::iter::repeat_n(0xA5, len));
            }
            replies.push_back(NACK);
            Self {
                replies,
                written: Vec::new(),
            }
        }
    }

    impl std::io::Read for FakePort {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let n = buf.len().min(self.replies.len());
            for slot in &mut buf[..n] {
                *slot = self.replies.pop_front().unwrap();
            }
            Ok(n)
        }
    }

    impl std::io::Write for FakePort {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.written.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl SerialPort for FakePort {
        fn name(&self) -> Option<String> {
            None
        }
        fn baud_rate(&self) -> serialport::Result<u32> {
            Ok(DEFAULT_BAUD)
        }
        fn data_bits(&self) -> serialport::Result<DataBits> {
            Ok(DataBits::Eight)
        }
        fn flow_control(&self) -> serialport::Result<FlowControl> {
            Ok(FlowControl::None)
        }
        fn parity(&self) -> serialport::Result<Parity> {
            Ok(Parity::Even)
        }
        fn stop_bits(&self) -> serialport::Result<StopBits> {
            Ok(StopBits::One)
        }
        fn timeout(&self) -> Duration {
            ACK_TIMEOUT
        }
        fn set_baud_rate(&mut self, _: u32) -> serialport::Result<()> {
            Ok(())
        }
        fn set_data_bits(&mut self, _: DataBits) -> serialport::Result<()> {
            Ok(())
        }
        fn set_flow_control(&mut self, _: FlowControl) -> serialport::Result<()> {
            Ok(())
        }
        fn set_parity(&mut self, _: Parity) -> serialport::Result<()> {
            Ok(())
        }
        fn set_stop_bits(&mut self, _: StopBits) -> serialport::Result<()> {
            Ok(())
        }
        fn set_timeout(&mut self, _: Duration) -> serialport::Result<()> {
            Ok(())
        }
        fn write_request_to_send(&mut self, _: bool) -> serialport::Result<()> {
            Ok(())
        }
        fn write_data_terminal_ready(&mut self, _: bool) -> serialport::Result<()> {
            Ok(())
        }
        fn read_clear_to_send(&mut self) -> serialport::Result<bool> {
            Ok(false)
        }
        fn read_data_set_ready(&mut self) -> serialport::Result<bool> {
            Ok(false)
        }
        fn read_ring_indicator(&mut self) -> serialport::Result<bool> {
            Ok(false)
        }
        fn read_carrier_detect(&mut self) -> serialport::Result<bool> {
            Ok(false)
        }
        fn bytes_to_read(&self) -> serialport::Result<u32> {
            Ok(self.replies.len() as u32)
        }
        fn bytes_to_write(&self) -> serialport::Result<u32> {
            Ok(0)
        }
        fn clear(&self, _: serialport::ClearBuffer) -> serialport::Result<()> {
            Ok(())
        }
        fn try_clone(&self) -> serialport::Result<Box<dyn SerialPort>> {
            Err(serialport::Error::new(
                serialport::ErrorKind::Unknown,
                "not cloneable",
            ))
        }
        fn set_break(&self) -> serialport::Result<()> {
            Ok(())
        }
        fn clear_break(&self) -> serialport::Result<()> {
            Ok(())
        }
    }

    struct Cancelled;

    impl FlashProgress for Cancelled {
        fn on_progress(&mut self, _: &str) {}

        fn cancelled(&self) -> bool {
            true
        }
    }

    fn existing_output(dir: &Path) -> std::path::PathBuf {
        let path = dir.join("backup.bin");
        std::fs::write(&path, b"earlier backup").unwrap();
        path
    }

    fn scratch_dir(name: &str) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("wslib-mcu-flash-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn a_full_chunk_is_read_as_256_bytes() {
        let dir = scratch_dir("full-chunk");
        let path = dir.join("backup.bin");
        let mut port = FakePort::acking_reads_then_nack(&[256, 44]);
        read_memory_to(
            &mut port,
            &path,
            DEFAULT_FLASH_BASE,
            300,
            &mut LogProgress::default(),
        )
        .unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), vec![0xA5; 300]);
        let len_frames: Vec<_> = port.written.chunks(9).map(|f| [f[7], f[8]]).collect();
        assert_eq!(len_frames, [[0xFF, 0x00], [43, !43]]);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_failed_read_leaves_the_existing_output() {
        let dir = scratch_dir("failed-read");
        let path = existing_output(&dir);
        let mut port = FakePort::acking_reads_then_nack(&[256]);
        let err = read_memory_to(
            &mut port,
            &path,
            DEFAULT_FLASH_BASE,
            512,
            &mut LogProgress::default(),
        );
        assert!(err.is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"earlier backup");
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_cancelled_read_leaves_the_existing_output() {
        let dir = scratch_dir("cancelled-read");
        let path = existing_output(&dir);
        let mut port = FakePort::acking_reads_then_nack(&[]);
        let result = read_memory_to(&mut port, &path, DEFAULT_FLASH_BASE, 256, &mut Cancelled);
        assert_eq!(result, Err(FlashError::Cancelled));
        assert_eq!(std::fs::read(&path).unwrap(), b"earlier backup");
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1);
        std::fs::remove_dir_all(dir).unwrap();
    }
}
