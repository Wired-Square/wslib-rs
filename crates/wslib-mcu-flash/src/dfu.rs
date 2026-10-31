//! USB DFU 1.1 / DfuSe in process over `dfu-nusb`. Blocks on USB control
//! transfers; wrap calls in `spawn_blocking`.
//!
//! `DfuSync::download` is one blocking call whose `'static` progress
//! closure cannot borrow the sink and is not `Send`, so the download stays
//! on the calling thread and reports chunk sizes over a channel to a scoped
//! thread that owns the sink. On cancel that thread resets the device
//! through a cloned handle so the in-flight transfer fails.

use std::io::Cursor;
use std::path::Path;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use crate::error::{FlashError, Result};
use crate::image;
use crate::ports::{Enumerator, SerialPort, TtySettle};
use crate::progress::{FlashProgress, FlashStage, check_cancel};

const DFU_INTERFACE_CLASS: u8 = 0xFE;
const DFU_INTERFACE_SUBCLASS: u8 = 0x01;
const STM32_DFU_VID: u16 = 0x0483;
const STM32_DFU_PID: u16 = 0xDF11;

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct DfuDeviceInfo {
    pub vid: u16,
    pub pid: u16,
    /// The USB serial, or `bus<N>-dev<M>` when the device reports none.
    pub serial: String,
    pub display_name: String,
    /// `"STM32 DFU"` for the ST ROM bootloader, `"DFU"` for anything else.
    pub manufacturer: String,
}

pub fn list_devices() -> Result<Vec<DfuDeviceInfo>> {
    Ok(enumerate()?
        .filter(is_dfu)
        .map(|info| DfuDeviceInfo {
            vid: info.vendor_id(),
            pid: info.product_id(),
            serial: identifier(&info),
            display_name: friendly_name(&info),
            manufacturer: manufacturer_for(&info),
        })
        .collect())
}

pub fn flash(
    usb_serial: &str,
    image_path: &Path,
    address: u32,
    progress: &mut dyn FlashProgress,
) -> Result<()> {
    flash_alt(usb_serial, image_path, 0, Some(address), progress)
}

/// `flash` to a chosen alt setting; `address` is the DfuSe start, `None` for plain DFU 1.1.
pub fn flash_alt(
    usb_serial: &str,
    image_path: &Path,
    alt: u8,
    address: Option<u32>,
    progress: &mut dyn FlashProgress,
) -> Result<()> {
    progress.on_stage(
        FlashStage::Connecting,
        &format!("Locating DFU device {usb_serial}"),
    );

    let info = enumerate()?
        .find(|d| identifier(d) == usb_serial)
        .ok_or_else(|| {
            FlashError::Message(format!(
                "DFU device {usb_serial} not found — is it still in bootloader mode?"
            ))
        })?;

    let interface_number = info
        .interfaces()
        .find(|i| is_dfu_interface(i))
        .map(|i| i.interface_number())
        .ok_or_else(|| FlashError::Message("DFU interface not advertised on this device".into()))?;

    download(&info, interface_number, image_path, alt, address, progress)
}

/// Options for `detach_and_flash`; the timeout bounds each of its two re-enumeration waits.
#[derive(Debug, Clone)]
pub struct DetachOptions {
    pub alt: u8,
    pub address: Option<u32>,
    pub reenumerate_timeout: Duration,
    pub poll: Duration,
}

impl Default for DetachOptions {
    fn default() -> Self {
        Self {
            alt: 0,
            address: None,
            reenumerate_timeout: Duration::from_secs(30),
            poll: Duration::from_millis(500),
        }
    }
}

/// Detaches a running application into DFU mode (unless it is there already), downloads the
/// image to `options.alt`, leaves DFU and returns the device's ttys once they are back.
pub fn detach_and_flash(
    usb_serial: &str,
    image_path: &Path,
    options: &DetachOptions,
    enumerate_ttys: &Enumerator,
    progress: &mut dyn FlashProgress,
) -> Result<Vec<SerialPort>> {
    progress.on_stage(
        FlashStage::Connecting,
        &format!("Locating USB device {usb_serial}"),
    );
    let (mut info, mut interface_number, mode) = find_dfu(usb_serial)?.ok_or_else(|| {
        FlashError::Message(format!(
            "USB device {usb_serial} with a DFU interface not found"
        ))
    })?;

    if mode == DfuMode::Runtime {
        detach(&info, interface_number, progress)?;
        progress.on_progress(&format!(
            "Waiting for {usb_serial} to re-enumerate in DFU mode…"
        ));
        (info, interface_number) =
            poll_until(options.reenumerate_timeout, options.poll, progress, || {
                find_dfu(usb_serial)
                    .ok()
                    .flatten()
                    .filter(|(_, _, mode)| *mode == DfuMode::Dfu)
                    .map(|(info, number, _)| (info, number))
            })?
            .ok_or_else(|| {
                FlashError::Message(format!(
                    "{usb_serial} did not come back in DFU mode within {}s",
                    options.reenumerate_timeout.as_secs()
                ))
            })?;
    }

    download(
        &info,
        interface_number,
        image_path,
        options.alt,
        options.address,
        progress,
    )?;

    progress.on_stage(
        FlashStage::Booting,
        &format!("Waiting for {usb_serial} to re-enumerate…"),
    );
    let ports = wait_for_ttys(
        enumerate_ttys,
        usb_serial,
        options.reenumerate_timeout,
        options.poll,
        progress,
    )?;
    let paths: Vec<&str> = ports.iter().map(|p| p.path.as_str()).collect();
    progress.on_progress(&format!("{usb_serial} is back on {}", paths.join(", ")));
    Ok(ports)
}

fn detach(
    info: &nusb::DeviceInfo,
    interface_number: u8,
    progress: &mut dyn FlashProgress,
) -> Result<()> {
    progress.on_progress(&format!("Detaching {} into DFU mode", friendly_name(info)));
    let (device, interface) = open_interface(info, interface_number)?;
    let dfu = dfu_nusb::DfuNusb::open(device, interface, 0)
        .map_err(|e| FlashError::Message(format!("DFU runtime handshake failed: {e}")))?
        .into_sync_dfu();
    // A device may drop off the bus before acknowledging DETACH; the wait for DFU mode decides.
    if let Err(e) = dfu.detach() {
        progress.on_progress(&format!(
            "DFU_DETACH reported {e}; waiting for DFU mode anyway"
        ));
    }
    if !dfu.will_detach() {
        let _ = dfu.usb_reset();
    }
    Ok(())
}

fn download(
    info: &nusb::DeviceInfo,
    interface_number: u8,
    image_path: &Path,
    alt: u8,
    address: Option<u32>,
    progress: &mut dyn FlashProgress,
) -> Result<()> {
    let (device, interface) = open_interface(info, interface_number)?;
    let cancel_device = device.clone();

    progress.on_progress(&format!(
        "Connected: {} ({:04x}:{:04x})",
        friendly_name(info),
        info.vendor_id(),
        info.product_id()
    ));

    let mut dfu = dfu_nusb::DfuNusb::open(device, interface, alt)
        .map_err(|e| FlashError::Message(format!("DFU handshake failed: {e}")))?
        .into_sync_dfu();
    if let Some(address) = address {
        dfu.override_address(address);
    }

    let image_bytes = image::load_flat(image_path)?;
    let total = image_bytes.len();
    if total == 0 {
        return Err("Firmware image is empty".into());
    }

    let destination = match address {
        Some(address) => format!("0x{address:08X}"),
        None => format!("alt {alt}"),
    };
    progress.on_stage(
        FlashStage::Erasing,
        &format!("Programming {total} bytes to {destination} (DFU will erase as needed)"),
    );
    progress.on_stage(FlashStage::Writing, "Downloading…");

    let (tx, rx) = mpsc::channel::<usize>();
    dfu.with_progress(move |n| {
        let _ = tx.send(n);
    });

    let outcome = std::thread::scope(|scope| {
        let drain = scope.spawn(|| {
            let mut done = 0u64;
            let mut reset_sent = false;
            for n in rx {
                done += n as u64;
                progress.on_bytes(done, total as u64);
                if progress.cancelled() && !reset_sent {
                    reset_sent = true;
                    progress.on_progress("Cancellation requested — resetting device…");
                    let _ = cancel_device.reset();
                }
            }
        });

        let result = dfu.download(Cursor::new(&image_bytes), total as u32);
        dfu.with_progress(|_| {});
        let _ = drain.join();
        result
    });

    outcome.map_err(|e| {
        if progress.cancelled() {
            FlashError::Cancelled
        } else {
            FlashError::Message(format!("DFU download failed: {e}"))
        }
    })?;

    progress.on_stage(
        FlashStage::Resetting,
        "Download complete; detaching to start firmware",
    );
    // DETACH is best effort; a USB reset is the spec's universal "leave DFU".
    let _ = dfu.detach();
    std::thread::sleep(Duration::from_millis(50));
    let _ = dfu.usb_reset();

    Ok(())
}

fn open_interface(
    info: &nusb::DeviceInfo,
    interface_number: u8,
) -> Result<(nusb::Device, nusb::Interface)> {
    let device = info
        .open()
        .map_err(|e| FlashError::Message(format!("Failed to open USB device: {e}")))?;
    let interface = device.claim_interface(interface_number).map_err(|e| {
        FlashError::Message(format!(
            "Failed to claim DFU interface {interface_number}: {e}"
        ))
    })?;
    Ok((device, interface))
}

fn wait_for_ttys(
    enumerate: &Enumerator,
    usb_serial: &str,
    timeout: Duration,
    poll: Duration,
    progress: &dyn FlashProgress,
) -> Result<Vec<SerialPort>> {
    let mut settle = TtySettle::default();
    poll_until(timeout, poll, progress, || {
        settle.observe(enumerate(), usb_serial)
    })?
    .ok_or_else(|| settle.timeout_error(usb_serial, timeout))
}

/// `Ok(None)` once `timeout` passes without `probe` finding anything.
fn poll_until<T>(
    timeout: Duration,
    poll: Duration,
    progress: &dyn FlashProgress,
    mut probe: impl FnMut() -> Option<T>,
) -> Result<Option<T>> {
    let started = Instant::now();
    loop {
        check_cancel(progress)?;
        if let Some(found) = probe() {
            return Ok(Some(found));
        }
        if started.elapsed() >= timeout {
            return Ok(None);
        }
        std::thread::sleep(poll);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum DfuMode {
    Dfu,
    Runtime,
}

/// DFU 1.1 section 4: interface protocol 1 is the runtime interface, 2 DFU mode.
fn interface_mode(class: u8, subclass: u8, protocol: u8) -> Option<DfuMode> {
    if class != DFU_INTERFACE_CLASS || subclass != DFU_INTERFACE_SUBCLASS {
        return None;
    }
    match protocol {
        1 => Some(DfuMode::Runtime),
        2 => Some(DfuMode::Dfu),
        _ => None,
    }
}

/// The interface to use from `(number, class, subclass, protocol)`, DFU mode first.
fn dfu_interface(interfaces: impl IntoIterator<Item = (u8, u8, u8, u8)>) -> Option<(u8, DfuMode)> {
    interfaces
        .into_iter()
        .filter_map(|(number, class, subclass, protocol)| {
            interface_mode(class, subclass, protocol).map(|mode| (number, mode))
        })
        .min_by_key(|&(_, mode)| mode)
}

/// The device with this serial, in DFU mode if it is listed in both (re-enumerating).
fn find_dfu(usb_serial: &str) -> Result<Option<(nusb::DeviceInfo, u8, DfuMode)>> {
    Ok(enumerate()?
        .filter(|d| identifier(d) == usb_serial)
        .filter_map(|info| {
            let found = dfu_interface(
                info.interfaces()
                    .map(|i| (i.interface_number(), i.class(), i.subclass(), i.protocol())),
            );
            found.map(|(number, mode)| (info, number, mode))
        })
        .min_by_key(|&(_, _, mode)| mode))
}

fn enumerate() -> Result<impl Iterator<Item = nusb::DeviceInfo>> {
    nusb::list_devices().map_err(|e| FlashError::Message(format!("Failed to enumerate USB: {e}")))
}

fn identifier(info: &nusb::DeviceInfo) -> String {
    info.serial_number()
        .map(str::to_string)
        .unwrap_or_else(|| format!("bus{}-dev{}", info.bus_number(), info.device_address()))
}

fn is_dfu(info: &nusb::DeviceInfo) -> bool {
    info.interfaces().any(is_dfu_interface)
}

fn is_dfu_interface(iface: &nusb::InterfaceInfo) -> bool {
    iface.class() == DFU_INTERFACE_CLASS && iface.subclass() == DFU_INTERFACE_SUBCLASS
}

fn is_stm32_bootloader(info: &nusb::DeviceInfo) -> bool {
    info.vendor_id() == STM32_DFU_VID && info.product_id() == STM32_DFU_PID
}

fn manufacturer_for(info: &nusb::DeviceInfo) -> String {
    if is_stm32_bootloader(info) {
        "STM32 DFU".to_string()
    } else {
        "DFU".to_string()
    }
}

fn friendly_name(info: &nusb::DeviceInfo) -> String {
    let manufacturer = info
        .manufacturer_string()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let product = info
        .product_string()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    match (manufacturer, product) {
        (Some(m), Some(p)) => format!("{m} {p}"),
        (Some(m), None) => m.to_string(),
        (None, Some(p)) => p.to_string(),
        (None, None) if is_stm32_bootloader(info) => "STM32 Bootloader".to_string(),
        (None, None) => format!("USB DFU {:04x}:{:04x}", info.vendor_id(), info.product_id()),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    use super::*;
    use crate::progress::LogProgress;

    const DFU: (u8, u8) = (DFU_INTERFACE_CLASS, DFU_INTERFACE_SUBCLASS);

    struct CancelAfter(AtomicUsize);

    impl FlashProgress for CancelAfter {
        fn on_progress(&mut self, _message: &str) {}

        fn cancelled(&self) -> bool {
            self.0
                .try_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_sub(1))
                .is_err()
        }
    }

    fn sequence(snapshots: Vec<Vec<SerialPort>>) -> Enumerator {
        let remaining = Mutex::new(snapshots);
        Arc::new(move || {
            let mut r = remaining.lock().unwrap();
            if r.len() > 1 {
                r.remove(0)
            } else {
                r.first().cloned().unwrap_or_default()
            }
        })
    }

    fn port(path: &str) -> SerialPort {
        SerialPort::new(path, Some("S"), Some(1))
    }

    #[test]
    fn interface_protocol_tells_runtime_from_dfu_mode() {
        assert_eq!(interface_mode(DFU.0, DFU.1, 1), Some(DfuMode::Runtime));
        assert_eq!(interface_mode(DFU.0, DFU.1, 2), Some(DfuMode::Dfu));
        assert_eq!(interface_mode(DFU.0, DFU.1, 0), None);
        assert_eq!(interface_mode(0x02, DFU.1, 2), None);
        assert_eq!(interface_mode(DFU.0, 0x02, 1), None);
    }

    #[test]
    fn dfu_interface_prefers_dfu_mode_and_skips_others() {
        let cdc = (0, 0x02, 0x02, 0x01);
        assert_eq!(dfu_interface([cdc]), None);
        assert_eq!(
            dfu_interface([cdc, (2, DFU.0, DFU.1, 1)]),
            Some((2, DfuMode::Runtime))
        );
        assert_eq!(
            dfu_interface([(2, DFU.0, DFU.1, 1), (0, DFU.0, DFU.1, 2)]),
            Some((0, DfuMode::Dfu))
        );
    }

    #[test]
    fn poll_until_returns_the_first_find() {
        let mut calls = 0;
        let found = poll_until(
            Duration::from_secs(5),
            Duration::ZERO,
            &LogProgress::default(),
            || {
                calls += 1;
                (calls == 3).then_some(calls)
            },
        );
        assert_eq!(found, Ok(Some(3)));
    }

    #[test]
    fn poll_until_gives_up_at_the_timeout() {
        let found: Result<Option<()>> = poll_until(
            Duration::ZERO,
            Duration::ZERO,
            &LogProgress::default(),
            || None,
        );
        assert_eq!(found, Ok(None));
    }

    #[test]
    fn poll_until_honours_cancel() {
        let mut calls = 0;
        let found: Result<Option<()>> = poll_until(
            Duration::from_secs(5),
            Duration::ZERO,
            &CancelAfter(AtomicUsize::new(2)),
            || {
                calls += 1;
                None
            },
        );
        assert_eq!(found, Err(FlashError::Cancelled));
        assert_eq!(calls, 2);
    }

    #[test]
    fn wait_for_ttys_waits_until_the_composite_stops_growing() {
        let enumerate = sequence(vec![
            vec![],
            vec![port("/dev/ttyACM1")],
            vec![port("/dev/ttyACM1"), port("/dev/ttyACM2")],
            vec![port("/dev/ttyACM1"), port("/dev/ttyACM2")],
        ]);
        let ports = wait_for_ttys(
            &enumerate,
            "S",
            Duration::from_secs(5),
            Duration::ZERO,
            &LogProgress::default(),
        )
        .unwrap();
        let paths: Vec<&str> = ports.iter().map(|p| p.path.as_str()).collect();
        assert_eq!(paths, vec!["/dev/ttyACM1", "/dev/ttyACM2"]);
    }

    #[test]
    fn wait_for_ttys_times_out_naming_what_is_attached() {
        let enumerate = sequence(vec![vec![SerialPort::new(
            "/dev/ttyACM0",
            Some("OTHER"),
            None,
        )]]);
        let err = wait_for_ttys(
            &enumerate,
            "S",
            Duration::ZERO,
            Duration::ZERO,
            &LogProgress::default(),
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("/dev/ttyACM0 (OTHER)"), "{err}");
    }

    #[test]
    fn wait_for_ttys_honours_cancel() {
        let enumerate = sequence(vec![vec![]]);
        let outcome = wait_for_ttys(
            &enumerate,
            "S",
            Duration::from_secs(5),
            Duration::ZERO,
            &CancelAfter(AtomicUsize::new(3)),
        );
        assert_eq!(outcome, Err(FlashError::Cancelled));
    }
}
