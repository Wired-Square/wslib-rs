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
use std::time::Duration;

use crate::error::{FlashError, Result};
use crate::image;
use crate::progress::{FlashProgress, FlashStage};

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

    let device = info
        .open()
        .map_err(|e| FlashError::Message(format!("Failed to open USB device: {e}")))?;
    let cancel_device = device.clone();
    let interface = device.claim_interface(interface_number).map_err(|e| {
        FlashError::Message(format!(
            "Failed to claim DFU interface {interface_number}: {e}"
        ))
    })?;

    progress.on_progress(&format!(
        "Connected: {} ({:04x}:{:04x})",
        friendly_name(&info),
        info.vendor_id(),
        info.product_id()
    ));

    let mut dfu = dfu_nusb::DfuNusb::open(device, interface, 0)
        .map_err(|e| FlashError::Message(format!("DFU handshake failed: {e}")))?
        .into_sync_dfu();
    dfu.override_address(address);

    let image_bytes = image::load_flat(image_path)?;
    let total = image_bytes.len();
    if total == 0 {
        return Err("Firmware image is empty".into());
    }

    progress.on_stage(
        FlashStage::Erasing,
        &format!("Programming {total} bytes to 0x{address:08X} (DFU will erase as needed)"),
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
