use std::pin::Pin;
use std::sync::Arc;

use btleplug::api::{Characteristic, Peripheral as _, WriteType};
use btleplug::platform::Peripheral;
use futures_core::Stream;
use tokio::sync::Mutex;
use tracing::debug;
use uuid::Uuid;

use crate::header::HEADER_LEN;
use crate::{BoxFuture, Error, Session, Transport};

/// The mcumgr SMP service, as Zephyr's SMP BLE transport defines it.
pub const SMP_SERVICE_UUID: Uuid = Uuid::from_u128(0x8d53dc1d_1db7_4cd3_868b_8a527460aa84);

/// Written without response with requests, and notifies replies.
pub const SMP_CHARACTERISTIC_UUID: Uuid = Uuid::from_u128(0xda2e7828_fbce_4e01_ae9e_261174997c48);

/// The ATT header of a write command, taken from the MTU.
const ATT_WRITE_HEADER: usize = 3;
/// What a write carries at the minimum ATT MTU of 23.
const MIN_WRITE: usize = 20;

/// Conservative until the device's buffers are known.
const BLE_CHUNK_SIZE: usize = 500;

type Notifications = Pin<Box<dyn Stream<Item = Vec<u8>> + Send>>;

/// SMP over the mcumgr GATT characteristic.
pub struct BleTransport {
    peripheral: Peripheral,
    characteristic: Characteristic,
    max_write: usize,
    rx: Mutex<Rx>,
}

struct Rx {
    notifications: Notifications,
    buf: Vec<u8>,
}

impl BleTransport {
    /// Takes a connected `peripheral` and the SMP characteristic's
    /// notifications, then subscribes to them. The stream ending closes the
    /// transport, and it lives as long as the transport, so it can hold
    /// whatever keeps the link up.
    pub async fn open<S>(peripheral: Peripheral, notifications: S) -> Result<Self, Error>
    where
        S: Stream<Item = Vec<u8>> + Send + 'static,
    {
        peripheral.discover_services().await?;
        let characteristic = peripheral
            .characteristics()
            .into_iter()
            .find(|c| c.uuid == SMP_CHARACTERISTIC_UUID && c.service_uuid == SMP_SERVICE_UUID)
            .ok_or(Error::CharacteristicNotFound)?;
        let mtu = usize::from(peripheral.mtu());
        let max_write = mtu.saturating_sub(ATT_WRITE_HEADER).max(MIN_WRITE);
        peripheral.subscribe(&characteristic).await?;
        debug!(mtu, max_write, "SMP over BLE open");
        Ok(Self {
            peripheral,
            characteristic,
            max_write,
            rx: Mutex::new(Rx {
                notifications: Box::pin(notifications),
                buf: Vec::new(),
            }),
        })
    }
}

impl Transport for BleTransport {
    /// CoreBluetooth drops a write longer than the MTU allows; the device
    /// reassembles the frame by the length in its header.
    fn send(&self, frame: Vec<u8>) -> BoxFuture<'_, Result<(), Error>> {
        Box::pin(async move {
            for piece in frame.chunks(self.max_write) {
                self.peripheral
                    .write(&self.characteristic, piece, WriteType::WithoutResponse)
                    .await?;
            }
            Ok(())
        })
    }

    /// Some platforms split one notification in two, so bytes gather until
    /// they hold a whole frame.
    fn receive(&self) -> BoxFuture<'_, Result<Vec<u8>, Error>> {
        Box::pin(async {
            let mut rx = self.rx.lock().await;
            loop {
                if let Some(frame) = take_frame(&mut rx.buf) {
                    return Ok(frame);
                }
                let next = std::future::poll_fn(|cx| rx.notifications.as_mut().poll_next(cx));
                match next.await {
                    Some(bytes) => rx.buf.extend_from_slice(&bytes),
                    None => return Err(Error::LinkClosed),
                }
            }
        })
    }

    fn is_connected(&self) -> BoxFuture<'_, bool> {
        Box::pin(async { self.peripheral.is_connected().await.unwrap_or(false) })
    }
}

impl Session {
    pub fn ble(transport: BleTransport) -> Self {
        Self::new(Arc::new(transport), BLE_CHUNK_SIZE)
    }
}

fn take_frame(buf: &mut Vec<u8>) -> Option<Vec<u8>> {
    let len = HEADER_LEN + usize::from(u16::from_be_bytes([*buf.get(2)?, *buf.get(3)?]));
    (buf.len() >= len).then(|| buf.drain(..len).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(payload: &[u8]) -> Vec<u8> {
        let mut v = vec![0x03, 0x00];
        v.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        v.extend_from_slice(&[0x00, 0x01, 0x42, 0x00]);
        v.extend_from_slice(payload);
        v
    }

    #[test]
    fn waits_for_a_whole_header() {
        let mut buf = vec![0x03, 0x00, 0x00];
        assert_eq!(take_frame(&mut buf), None);
        assert_eq!(buf.len(), 3);
    }

    #[test]
    fn waits_for_the_whole_payload() {
        let whole = frame(&[0xaa; 5]);
        let mut buf = whole[..HEADER_LEN + 2].to_vec();
        assert_eq!(take_frame(&mut buf), None);
        buf.extend_from_slice(&whole[HEADER_LEN + 2..]);
        assert_eq!(take_frame(&mut buf), Some(whole));
        assert!(buf.is_empty());
    }

    #[test]
    fn leaves_the_next_frame_behind() {
        let mut buf = frame(&[0xaa; 3]);
        buf.extend_from_slice(&frame(&[]));
        assert_eq!(take_frame(&mut buf), Some(frame(&[0xaa; 3])));
        assert_eq!(take_frame(&mut buf), Some(frame(&[])));
        assert!(buf.is_empty());
    }
}
