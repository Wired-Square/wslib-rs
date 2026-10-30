use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use btleplug::api::{Characteristic, Peripheral as _, WriteType};
use btleplug::platform::Peripheral;
use futures_core::Stream;
use tokio::sync::Mutex;
use tracing::debug;
use uuid::Uuid;

use crate::header::{HEADER_LEN, Header, Op};
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

/// A frame's notifications come back to back; a gap this long means one was
/// lost.
const REASSEMBLY_TIMEOUT: Duration = Duration::from_secs(2);

type Notifications = Pin<Box<dyn Stream<Item = Vec<u8>> + Send>>;

/// SMP over the mcumgr GATT characteristic.
pub struct BleTransport {
    peripheral: Peripheral,
    characteristic: Characteristic,
    max_write: usize,
    tx: Mutex<()>,
    rx: Mutex<Rx>,
}

struct Rx {
    notifications: Notifications,
    frames: Reassembly,
    reassembly_timeout: Duration,
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
            tx: Mutex::new(()),
            rx: Mutex::new(Rx::new(Box::pin(notifications), REASSEMBLY_TIMEOUT)),
        })
    }
}

impl Transport for BleTransport {
    /// CoreBluetooth drops a write longer than the MTU allows; the device
    /// reassembles the frame by the length in its header, so one frame's
    /// pieces go out before the next frame's.
    fn send(&self, frame: Vec<u8>) -> BoxFuture<'_, Result<(), Error>> {
        Box::pin(async move {
            let _one_frame_at_a_time = self.tx.lock().await;
            for piece in frame.chunks(self.max_write) {
                self.peripheral
                    .write(&self.characteristic, piece, WriteType::WithoutResponse)
                    .await?;
            }
            Ok(())
        })
    }

    fn receive(&self) -> BoxFuture<'_, Result<Vec<u8>, Error>> {
        Box::pin(async { self.rx.lock().await.next_frame().await })
    }

    fn is_connected(&self) -> BoxFuture<'_, bool> {
        Box::pin(async { self.peripheral.is_connected().await.unwrap_or(false) })
    }
}

impl Session {
    /// Must be called within a tokio runtime, as [`Session::new`] is.
    pub fn ble(transport: BleTransport) -> Self {
        Self::new(Arc::new(transport), BLE_CHUNK_SIZE)
    }
}

impl Rx {
    fn new(notifications: Notifications, reassembly_timeout: Duration) -> Self {
        Self {
            notifications,
            frames: Reassembly::default(),
            reassembly_timeout,
        }
    }

    /// Some platforms split one notification in two, so bytes gather until
    /// they hold a whole frame; a frame left unfinished is dropped.
    async fn next_frame(&mut self) -> Result<Vec<u8>, Error> {
        loop {
            if let Some(frame) = self.frames.take() {
                return Ok(frame);
            }
            let next = std::future::poll_fn(|cx| self.notifications.as_mut().poll_next(cx));
            let bytes = if self.frames.buf.is_empty() {
                next.await
            } else if let Ok(bytes) = tokio::time::timeout(self.reassembly_timeout, next).await {
                bytes
            } else {
                debug!("SMP over BLE: dropping an unfinished frame");
                self.frames = Reassembly::default();
                continue;
            };
            match bytes {
                Some(bytes) => self.frames.push(&bytes),
                None => return Err(Error::LinkClosed),
            }
        }
    }
}

/// A frame starts at the start of a notification, which is where a lost or
/// stray notification lets it pick up again.
#[derive(Default)]
struct Reassembly {
    buf: Vec<u8>,
    latest_notification_at: usize,
}

impl Reassembly {
    /// A notification too long to finish the frame in hand, that opens a
    /// reply of its own, means that frame lost its tail.
    fn push(&mut self, notification: &[u8]) {
        if self.still_needs().is_some_and(|n| notification.len() > n) && opens_a_reply(notification)
        {
            debug!(
                dropped = self.buf.len(),
                "SMP over BLE: a reply began before the last was whole"
            );
            self.buf.clear();
        }
        self.latest_notification_at = self.buf.len();
        self.buf.extend_from_slice(notification);
    }

    fn still_needs(&self) -> Option<usize> {
        let header = Header::decode(&self.buf).ok()?;
        (HEADER_LEN + usize::from(header.len))
            .checked_sub(self.buf.len())
            .filter(|&n| n > 0)
    }

    fn take(&mut self) -> Option<Vec<u8>> {
        loop {
            if self.buf.len() < HEADER_LEN {
                return None;
            }
            match Header::decode(&self.buf) {
                Ok(header) if matches!(header.op, Op::ReadResponse | Op::WriteResponse) => {
                    let len = HEADER_LEN + usize::from(header.len);
                    if self.buf.len() < len {
                        return None;
                    }
                    self.latest_notification_at = self.latest_notification_at.saturating_sub(len);
                    return Some(self.buf.drain(..len).collect());
                }
                _ => {
                    let resync_at = match self.latest_notification_at {
                        0 => self.buf.len(),
                        at => at,
                    };
                    debug!(
                        dropped = resync_at,
                        "SMP over BLE: bytes that start no reply"
                    );
                    self.buf.drain(..resync_at);
                    self.latest_notification_at = 0;
                }
            }
        }
    }
}

/// A response header with its reserved bits clear, then a CBOR map, as
/// every SMP payload is.
fn opens_a_reply(notification: &[u8]) -> bool {
    Header::decode(notification).is_ok_and(|h| matches!(h.op, Op::ReadResponse | Op::WriteResponse))
        && notification[0] >> 5 == 0
        && notification
            .get(HEADER_LEN)
            .is_none_or(|&first| first >> 5 == CBOR_MAP)
}

const CBOR_MAP: u8 = 5;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::Events;
    use tokio::sync::mpsc;

    fn frame(payload: &[u8]) -> Vec<u8> {
        let mut v = vec![0x03, 0x00];
        v.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        v.extend_from_slice(&[0x00, 0x01, 0x42, 0x00]);
        v.extend_from_slice(payload);
        v
    }

    fn reassembly_of(notifications: &[&[u8]]) -> Reassembly {
        let mut frames = Reassembly::default();
        notifications.iter().for_each(|n| frames.push(n));
        frames
    }

    #[test]
    fn waits_for_a_whole_header() {
        let mut frames = reassembly_of(&[&[0x03, 0x00, 0x00]]);
        assert_eq!(frames.take(), None);
        assert_eq!(frames.buf.len(), 3);
    }

    #[test]
    fn waits_for_the_whole_payload() {
        let whole = frame(&[0xaa; 5]);
        let mut frames = reassembly_of(&[&whole[..HEADER_LEN + 2]]);
        assert_eq!(frames.take(), None);
        frames.push(&whole[HEADER_LEN + 2..]);
        assert_eq!(frames.take(), Some(whole));
        assert!(frames.buf.is_empty());
    }

    #[test]
    fn leaves_the_next_frame_behind() {
        let mut frames = reassembly_of(&[&[frame(&[0xaa; 3]), frame(&[])].concat()]);
        assert_eq!(frames.take(), Some(frame(&[0xaa; 3])));
        assert_eq!(frames.take(), Some(frame(&[])));
        assert!(frames.buf.is_empty());
    }

    #[test]
    fn a_stray_fragment_before_a_frame_is_dropped() {
        let good = frame(&[0xbb; 4]);
        let mut frames = reassembly_of(&[&[0xaa; 5], &good]);
        assert_eq!(frames.take(), Some(good));
        assert!(frames.buf.is_empty());
    }

    #[test]
    fn a_notification_that_starts_no_reply_is_dropped() {
        let mut frames = reassembly_of(&[&[0x02; HEADER_LEN + 4]]);
        assert_eq!(frames.take(), None);
        assert!(frames.buf.is_empty());
    }

    #[test]
    fn a_reply_after_one_that_lost_its_tail_is_not_glued_to_it() {
        let lost_its_tail = frame(&[0xa1; 10]);
        let next = frame(&[0xa1, 0x61, b'x', 0x01]);
        let mut frames = reassembly_of(&[&lost_its_tail[..10], &next]);
        assert_eq!(frames.take(), Some(next));
        assert!(frames.buf.is_empty());
    }

    #[test]
    fn a_continuation_that_looks_like_a_header_still_finishes_its_frame() {
        let whole = frame(&[
            0xaa, 0xbb, 0x03, 0x00, 0x00, 0x04, 0x00, 0x01, 0x42, 0x00, 0xa0,
        ]);
        let mut frames = reassembly_of(&[&whole[..HEADER_LEN + 2], &whole[HEADER_LEN + 2..]]);
        assert_eq!(frames.take(), Some(whole));
    }

    #[tokio::test]
    async fn a_frame_left_unfinished_gives_way_to_the_next() {
        const TIMEOUT: Duration = Duration::from_millis(50);
        let (tx, rx) = mpsc::channel(4);
        let mut rx = Rx::new(Box::pin(Events(rx)), TIMEOUT);
        let lost_its_tail = frame(&[0xaa; 8]);
        let good = frame(&[0xbb; 4]);
        tx.send(lost_its_tail[..HEADER_LEN + 2].to_vec())
            .await
            .unwrap();
        let late = async {
            tokio::time::sleep(TIMEOUT * 3).await;
            tx.send(good.clone()).await.unwrap();
        };

        let (received, ()) = tokio::join!(rx.next_frame(), late);

        assert_eq!(received.unwrap(), good);
    }
}
