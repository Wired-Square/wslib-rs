use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

use btleplug::api::{CharPropFlags, Characteristic, Peripheral as _, WriteType};
use btleplug::platform::Peripheral;
use futures_util::Stream;
use tokio::sync::mpsc;
use tracing::{debug, warn};
use uuid::Uuid;

use super::types::{
    ProvisioningEvent, ProvisioningStatus, WifiCredentials, WifiSecurity, WifiStatus,
};
use super::uuids::{
    CHAR_CONTROL_UUID, CHAR_IP_ADDR_UUID, CHAR_PASSPHRASE_UUID, CHAR_SECURITY_UUID, CHAR_SSID_UUID,
    CHAR_STATUS_UUID, CONTROL_DELETE_ALL, CONTROL_DISCONNECT, CONTROL_SAVE_CONNECT,
};
use crate::Error;
use crate::ble::WIFI_PROV_SERVICE_UUID;
use crate::ble::notify_dispatcher::NotifyDispatcher;
use crate::discovery::ble::PeripheralLease;
use crate::runtime::ble_runtime;

const READ_TIMEOUT: Duration = Duration::from_secs(5);

/// How long to wait for an address once the device reports `Connected`.
const IP_GRACE_AFTER_CONNECTED: Duration = Duration::from_secs(5);

/// A BLE link to a device's provisioning service. The link is shared with any
/// other session on the device and closes when the last one drops.
pub struct WifiProvSession {
    lease: Arc<PeripheralLease>,
    peripheral: Peripheral,
    chars: ResolvedCharacteristics,
}

#[derive(Clone)]
struct ResolvedCharacteristics {
    ssid: Characteristic,
    passphrase: Characteristic,
    security: Characteristic,
    control: Characteristic,
    status: Characteristic,
    ip_addr: Characteristic,
}

impl ResolvedCharacteristics {
    async fn resolve(peripheral: &Peripheral) -> Result<Self, Error> {
        peripheral.discover_services().await?;
        let services = peripheral.services();
        let service = services
            .iter()
            .find(|s| s.uuid == WIFI_PROV_SERVICE_UUID)
            .ok_or(Error::GattServiceMissing(WIFI_PROV_SERVICE_UUID))?;
        let find = |uuid: Uuid| {
            service
                .characteristics
                .iter()
                .find(|c| c.uuid == uuid)
                .cloned()
                .ok_or(Error::CharacteristicNotFound(uuid))
        };
        Ok(Self {
            ssid: find(CHAR_SSID_UUID)?,
            passphrase: find(CHAR_PASSPHRASE_UUID)?,
            security: find(CHAR_SECURITY_UUID)?,
            control: find(CHAR_CONTROL_UUID)?,
            status: find(CHAR_STATUS_UUID)?,
            ip_addr: find(CHAR_IP_ADDR_UUID)?,
        })
    }
}

struct ProvNotifyRxs {
    status: mpsc::Receiver<Result<Vec<u8>, String>>,
    ip_addr: mpsc::Receiver<Result<Vec<u8>, String>>,
}

pub(crate) async fn open_session(lease: Arc<PeripheralLease>) -> Result<WifiProvSession, Error> {
    let peripheral = lease.ensure_ready().await?.clone();
    let chars = ResolvedCharacteristics::resolve(&peripheral).await?;
    debug!("wifi-prov session opened");
    Ok(WifiProvSession {
        lease,
        peripheral,
        chars,
    })
}

impl WifiProvSession {
    /// Each read has five seconds, since a device can stall on a read after a
    /// write; an unreadable status is `Disconnected`.
    pub async fn status(&self) -> Result<ProvisioningStatus, Error> {
        let ssid = if self.chars.ssid.properties.contains(CharPropFlags::READ) {
            read_with_timeout(&self.peripheral, &self.chars.ssid)
                .await
                .map(|bytes| String::from_utf8_lossy(&bytes).to_string())
                .filter(|s| !s.is_empty())
        } else {
            None
        };

        let security = if self.chars.security.properties.contains(CharPropFlags::READ) {
            read_with_timeout(&self.peripheral, &self.chars.security)
                .await
                .and_then(|b| b.first().copied())
                .map(WifiSecurity::from_byte)
        } else {
            None
        };

        let status = if self.chars.status.properties.contains(CharPropFlags::READ) {
            read_with_timeout(&self.peripheral, &self.chars.status)
                .await
                .and_then(|b| b.first().copied())
                .map(WifiStatus::from_byte)
                .unwrap_or(WifiStatus::Disconnected)
        } else {
            WifiStatus::Disconnected
        };

        let ip_address = if self.chars.ip_addr.properties.contains(CharPropFlags::READ) {
            read_with_timeout(&self.peripheral, &self.chars.ip_addr)
                .await
                .and_then(decode_ipv4)
        } else {
            None
        };

        Ok(ProvisioningStatus {
            ssid,
            security,
            status,
            ip_address,
        })
    }

    /// Saves `creds` and connects, streaming the device's progress. The
    /// stream ends once connected with an address, or five seconds after
    /// connecting without one, or with [`Error::WifiProvFailed`] after
    /// `Error`. A link that drops once the credentials are saved also ends
    /// it, without error: the device may reset to connect.
    pub fn provision(
        &self,
        creds: WifiCredentials,
    ) -> impl Stream<Item = Result<ProvisioningEvent, Error>> + Send + 'static {
        let chars = self.chars.clone();
        let peripheral = self.peripheral.clone();
        let (tx, rx) = mpsc::channel(16);

        ble_runtime().spawn(async move {
            macro_rules! emit {
                ($evt:expr) => {
                    if tx.send($evt).await.is_err() {
                        debug!("consumer dropped provision stream; aborting watcher");
                        return;
                    }
                };
            }

            // Staging writes raise no notifications, so they can precede the
            // subscription.
            if let Err(e) = write_char(&peripheral, &chars.ssid, creds.ssid.as_bytes()).await {
                emit!(Err(e));
                return;
            }
            if let Some(psk) = creds.passphrase.as_deref().filter(|s| !s.is_empty())
                && let Err(e) = write_char(&peripheral, &chars.passphrase, psk.as_bytes()).await
            {
                emit!(Err(e));
                return;
            }
            if let Err(e) = write_char(&peripheral, &chars.security, &[creds.security.byte()]).await
            {
                emit!(Err(e));
                return;
            }

            // Subscribed before SAVE_CONNECT, which raises `Connecting` at once.
            let (_dispatcher, mut notifs) = match start_notify_multiplex(&peripheral, &chars).await
            {
                Ok(n) => n,
                Err(e) => {
                    emit!(Err(e));
                    return;
                }
            };

            if let Err(e) = write_char(&peripheral, &chars.control, &[CONTROL_SAVE_CONNECT]).await {
                emit!(Err(e));
                return;
            }

            let mut got_ip = false;
            let mut connected_at: Option<tokio::time::Instant> = None;

            loop {
                let (uuid, result) = match connected_at {
                    None => {
                        let Some(item) = recv_either(&mut notifs).await else {
                            return;
                        };
                        item
                    }
                    Some(when) => {
                        let remaining = IP_GRACE_AFTER_CONNECTED.saturating_sub(when.elapsed());
                        match tokio::time::timeout(remaining, recv_either(&mut notifs)).await {
                            Ok(Some(item)) => item,
                            Ok(None) | Err(_) => return,
                        }
                    }
                };

                let value = match result {
                    Ok(v) => v,
                    Err(e) => {
                        emit!(Err(Error::NotifySubscribe { uuid, cause: e }));
                        return;
                    }
                };

                if uuid == CHAR_STATUS_UUID {
                    let code = value.first().copied().unwrap_or(0);
                    let status = WifiStatus::from_byte(code);
                    emit!(Ok(ProvisioningEvent::Status { status }));
                    match status {
                        WifiStatus::Error => {
                            emit!(Err(Error::WifiProvFailed));
                            return;
                        }
                        WifiStatus::Connected => {
                            if got_ip {
                                return;
                            }
                            connected_at = Some(tokio::time::Instant::now());
                        }
                        _ => {}
                    }
                } else if uuid == CHAR_IP_ADDR_UUID
                    && let Some(addr) = decode_ipv4(value)
                {
                    emit!(Ok(ProvisioningEvent::IpAddress { address: addr }));
                    got_ip = true;
                    if connected_at.is_some() {
                        return;
                    }
                }
            }
        });

        receiver_stream(rx)
    }

    /// The device's status and address as they change, until the link drops.
    pub fn watch(&self) -> impl Stream<Item = Result<ProvisioningEvent, Error>> + Send + 'static {
        let chars = self.chars.clone();
        let peripheral = self.peripheral.clone();
        let (tx, rx) = mpsc::channel(16);

        ble_runtime().spawn(async move {
            macro_rules! emit {
                ($evt:expr) => {
                    if tx.send($evt).await.is_err() {
                        debug!("consumer dropped watch stream");
                        return;
                    }
                };
            }

            let (_dispatcher, mut notifs) = match start_notify_multiplex(&peripheral, &chars).await
            {
                Ok(n) => n,
                Err(e) => {
                    emit!(Err(e));
                    return;
                }
            };

            while let Some((uuid, result)) = recv_either(&mut notifs).await {
                let value = match result {
                    Ok(v) => v,
                    Err(e) => {
                        emit!(Err(Error::NotifySubscribe { uuid, cause: e }));
                        return;
                    }
                };
                if uuid == CHAR_STATUS_UUID {
                    let code = value.first().copied().unwrap_or(0);
                    emit!(Ok(ProvisioningEvent::Status {
                        status: WifiStatus::from_byte(code),
                    }));
                } else if uuid == CHAR_IP_ADDR_UUID
                    && let Some(addr) = decode_ipv4(value)
                {
                    emit!(Ok(ProvisioningEvent::IpAddress { address: addr }));
                }
            }
            emit!(Err(Error::BleLinkDropped));
        });

        receiver_stream(rx)
    }

    /// Forgets every stored credential.
    pub async fn forget(&self) -> Result<(), Error> {
        write_char(&self.peripheral, &self.chars.control, &[CONTROL_DELETE_ALL]).await
    }

    pub async fn is_connected(&self) -> bool {
        self.lease.is_connected().await
    }

    /// Leaves the Wi-Fi network, keeping its credentials.
    pub async fn disconnect(&self) -> Result<(), Error> {
        write_char(&self.peripheral, &self.chars.control, &[CONTROL_DISCONNECT]).await
    }
}

fn receiver_stream<T: Send + 'static>(
    rx: mpsc::Receiver<T>,
) -> impl Stream<Item = T> + Send + 'static {
    futures_util::stream::unfold(rx, |mut rx| async move {
        rx.recv().await.map(|item| (item, rx))
    })
}

async fn write_char(
    peripheral: &Peripheral,
    char: &Characteristic,
    bytes: &[u8],
) -> Result<(), Error> {
    peripheral
        .write(char, bytes, WriteType::WithResponse)
        .await
        .map_err(|source| Error::CharacteristicWrite {
            uuid: char.uuid,
            source,
        })
}

async fn read_with_timeout(peripheral: &Peripheral, char: &Characteristic) -> Option<Vec<u8>> {
    match tokio::time::timeout(READ_TIMEOUT, peripheral.read(char)).await {
        Ok(Ok(bytes)) if !bytes.is_empty() => Some(bytes),
        Ok(Ok(_)) => None,
        Ok(Err(e)) => {
            warn!(uuid = %char.uuid, "read failed: {e}");
            None
        }
        Err(_) => {
            warn!(uuid = %char.uuid, "read timed out after {:?}", READ_TIMEOUT);
            None
        }
    }
}

/// The dispatcher routes only while it lives.
async fn start_notify_multiplex(
    peripheral: &Peripheral,
    chars: &ResolvedCharacteristics,
) -> Result<(NotifyDispatcher, ProvNotifyRxs), Error> {
    if !chars.status.properties.contains(CharPropFlags::NOTIFY) {
        return Err(Error::NotifySubscribe {
            uuid: CHAR_STATUS_UUID,
            cause: "characteristic does not support NOTIFY".into(),
        });
    }
    if !chars.ip_addr.properties.contains(CharPropFlags::NOTIFY) {
        return Err(Error::NotifySubscribe {
            uuid: CHAR_IP_ADDR_UUID,
            cause: "characteristic does not support NOTIFY".into(),
        });
    }

    peripheral
        .subscribe(&chars.status)
        .await
        .map_err(|e| Error::NotifySubscribe {
            uuid: CHAR_STATUS_UUID,
            cause: e.to_string(),
        })?;
    peripheral
        .subscribe(&chars.ip_addr)
        .await
        .map_err(|e| Error::NotifySubscribe {
            uuid: CHAR_IP_ADDR_UUID,
            cause: e.to_string(),
        })?;

    let dispatcher =
        NotifyDispatcher::start(peripheral)
            .await
            .map_err(|e| Error::NotifySubscribe {
                uuid: CHAR_STATUS_UUID,
                cause: e.to_string(),
            })?;
    let rx_status = dispatcher.subscribe(CHAR_STATUS_UUID).await;
    let rx_ip = dispatcher.subscribe(CHAR_IP_ADDR_UUID).await;

    Ok((
        dispatcher,
        ProvNotifyRxs {
            status: rx_status,
            ip_addr: rx_ip,
        },
    ))
}

async fn recv_either(rxs: &mut ProvNotifyRxs) -> Option<(Uuid, Result<Vec<u8>, String>)> {
    tokio::select! {
        biased;
        item = rxs.status.recv() => item.map(|v| (CHAR_STATUS_UUID, v)),
        item = rxs.ip_addr.recv() => item.map(|v| (CHAR_IP_ADDR_UUID, v)),
    }
}

fn decode_ipv4<B: AsRef<[u8]>>(bytes: B) -> Option<Ipv4Addr> {
    let b = bytes.as_ref();
    if b.len() < 4 {
        return None;
    }
    let addr = Ipv4Addr::new(b[0], b[1], b[2], b[3]);
    if addr.is_unspecified() {
        None
    } else {
        Some(addr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_ipv4_handles_unset() {
        assert_eq!(decode_ipv4([0, 0, 0, 0]), None);
        assert_eq!(
            decode_ipv4([192, 168, 1, 42]),
            Some(Ipv4Addr::new(192, 168, 1, 42))
        );
        // Firmware may pad to the MTU.
        assert_eq!(
            decode_ipv4([192, 168, 1, 42, 0, 0, 0, 0]),
            Some(Ipv4Addr::new(192, 168, 1, 42))
        );
    }

    #[test]
    fn decode_ipv4_rejects_short() {
        assert_eq!(decode_ipv4([1, 2, 3]), None);
        assert_eq!(decode_ipv4([] as [u8; 0]), None);
    }
}
