//! A one-shot browse for `_framelink._tcp`, for a caller with no use for a
//! running [`Discovery`](super::Discovery).

use std::net::SocketAddr;
use std::time::Duration;

use wslib_mdns::{BrowseEvent, InProcess, Options};

use crate::Error;

#[derive(Debug, Clone)]
pub struct FrameLinkDevice {
    pub name: String,
    pub addr: SocketAddr,
}

/// Every FrameLink device resolved within `timeout`, once per IPv4 address.
pub async fn discover(timeout: Duration) -> Result<Vec<FrameLinkDevice>, Error> {
    let responder = InProcess::new(Options::default())?;
    let mut browse = responder.browse(&"_framelink._tcp".parse().expect("a valid service type"))?;
    let deadline = tokio::time::Instant::now() + timeout;
    let mut devices: Vec<FrameLinkDevice> = Vec::new();
    while let Ok(Some(event)) = tokio::time::timeout_at(deadline, browse.next()).await {
        let BrowseEvent::Resolved(found) = event else {
            continue;
        };
        let name = found
            .instance
            .as_str()
            .split('.')
            .next()
            .unwrap_or_default();
        for ip in found.addrs.iter().filter(|a| a.is_ipv4()) {
            let addr = SocketAddr::new(*ip, found.port);
            if !devices.iter().any(|d| d.addr == addr) {
                devices.push(FrameLinkDevice {
                    name: name.to_string(),
                    addr,
                });
            }
        }
    }
    Ok(devices)
}
