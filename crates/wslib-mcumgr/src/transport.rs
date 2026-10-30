use std::future::Future;
use std::pin::Pin;

use crate::Error;

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Carries whole SMP frames to and from a device. A session sends and
/// receives from separate tasks at once, so both take `&self`.
pub trait Transport: Send + Sync {
    fn send(&self, frame: Vec<u8>) -> BoxFuture<'_, Result<(), Error>>;

    /// The next whole frame from the device.
    fn receive(&self) -> BoxFuture<'_, Result<Vec<u8>, Error>>;

    /// How many upload chunks may await their reply at once. A transport that
    /// drops what the device has no room for, as UDP does, returns 1.
    fn max_in_flight(&self) -> usize {
        usize::MAX
    }

    fn is_connected(&self) -> BoxFuture<'_, bool> {
        Box::pin(async { true })
    }
}
