//! A peripheral's one notification stream, routed to a channel per
//! characteristic. The caller subscribes to each characteristic itself.

use std::collections::HashMap;
use std::sync::Arc;

use btleplug::api::{Peripheral as _, ValueNotification};
use btleplug::platform::Peripheral;
use futures_util::{Stream, StreamExt};
use tokio::sync::{Mutex, mpsc};
use tokio::task::JoinHandle;
use tracing::{debug, trace, warn};
use uuid::Uuid;

const SUBSCRIBER_CHANNEL_DEPTH: usize = 16;

type Routes = Arc<Mutex<HashMap<Uuid, mpsc::Sender<Result<Vec<u8>, String>>>>>;

pub(crate) struct NotifyDispatcher {
    routes: Routes,
    handle: JoinHandle<()>,
}

impl NotifyDispatcher {
    pub(crate) async fn start(peripheral: &Peripheral) -> Result<Self, btleplug::Error> {
        let stream = peripheral.notifications().await?;
        Ok(Self::from_stream(stream))
    }

    pub(crate) fn from_stream<S>(stream: S) -> Self
    where
        S: Stream<Item = ValueNotification> + Send + Unpin + 'static,
    {
        let routes: Routes = Arc::new(Mutex::new(HashMap::new()));
        let routes_task = routes.clone();
        let handle = tokio::spawn(async move {
            let mut stream = stream;
            while let Some(notification) = stream.next().await {
                let guard = routes_task.lock().await;
                if let Some(tx) = guard.get(&notification.uuid) {
                    if tx.try_send(Ok(notification.value)).is_err() {
                        debug!(uuid = %notification.uuid, "subscriber channel full or closed; dropping payload");
                    }
                } else {
                    trace!(uuid = %notification.uuid, "no subscriber for notification UUID");
                }
            }
            warn!("btleplug notifications stream ended");
            let guard = routes_task.lock().await;
            for (uuid, tx) in guard.iter() {
                if tx
                    .try_send(Err("notifications stream ended".into()))
                    .is_err()
                {
                    debug!(uuid = %uuid, "subscriber channel full at stream end; stream-end error dropped");
                }
            }
        });
        Self { routes, handle }
    }

    pub(crate) async fn subscribe(&self, uuid: Uuid) -> mpsc::Receiver<Result<Vec<u8>, String>> {
        let (tx, rx) = mpsc::channel(SUBSCRIBER_CHANNEL_DEPTH);
        self.routes.lock().await.insert(uuid, tx);
        rx
    }

    #[cfg(test)]
    pub(crate) async fn unsubscribe(&self, uuid: &Uuid) {
        self.routes.lock().await.remove(uuid);
    }
}

impl Drop for NotifyDispatcher {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use btleplug::api::ValueNotification;
    use tokio::sync::mpsc;
    use uuid::{Uuid, uuid};

    const UUID_A: Uuid = uuid!("00000000-0000-0000-0000-00000000000a");
    const UUID_B: Uuid = uuid!("00000000-0000-0000-0000-00000000000b");
    const IGNORED_SVC_UUID: Uuid = Uuid::nil();

    fn make_dispatcher() -> (NotifyDispatcher, mpsc::Sender<ValueNotification>) {
        let (tx, rx) = mpsc::channel::<ValueNotification>(8);
        let stream =
            futures_util::stream::unfold(
                rx,
                |mut rx| async move { rx.recv().await.map(|n| (n, rx)) },
            );
        (NotifyDispatcher::from_stream(Box::pin(stream)), tx)
    }

    #[tokio::test]
    async fn routes_notification_to_matching_subscriber() {
        let (dispatcher, source) = make_dispatcher();
        let mut sub = dispatcher.subscribe(UUID_A).await;

        source
            .send(ValueNotification {
                uuid: UUID_A,
                service_uuid: IGNORED_SVC_UUID,
                value: vec![1, 2, 3],
            })
            .await
            .unwrap();

        let received = sub.recv().await.expect("subscriber channel closed");
        assert_eq!(received.unwrap(), vec![1, 2, 3]);
    }

    #[tokio::test]
    async fn drops_notification_with_no_subscriber() {
        let (dispatcher, source) = make_dispatcher();
        let mut sub = dispatcher.subscribe(UUID_A).await;

        source
            .send(ValueNotification {
                uuid: UUID_B,
                service_uuid: IGNORED_SVC_UUID,
                value: vec![9],
            })
            .await
            .unwrap();
        source
            .send(ValueNotification {
                uuid: UUID_A,
                service_uuid: IGNORED_SVC_UUID,
                value: vec![1],
            })
            .await
            .unwrap();

        let received = sub.recv().await.expect("subscriber channel closed");
        assert_eq!(received.unwrap(), vec![1]);
    }

    #[tokio::test]
    async fn signals_stream_end_to_subscribers() {
        let (dispatcher, source) = make_dispatcher();
        let mut sub = dispatcher.subscribe(UUID_A).await;

        drop(source);

        let received = sub.recv().await.expect("subscriber channel closed");
        assert!(
            received.is_err(),
            "expected Err on stream end, got {received:?}"
        );
    }

    #[tokio::test]
    async fn unsubscribe_stops_routing() {
        let (dispatcher, source) = make_dispatcher();
        let mut sub_a = dispatcher.subscribe(UUID_A).await;
        let mut sub_b = dispatcher.subscribe(UUID_B).await;
        dispatcher.unsubscribe(&UUID_A).await;

        source
            .send(ValueNotification {
                uuid: UUID_A,
                service_uuid: IGNORED_SVC_UUID,
                value: vec![1],
            })
            .await
            .unwrap();
        source
            .send(ValueNotification {
                uuid: UUID_B,
                service_uuid: IGNORED_SVC_UUID,
                value: vec![2],
            })
            .await
            .unwrap();

        // UUID_B's arrival proves UUID_A's was routed first.
        let received_b = sub_b.recv().await.expect("UUID_B subscriber closed");
        assert_eq!(received_b.unwrap(), vec![2]);
        assert!(
            sub_a.try_recv().is_err(),
            "UUID_A should have been dropped after unsubscribe"
        );
    }
}
