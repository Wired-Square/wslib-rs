//! A `broadcast` channel as a server-sent event feed in the shape the kit's `useFeed` reads.
//!
//! **The heartbeat is a named event carrying data, not an SSE comment**: a comment
//! fires nothing in a browser, and a browser discards an event with empty `data:`.

use std::convert::Infallible;
use std::time::Duration;

use axum::response::sse::{Event, KeepAlive, Sse};
use futures_util::{Stream, StreamExt};
use serde::Serialize;
use tokio::sync::broadcast;
use tokio::sync::broadcast::error::RecvError;
use tokio_util::sync::CancellationToken;
use wslib_appliance_types::log::FEED_HEARTBEAT_S;

/// Each message on `rx` as an event called `name`, its data `W`'s JSON; one that
/// does not serialise is logged and skipped. A receiver that fell behind skips
/// to the oldest message still held, and ending the channel ends the stream.
pub fn feed<T, W>(
    rx: broadcast::Receiver<T>,
    name: &'static str,
) -> impl Stream<Item = Result<Event, Infallible>> + Send + 'static
where
    T: Clone + Send + 'static,
    W: Serialize + From<T> + 'static,
{
    futures_util::stream::unfold(rx, move |mut rx| async move {
        loop {
            match rx.recv().await {
                Ok(message) => match Event::default().event(name).json_data(W::from(message)) {
                    Ok(event) => return Some((Ok(event), rx)),
                    Err(e) => {
                        tracing::warn!(feed = name, error = %e, "could not serialise an event")
                    }
                },
                Err(RecvError::Lagged(_)) => {}
                Err(RecvError::Closed) => return None,
            }
        }
    })
}

/// A session is checked only when the feed opens, so this bounds how long a revoked one reads.
const FEED_LIFETIME: Duration = Duration::from_secs(5 * 60);

/// `stream` as a response, with a `heartbeat` first and every [`FEED_HEARTBEAT_S`]
/// seconds idle, ended on `stop` or after five minutes. The first heartbeat gets
/// the head past a proxy that holds it until the first body byte.
pub fn sse(
    stream: impl Stream<Item = Result<Event, Infallible>> + Send + 'static,
    stop: CancellationToken,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let first = futures_util::stream::once(async { Ok(heartbeat()) });
    let over = stop.run_until_cancelled_owned(tokio::time::sleep(FEED_LIFETIME));
    Sse::new(first.chain(stream).take_until(over)).keep_alive(
        KeepAlive::new()
            .interval(Duration::from_secs(FEED_HEARTBEAT_S))
            .event(heartbeat()),
    )
}

fn heartbeat() -> Event {
    Event::default().event("heartbeat").data("ok")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::first_frame;

    #[derive(Serialize)]
    struct Doubled(u32);

    impl From<u32> for Doubled {
        fn from(n: u32) -> Self {
            Self(n * 2)
        }
    }

    #[tokio::test]
    async fn each_message_is_a_named_event_of_its_wire_type() {
        let (tx, rx) = broadcast::channel(4);
        let mut stream = std::pin::pin!(feed::<u32, Doubled>(rx, "tick"));
        tx.send(21).unwrap();
        drop(tx);

        let event = stream.next().await.expect("an event").unwrap();
        let frame = first_frame(Sse::new(futures_util::stream::iter([Ok(event)]))).await;
        assert_eq!(frame, "event: tick\ndata: 42\n\n");
        assert!(
            stream.next().await.is_none(),
            "a closed channel ends the feed"
        );
    }

    #[tokio::test]
    async fn a_receiver_that_fell_behind_skips_to_the_oldest_message_held() {
        let (tx, rx) = broadcast::channel(2);
        for n in 0..5 {
            tx.send(n).unwrap();
        }
        let frame = first_frame(Sse::new(feed::<u32, u32>(rx, "tick"))).await;
        assert_eq!(frame, "event: tick\ndata: 3\n\n");
    }

    #[tokio::test]
    async fn the_heartbeat_is_a_named_event_that_carries_data() {
        let idle = Sse::new(futures_util::stream::pending()).keep_alive(
            KeepAlive::new()
                .interval(Duration::from_millis(1))
                .event(heartbeat()),
        );
        assert_eq!(first_frame(idle).await, "event: heartbeat\ndata: ok\n\n");
    }

    #[tokio::test]
    async fn the_response_opens_with_a_heartbeat_and_ends_on_stop() {
        use axum::response::IntoResponse;
        let (_tx, rx) = broadcast::channel::<u32>(1);
        let stop = CancellationToken::new();
        let response = sse(feed::<u32, u32>(rx, "tick"), stop.clone()).into_response();
        let mut body = response.into_body().into_data_stream();

        let frame = body.next().await.expect("a frame").expect("bytes");
        assert_eq!(frame, "event: heartbeat\ndata: ok\n\n");
        stop.cancel();
        assert!(body.next().await.is_none(), "stopping ends the feed");
    }

    #[tokio::test(start_paused = true)]
    async fn the_response_ends_after_its_lifetime() {
        use axum::response::IntoResponse;
        let idle = futures_util::stream::pending();
        let response = sse(idle, CancellationToken::new()).into_response();
        let mut body = response.into_body().into_data_stream();
        let opened = tokio::time::Instant::now();
        tokio::time::timeout(FEED_LIFETIME * 2, async {
            while body.next().await.is_some() {}
        })
        .await
        .expect("the feed ended");
        assert_eq!(opened.elapsed(), FEED_LIFETIME);
    }
}
