use std::env;
use std::future::{Future, poll_fn};
use std::io;
use std::pin::pin;
use std::task::Poll;
use std::time::Duration;

use crate::{send, watchdog_interval};

/// Sends `WATCHDOG=1` at half of [`watchdog_interval`] until `stop` completes,
/// ending early with the first send that fails other than a full socket; with no
/// interval it only waits for `stop`.
pub async fn feed_watchdog(stop: impl Future<Output = ()>) -> io::Result<()> {
    let socket = env::var_os("NOTIFY_SOCKET");
    let ping = || send(socket.as_deref(), "WATCHDOG=1");
    feed(ping, watchdog_interval(), stop).await
}

async fn feed(
    mut ping: impl FnMut() -> io::Result<()>,
    interval: Option<Duration>,
    stop: impl Future<Output = ()>,
) -> io::Result<()> {
    let mut stop = pin!(stop);
    let Some(interval) = interval else {
        stop.await;
        return Ok(());
    };
    // sd_watchdog_enabled(3) asks for pings at half the interval, so one late
    // wake-up does not get the service killed.
    let mut ticks = tokio::time::interval(interval / 2);
    loop {
        let ticked = poll_fn(|cx| match stop.as_mut().poll(cx) {
            Poll::Ready(()) => Poll::Ready(false),
            Poll::Pending => ticks.poll_tick(cx).map(|_| true),
        })
        .await;
        if !ticked {
            return Ok(());
        }
        match ping() {
            // A full socket is transient, and the next ping comes well within
            // the interval.
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
            result => result?,
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use std::ffi::OsString;

    use tokio::sync::oneshot;
    use tokio::time::sleep;

    use super::*;
    use crate::tests::socket::Listener;

    fn pinging(socket: impl Into<OsString>) -> impl FnMut() -> io::Result<()> {
        let socket = socket.into();
        move || send(Some(&socket), "WATCHDOG=1")
    }

    fn stop_signal() -> (oneshot::Sender<()>, impl Future<Output = ()>) {
        let (tx, rx) = oneshot::channel();
        (tx, async {
            let _ = rx.await;
        })
    }

    #[tokio::test(start_paused = true)]
    async fn pings_at_half_the_interval_until_stopped() {
        let listener = Listener::bind();
        let (tx, stop) = stop_signal();
        let ping = pinging(listener.path.clone());
        let task = tokio::spawn(feed(ping, Some(Duration::from_secs(10)), stop));

        sleep(Duration::from_millis(1)).await;
        assert_eq!(listener.received(), ["WATCHDOG=1"]);
        sleep(Duration::from_secs(5)).await;
        assert_eq!(listener.received().len(), 1);
        sleep(Duration::from_secs(5)).await;
        assert_eq!(listener.received().len(), 1);

        tx.send(()).unwrap();
        task.await.unwrap().unwrap();
        sleep(Duration::from_secs(60)).await;
        assert!(listener.received().is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn without_an_interval_it_waits_for_stop_and_sends_nothing() {
        let listener = Listener::bind();
        let (tx, stop) = stop_signal();
        let task = tokio::spawn(feed(pinging(listener.path.clone()), None, stop));

        sleep(Duration::from_secs(3600)).await;
        assert!(!task.is_finished());
        tx.send(()).unwrap();
        task.await.unwrap().unwrap();
        assert!(listener.received().is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn a_full_socket_skips_the_ping_and_carries_on() {
        let (_tx, stop) = stop_signal();
        let mut pings = 0;
        let ping = move || {
            pings += 1;
            match pings {
                1 => Err(io::ErrorKind::WouldBlock.into()),
                _ => Err(io::ErrorKind::NotFound.into()),
            }
        };
        let task = tokio::spawn(feed(ping, Some(Duration::from_secs(10)), stop));

        sleep(Duration::from_secs(1)).await;
        assert!(!task.is_finished());
        sleep(Duration::from_secs(5)).await;
        let error = task.await.unwrap().unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::NotFound);
    }

    #[tokio::test(start_paused = true)]
    async fn a_failed_send_ends_the_task() {
        let (_tx, stop) = stop_signal();
        let ping = pinging("/nonexistent/wslib-sd/notify");
        let error = feed(ping, Some(Duration::from_secs(10)), stop)
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::NotFound);
    }
}
