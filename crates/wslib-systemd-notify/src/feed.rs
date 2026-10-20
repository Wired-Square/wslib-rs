use std::env;
use std::ffi::OsString;
use std::future::{Future, poll_fn};
use std::io;
use std::pin::pin;
use std::task::Poll;
use std::time::Duration;

use crate::{send, watchdog_interval};

/// Sends `WATCHDOG=1` at half of [`watchdog_interval`] until `stop` completes,
/// ending early with the first send that fails; with no interval it only waits
/// for `stop`.
pub async fn feed_watchdog(stop: impl Future<Output = ()>) -> io::Result<()> {
    feed(env::var_os("NOTIFY_SOCKET"), watchdog_interval(), stop).await
}

async fn feed(
    socket: Option<OsString>,
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
        send(socket.as_deref(), "WATCHDOG=1")?;
    }
}

#[cfg(all(test, unix))]
mod tests {
    use tokio::sync::oneshot;
    use tokio::time::sleep;

    use super::*;
    use crate::tests::socket::Listener;

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
        let socket = Some(listener.path.clone().into_os_string());
        let task = tokio::spawn(feed(socket, Some(Duration::from_secs(10)), stop));

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
        let socket = Some(listener.path.clone().into_os_string());
        let task = tokio::spawn(feed(socket, None, stop));

        sleep(Duration::from_secs(3600)).await;
        assert!(!task.is_finished());
        tx.send(()).unwrap();
        task.await.unwrap().unwrap();
        assert!(listener.received().is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn a_failed_send_ends_the_task() {
        let (_tx, stop) = stop_signal();
        let gone = Some(OsString::from("/nonexistent/wslib-sd/notify"));
        let error = feed(gone, Some(Duration::from_secs(10)), stop)
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::NotFound);
    }
}
