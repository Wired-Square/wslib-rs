//! What the stop tells systemd, apart from the socket it is told through, so
//! the sequence is tested on every platform.

use std::io;
use std::time::Duration;

use tokio_util::sync::CancellationToken;

const STOP_MARGIN: Duration = Duration::from_secs(5);

/// Sends `READY=1` when first polled, as serving starts, and once `requested`
/// fires `STOPPING=1` with the time `grace` needs.
pub(crate) async fn stop(
    requested: CancellationToken,
    grace: Duration,
    notify: impl Fn(&[(&str, &str)]) -> io::Result<()>,
) {
    told(notify(&[("READY", "1")]));
    requested.cancelled().await;
    let extend = (grace + STOP_MARGIN).as_micros().to_string();
    told(notify(&[
        ("STOPPING", "1"),
        ("EXTEND_TIMEOUT_USEC", &extend),
    ]));
}

fn told(sent: io::Result<()>) {
    if let Err(e) = sent {
        tracing::warn!(error = %e, "could not notify systemd");
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::*;

    #[tokio::test]
    async fn ready_on_the_first_poll_and_stopping_with_the_grace_and_margin_once_requested() {
        let sent = Arc::new(Mutex::new(Vec::new()));
        let notify = {
            let sent = sent.clone();
            move |fields: &[(&str, &str)]| {
                let fields = fields.iter().map(|(key, value)| format!("{key}={value}"));
                sent.lock()
                    .unwrap()
                    .push(fields.collect::<Vec<_>>().join("\n"));
                Ok(())
            }
        };
        let requested = CancellationToken::new();
        let stopping = stop(requested.clone(), Duration::from_secs(15), notify);
        assert!(sent.lock().unwrap().is_empty(), "nothing until polled");

        let stopped = tokio::spawn(stopping);
        tokio::time::timeout(Duration::from_secs(5), async {
            while sent.lock().unwrap().is_empty() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("ready");
        requested.cancel();
        stopped.await.unwrap();

        assert_eq!(
            *sent.lock().unwrap(),
            ["READY=1", "STOPPING=1\nEXTEND_TIMEOUT_USEC=20000000"]
        );
    }
}
