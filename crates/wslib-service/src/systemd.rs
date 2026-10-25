//! What the service tells systemd, apart from the socket it is told through,
//! so the messages are tested on every platform.

use std::io;
use std::time::Duration;

use crate::Tell;

const STOP_MARGIN: Duration = Duration::from_secs(5);

pub(crate) struct Systemd<N>(pub(crate) N);

impl<N: Fn(&[(&str, &str)]) -> io::Result<()> + Send + Sync> Tell for Systemd<N> {
    fn ready(&self, status: Option<&str>) {
        match status {
            Some(status) => told((self.0)(&[("READY", "1"), ("STATUS", status)])),
            None => told((self.0)(&[("READY", "1")])),
        }
    }

    fn status(&self, status: &str) {
        told((self.0)(&[("STATUS", status)]));
    }

    fn extend(&self, grace: Duration) {
        told((self.0)(&[("EXTEND_TIMEOUT_USEC", &extend_usec(grace))]));
    }
}

/// `STOPPING=1`, with the time `grace` needs, in answer to a signal.
pub(crate) fn stopping(grace: Duration, notify: impl Fn(&[(&str, &str)]) -> io::Result<()>) {
    told(notify(&[
        ("STOPPING", "1"),
        ("EXTEND_TIMEOUT_USEC", &extend_usec(grace)),
    ]));
}

fn extend_usec(grace: Duration) -> String {
    (grace + STOP_MARGIN).as_micros().to_string()
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

    type Sent = Arc<Mutex<Vec<String>>>;

    fn recording(sent: &Sent) -> impl Fn(&[(&str, &str)]) -> io::Result<()> + Send + Sync {
        let sent = sent.clone();
        move |fields: &[(&str, &str)]| {
            let fields = fields.iter().map(|(key, value)| format!("{key}={value}"));
            sent.lock()
                .unwrap()
                .push(fields.collect::<Vec<_>>().join("\n"));
            Ok(())
        }
    }

    #[test]
    fn ready_carries_its_status_in_the_same_datagram_and_status_goes_alone() {
        let sent = Sent::default();
        let systemd = Systemd(recording(&sent));
        systemd.ready(Some("serving on :443"));
        systemd.status("draining");
        systemd.ready(None);
        assert_eq!(
            *sent.lock().unwrap(),
            [
                "READY=1\nSTATUS=serving on :443",
                "STATUS=draining",
                "READY=1"
            ]
        );
    }

    #[test]
    fn stopping_extends_the_timeout_by_the_grace_and_the_margin() {
        let sent = Sent::default();
        stopping(Duration::from_secs(15), recording(&sent));
        assert_eq!(
            *sent.lock().unwrap(),
            ["STOPPING=1\nEXTEND_TIMEOUT_USEC=20000000"]
        );
    }

    #[test]
    fn a_late_grace_extends_the_timeout_again_by_the_grace_and_the_margin() {
        let sent = Sent::default();
        Systemd(recording(&sent)).extend(Duration::from_secs(15));
        assert_eq!(*sent.lock().unwrap(), ["EXTEND_TIMEOUT_USEC=20000000"]);
    }
}
