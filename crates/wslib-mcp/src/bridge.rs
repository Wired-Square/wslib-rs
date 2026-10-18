//! Correlates requests sent to a page with the replies it sends back, over
//! whatever transport carries them.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use serde::Deserialize;
use serde_json::Value;
use tokio::sync::oneshot;

pub type Reply = Result<Value, String>;

/// The requests sent to the page that it has yet to answer, by id.
#[derive(Debug, Default)]
pub struct Pending {
    next: AtomicU32,
    waiting: Mutex<HashMap<u32, oneshot::Sender<Reply>>>,
}

#[derive(Deserialize)]
struct PageReply {
    id: u32,
    #[serde(default)]
    ok: Value,
    error: Option<String>,
}

impl Pending {
    pub fn open(&self) -> (u32, oneshot::Receiver<Reply>) {
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = oneshot::channel();
        self.waiting().insert(id, tx);
        (id, rx)
    }

    /// Hands `reply` to whoever opened `id`; a stray id is dropped.
    pub fn settle(&self, id: u32, reply: Reply) {
        if let Some(tx) = self.waiting().remove(&id) {
            let _ = tx.send(reply);
        }
    }

    /// Settles from the page's `{ id, ok }` or `{ id, error }`; anything else
    /// is dropped.
    pub fn settle_json(&self, payload: &str) {
        if let Ok(reply) = serde_json::from_str::<PageReply>(payload) {
            self.settle(reply.id, reply.error.map_or(Ok(reply.ok), Err));
        }
    }

    pub fn forget(&self, id: u32) {
        self.waiting().remove(&id);
    }

    /// Awaits the reply to `id` for up to `timeout`, and forgets `id` however
    /// the wait ends, including the caller dropping it.
    pub async fn wait(&self, id: u32, rx: oneshot::Receiver<Reply>, timeout: Duration) -> Reply {
        let _forget = Forget(self, id);
        match tokio::time::timeout(timeout, rx).await {
            Ok(Ok(reply)) => reply,
            Ok(Err(_)) => Err("the request was dropped before the page answered".to_owned()),
            Err(_) => Err(format!(
                "the page did not answer within {timeout:?}: is it open?"
            )),
        }
    }

    #[cfg(test)]
    pub(crate) fn is_empty(&self) -> bool {
        self.waiting().is_empty()
    }

    fn waiting(&self) -> MutexGuard<'_, HashMap<u32, oneshot::Sender<Reply>>> {
        self.waiting.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

struct Forget<'a>(&'a Pending, u32);

impl Drop for Forget<'_> {
    fn drop(&mut self) {
        self.0.forget(self.1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_reply_reaches_the_request_with_its_id() {
        let pending = Pending::default();
        let (one, mut first) = pending.open();
        let (two, mut second) = pending.open();
        pending.settle_json(&json!({ "id": two, "ok": { "path": "/logs" } }).to_string());
        pending.settle_json(&json!({ "id": one, "error": "no match" }).to_string());
        assert_eq!(second.try_recv().unwrap(), Ok(json!({ "path": "/logs" })));
        assert_eq!(first.try_recv().unwrap(), Err("no match".to_owned()));
        assert!(pending.is_empty());
    }

    #[test]
    fn a_stray_or_malformed_reply_is_dropped() {
        let pending = Pending::default();
        let (id, mut rx) = pending.open();
        pending.settle_json(&json!({ "id": id + 1, "ok": {} }).to_string());
        pending.settle_json("not json");
        assert!(rx.try_recv().is_err());
        pending.forget(id);
        assert!(pending.is_empty());
    }

    #[test]
    fn a_reply_without_ok_or_error_is_null() {
        let pending = Pending::default();
        let (id, mut rx) = pending.open();
        pending.settle_json(&json!({ "id": id }).to_string());
        assert_eq!(rx.try_recv().unwrap(), Ok(Value::Null));
    }

    #[tokio::test]
    async fn an_unanswered_wait_times_out_and_forgets_its_id() {
        let pending = Pending::default();
        let (id, rx) = pending.open();
        let reply = pending.wait(id, rx, Duration::from_millis(10)).await;
        assert!(reply.unwrap_err().contains("did not answer"));
        assert!(pending.is_empty());
    }

    #[tokio::test]
    async fn a_wait_returns_the_settled_reply() {
        let pending = Pending::default();
        let (id, rx) = pending.open();
        pending.settle(id, Ok(json!(7)));
        assert_eq!(
            pending.wait(id, rx, Duration::from_secs(1)).await,
            Ok(json!(7))
        );
    }
}
