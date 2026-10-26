//! A [`DomBridge`] over Tauri events: `harness:request` `{ id, op, args }` to
//! one window, `harness:reply` `{ id, ok }` or `{ id, error }` back, answered
//! on the page by `@wired-square/mcp-bridge/tauri-bridge`.

use std::sync::Arc;
use std::time::Duration;

use serde_json::{Value, json};
use tauri::{AppHandle, Emitter, Listener, Runtime};

use crate::bridge::{Pending, Reply};
use crate::dom::DomBridge;

pub const REQUEST_EVENT: &str = "harness:request";
pub const REPLY_EVENT: &str = "harness:reply";
pub const DEFAULT_WINDOW: &str = "main";

/// Build one and clone it: every instance hears every reply, and ids are
/// only unique within one.
pub struct TauriBridge<R: Runtime> {
    app: AppHandle<R>,
    window: Arc<str>,
    pending: Arc<Pending>,
}

impl<R: Runtime> Clone for TauriBridge<R> {
    fn clone(&self) -> Self {
        Self {
            app: self.app.clone(),
            window: self.window.clone(),
            pending: self.pending.clone(),
        }
    }
}

impl<R: Runtime> TauriBridge<R> {
    /// Listens for replies from now on, and sends requests to the window labelled `main`.
    pub fn new(app: &AppHandle<R>) -> Self {
        Self::for_window(app, DEFAULT_WINDOW)
    }

    pub fn for_window(app: &AppHandle<R>, window: &str) -> Self {
        let pending = Arc::new(Pending::default());
        let settle = pending.clone();
        app.listen(REPLY_EVENT, move |event| {
            settle.settle_json(event.payload())
        });
        Self {
            app: app.clone(),
            window: window.into(),
            pending,
        }
    }

    pub async fn request(&self, op: &str, args: Value, timeout: Duration) -> Reply {
        let (id, rx) = self.pending.open();
        let request = json!({ "id": id, "op": op, "args": args });
        if let Err(e) = self.app.emit_to(&*self.window, REQUEST_EVENT, request) {
            self.pending.forget(id);
            return Err(format!("could not reach window {}: {e}", self.window));
        }
        self.pending.wait(id, rx, timeout).await
    }
}

impl<R: Runtime> DomBridge for TauriBridge<R> {
    async fn call(&self, op: &str, args: Value, timeout: Duration) -> Reply {
        self.request(op, args, timeout).await
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use tauri::test::{MockRuntime, mock_app};
    use tauri::{App, WebviewUrl, WebviewWindow, WebviewWindowBuilder};

    use super::*;

    fn app_with_window() -> (App<MockRuntime>, WebviewWindow<MockRuntime>) {
        let app = mock_app();
        let window = WebviewWindowBuilder::new(&app, DEFAULT_WINDOW, WebviewUrl::default())
            .build()
            .unwrap();
        (app, window)
    }

    fn on_request(window: &WebviewWindow<MockRuntime>, answer: impl Fn(Value) + Send + 'static) {
        window.listen(REQUEST_EVENT, move |event| {
            answer(serde_json::from_str(event.payload()).unwrap())
        });
    }

    #[tokio::test]
    async fn a_reply_emitted_on_the_app_reaches_the_request() {
        let (app, window) = app_with_window();
        let bridge = TauriBridge::new(app.handle());
        let page = app.handle().clone();
        let seen = Arc::new(Mutex::new(Value::Null));
        let record = seen.clone();
        on_request(&window, move |request| {
            let reply = json!({ "id": request["id"], "ok": { "path": "/logs" } });
            *record.lock().unwrap() = request;
            page.emit(REPLY_EVENT, reply).unwrap();
        });

        let reply = bridge
            .request(
                "navigate",
                json!({ "path": "/logs" }),
                Duration::from_secs(5),
            )
            .await;

        assert_eq!(reply, Ok(json!({ "path": "/logs" })));
        let request = seen.lock().unwrap().clone();
        assert_eq!(request["op"], "navigate");
        assert_eq!(request["args"], json!({ "path": "/logs" }));
        assert!(bridge.pending.is_empty());
    }

    #[tokio::test]
    async fn an_unanswered_request_times_out_and_leaves_nothing_pending() {
        let (app, window) = app_with_window();
        let bridge = TauriBridge::new(app.handle());
        let asked = Arc::new(Mutex::new(false));
        let record = asked.clone();
        on_request(&window, move |_| *record.lock().unwrap() = true);

        let reply = bridge
            .request(
                "query",
                json!({ "selector": "b" }),
                Duration::from_millis(20),
            )
            .await;

        assert!(reply.unwrap_err().contains("did not answer"));
        assert!(*asked.lock().unwrap());
        assert!(bridge.pending.is_empty());
    }
}
