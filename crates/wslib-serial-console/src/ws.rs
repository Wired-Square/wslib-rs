//! `/ws/serial`: a browser's console on one port. Device bytes go both ways in
//! binary frames; everything else is a JSON text frame, a [`ConsoleEvent`] to
//! the browser and a [`ConsoleAction`] from it.
//!
//! With none of the [`Bounds`] in its query, a console joins the port's shared
//! session and may type if its [`Attendee`] writes. With any, it is a
//! read-only stream that ends with a [`Finished`] frame.

use std::{future::Future, sync::Arc};

use axum::{
    extract::{
        FromRequestParts, Query, Request, State,
        ws::{Message, WebSocket, WebSocketUpgrade},
    },
    http::request::Parts,
    response::{IntoResponse, Response},
    routing::{MethodFilter, MethodRouter, on},
};
use serde::{Deserialize, Serialize};

use crate::{
    Bounds, ConsoleAction, ConsoleEvent, Finished, Frame, Monitors, PortKey, Refusal,
    RefusalReason, Update, text,
};

pub const MISSING_PORT: &str = "missing address, usb_serial and usb_path";

/// Who is at a console.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attendee {
    /// The name the session shows, and attributes this console's input to.
    pub name: String,
    pub writes: bool,
    /// Where they are attached from, as the roster shows it.
    pub via: String,
}

/// What a console did, for the host's audit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Audit<'a> {
    Attached,
    Detached,
    /// Bytes sent to the port.
    Wrote(&'a [u8]),
    /// DTR pulsed to reset the board.
    Reset,
}

/// What the host decides for its consoles, given the router's state.
pub trait ConsoleHooks<S>: Send + Sync + 'static {
    /// Who is asking, or the response that refuses the upgrade.
    fn attendee(
        &self,
        state: &S,
        request: &mut Parts,
    ) -> impl Future<Output = Result<Attendee, Response>> + Send;

    /// Whether a console may open `key`; `Err` is the message it shows, as
    /// when an app holds the port.
    fn may_open(
        &self,
        _state: &S,
        _key: &PortKey,
    ) -> impl Future<Output = Result<(), String>> + Send {
        async { Ok(()) }
    }

    /// As [`may_open`](Self::may_open), told the path the console will open:
    /// the line its monitor has open, or else `key` resolved, which the
    /// monitor then opens without resolving again. `None` when no attached
    /// device has the USB serial. Calls `may_open` unless overridden.
    fn may_open_path(
        &self,
        state: &S,
        key: &PortKey,
        _path: Option<&str>,
    ) -> impl Future<Output = Result<(), String>> + Send {
        self.may_open(state, key)
    }

    /// Called as a console attaches and detaches, and for each write or reset
    /// it sends to the port.
    fn audit(&self, _state: &S, _key: &PortKey, _who: &Attendee, _what: Audit<'_>) {}
}

/// The query a console connects with. `follow` defaults to true.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ConsoleQuery {
    pub address: Option<String>,
    pub usb_serial: Option<String>,
    pub usb_path: Option<String>,
    /// Opens the port when this console is its first; ignored after.
    pub baud: Option<u32>,
    pub tail: Option<u32>,
    pub since_ms: Option<u64>,
    pub wait_for: Option<String>,
    pub timeout_ms: Option<u64>,
    pub duration_ms: Option<u64>,
    pub lines: Option<u32>,
    pub follow: Option<bool>,
}

impl ConsoleQuery {
    pub fn key(&self) -> Option<PortKey> {
        PortKey::from_parts(
            self.usb_serial.as_deref(),
            self.usb_path.as_deref(),
            self.address.as_deref(),
        )
    }

    pub fn bounds(&self) -> Bounds {
        Bounds {
            tail: self.tail,
            since_ms: self.since_ms,
            follow: self.follow.unwrap_or(true),
            wait_for: self.wait_for.clone(),
            timeout_ms: self.timeout_ms,
            duration_ms: self.duration_ms,
            lines: self.lines,
        }
    }
}

/// The `GET`, or HTTP/2 extended `CONNECT`, that upgrades a console, for the
/// host to route at `/ws/serial`.
pub fn console<S, H: ConsoleHooks<S>>(monitors: Monitors, hooks: H) -> MethodRouter<S>
where
    S: Clone + Send + Sync + 'static,
{
    let hooks = Arc::new(hooks);
    let methods = MethodFilter::GET.or(MethodFilter::CONNECT);
    on(methods, move |State(state): State<S>, request: Request| {
        upgrade(monitors.clone(), hooks.clone(), state, request)
    })
}

/// The hooks run before the upgrade is checked, so a request they refuse gets
/// their answer whether or not it asked to upgrade.
async fn upgrade<S, H: ConsoleHooks<S>>(
    monitors: Monitors,
    hooks: Arc<H>,
    state: S,
    request: Request,
) -> Response
where
    S: Send + Sync + 'static,
{
    let (mut parts, _) = request.into_parts();
    let who = match hooks.attendee(&state, &mut parts).await {
        Ok(who) => who,
        Err(refused) => return refused,
    };
    let query = match Query::<ConsoleQuery>::from_request_parts(&mut parts, &()).await {
        Ok(Query(query)) => query,
        Err(rejection) => return rejection.into_response(),
    };
    let opened = match query.key() {
        Some(key) => {
            let path = monitors.resolve(&key);
            let allowed = hooks.may_open_path(&state, &key, path.as_deref()).await;
            allowed.map(|()| (key, path))
        }
        None => Err(MISSING_PORT.to_owned()),
    };
    let ws = match WebSocketUpgrade::from_request_parts(&mut parts, &()).await {
        Ok(ws) => ws,
        Err(rejection) => return rejection.into_response(),
    };
    ws.on_upgrade(move |mut socket| async move {
        match opened {
            Ok((key, path)) => {
                let console = Console {
                    hooks: &*hooks,
                    state: &state,
                    key: &key,
                    who: &who,
                };
                console.audit(Audit::Attached);
                console.serve(&mut socket, monitors, path, query).await;
                console.audit(Audit::Detached);
            }
            Err(message) => {
                let error = ConsoleEvent::Error { message };
                let _ = socket.send(text_frame(&error)).await;
            }
        }
        let _ = socket.send(Message::Close(None)).await;
    })
}

struct Console<'a, S, H> {
    hooks: &'a H,
    state: &'a S,
    key: &'a PortKey,
    who: &'a Attendee,
}

impl<S, H: ConsoleHooks<S>> Console<'_, S, H> {
    fn audit(&self, what: Audit<'_>) {
        self.hooks.audit(self.state, self.key, self.who, what);
    }

    async fn serve(
        &self,
        socket: &mut WebSocket,
        monitors: Monitors,
        path: Option<String>,
        query: ConsoleQuery,
    ) {
        let (key, who) = (self.key, self.who);
        let bounds = query.bounds();
        let session = bounds.is_open_ended();
        let mut subscription = monitors.subscribe_resolved(key.clone(), path, query.baud, bounds);
        if session {
            subscription.join(&who.via, vec![who.name.clone()]);
            let attached = ConsoleEvent::Attached {
                name: who.name.clone(),
                writes: who.writes,
                baud: Some(subscription.baud()),
            };
            if socket.send(text_frame(&attached)).await.is_err() {
                return;
            }
        }
        loop {
            tokio::select! {
                update = subscription.next() => {
                    let Some(update) = update else { return };
                    let last = matches!(update, Update::End(_));
                    let sent = match subscription.revoked().filter(|_| last) {
                        Some(reason) => vec![text_frame(&ConsoleEvent::Error { message: reason.to_owned() })],
                        None => frames(update),
                    };
                    for frame in sent {
                        if socket.send(frame).await.is_err() {
                            return;
                        }
                    }
                    if last {
                        return;
                    }
                }
                received = socket.recv() => {
                    let refused = match received {
                        None | Some(Err(_) | Ok(Message::Close(_))) => return,
                        Some(Ok(Message::Binary(bytes))) if session => self.input(Audit::Wrote(&bytes), || {
                            monitors.write(key, bytes.to_vec(), Some(&who.name))
                        }),
                        Some(Ok(Message::Text(action))) if session => {
                            match serde_json::from_str::<ConsoleAction>(&action) {
                                Ok(ConsoleAction::Reset) => self.input(Audit::Reset, || monitors.reset(key)),
                                Err(_) => None,
                            }
                        }
                        Some(Ok(_)) => None,
                    };
                    if let Some(refused) = refused
                        && socket.send(text_frame(&refused)).await.is_err()
                    {
                        return;
                    }
                }
            }
        }
    }

    /// The refusal for this console alone, if its input was not sent.
    fn input(
        &self,
        what: Audit<'_>,
        send: impl FnOnce() -> Result<(), Refusal>,
    ) -> Option<ConsoleEvent> {
        if !self.who.writes {
            return Some(ConsoleEvent::Refused {
                reason: RefusalReason::NotPermitted,
                detail: None,
            });
        }
        match send() {
            Ok(()) => {
                self.audit(what);
                None
            }
            Err(refusal) => Some(ConsoleEvent::Refused {
                reason: refusal.reason(),
                detail: Some(refusal.to_string()),
            }),
        }
    }
}

/// The frames a console is sent for `update`, as `/ws/serial` sends them.
pub fn frames(update: Update) -> Vec<Message> {
    let event = match update {
        Update::Output { bytes, spans } => {
            let spans = (!spans.is_empty()).then_some(ConsoleEvent::Spans { spans });
            return crate::frames(spans.as_ref(), &bytes)
                .map(Message::from)
                .collect();
        }
        Update::State { state, message } => ConsoleEvent::state(state, message),
        Update::Unechoed {
            by,
            colour,
            count,
            controls,
        } => ConsoleEvent::input(by, colour, count, &controls),
        Update::Participants(participants) => ConsoleEvent::Participants { participants },
        Update::End(reason) => return vec![text_frame(&Finished { reason })],
    };
    vec![text_frame(&event)]
}

/// A wire type as the JSON text frame a console reads.
pub fn text_frame(value: &impl Serialize) -> Message {
    Message::Text(text(value).into())
}

impl From<Frame<'_>> for Message {
    fn from(frame: Frame<'_>) -> Self {
        match frame {
            Frame::Text(text) => Self::Text(text.into()),
            Frame::Binary(bytes) => Self::Binary(bytes.to_vec().into()),
        }
    }
}
