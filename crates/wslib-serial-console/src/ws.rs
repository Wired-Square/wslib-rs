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
    http::{StatusCode, request::Parts},
    response::{IntoResponse, Response},
    routing::{MethodRouter, get},
};
use serde::{Deserialize, Serialize};

use crate::{
    Bounds, ConsoleAction, ConsoleEvent, Finished, Monitors, PortKey, Refusal, RefusalReason,
    Update,
};

/// Who is at a console.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attendee {
    /// The name the session shows, and attributes this console's input to.
    pub name: String,
    pub writes: bool,
    /// Where they are attached from, as the roster shows it.
    pub via: String,
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
}

/// The query a console connects with. `follow` defaults to true.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ConsoleQuery {
    pub address: Option<String>,
    pub usb_serial: Option<String>,
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

/// The `GET` that upgrades a console, for the host to route at `/ws/serial`.
pub fn console<S, H: ConsoleHooks<S>>(monitors: Monitors, hooks: H) -> MethodRouter<S>
where
    S: Clone + Send + Sync + 'static,
{
    let hooks = Arc::new(hooks);
    get(move |State(state): State<S>, request: Request| {
        upgrade(monitors.clone(), hooks.clone(), state, request)
    })
}

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
    let ws = match WebSocketUpgrade::from_request_parts(&mut parts, &()).await {
        Ok(ws) => ws,
        Err(rejection) => return rejection.into_response(),
    };
    let query = match Query::<ConsoleQuery>::from_request_parts(&mut parts, &()).await {
        Ok(Query(query)) => query,
        Err(rejection) => return rejection.into_response(),
    };
    let Some(key) = PortKey::new(query.address.as_deref(), query.usb_serial.as_deref()) else {
        return (StatusCode::BAD_REQUEST, "missing address and usb_serial").into_response();
    };
    let who = match hooks.attendee(&state, &mut parts).await {
        Ok(who) => who,
        Err(refused) => return refused,
    };
    ws.on_upgrade(move |mut socket| async move {
        match hooks.may_open(&state, &key).await {
            Ok(()) => serve(&mut socket, monitors, key, query, who).await,
            Err(message) => {
                let _ = socket.send(text(&ConsoleEvent::Error { message })).await;
            }
        }
        let _ = socket.send(Message::Close(None)).await;
    })
}

async fn serve(
    socket: &mut WebSocket,
    monitors: Monitors,
    key: PortKey,
    query: ConsoleQuery,
    who: Attendee,
) {
    let bounds = query.bounds();
    let session = bounds.is_open_ended();
    let mut subscription = monitors.subscribe(key.clone(), query.baud, bounds);
    if session {
        subscription.join(&who.via, vec![who.name.clone()]);
        let attached = ConsoleEvent::Attached {
            name: who.name.clone(),
            writes: who.writes,
            baud: Some(subscription.baud()),
        };
        if socket.send(text(&attached)).await.is_err() {
            return;
        }
    }
    loop {
        tokio::select! {
            update = subscription.next() => {
                let Some(update) = update else { return };
                if let Update::End(reason) = update {
                    let _ = socket.send(text(&Finished { reason })).await;
                    return;
                }
                for message in messages(update) {
                    if socket.send(message).await.is_err() {
                        return;
                    }
                }
            }
            received = socket.recv() => {
                let refused = match received {
                    None | Some(Err(_) | Ok(Message::Close(_))) => return,
                    Some(Ok(Message::Binary(bytes))) if session => {
                        input(&who, || monitors.write(&key, bytes.to_vec(), Some(&who.name)))
                    }
                    Some(Ok(Message::Text(action))) if session => {
                        match serde_json::from_str::<ConsoleAction>(&action) {
                            Ok(ConsoleAction::Reset) => input(&who, || monitors.reset(&key)),
                            Err(_) => None,
                        }
                    }
                    Some(Ok(_)) => None,
                };
                if let Some(refused) = refused
                    && socket.send(text(&refused)).await.is_err()
                {
                    return;
                }
            }
        }
    }
}

/// The refusal for this console alone, if its input was not sent.
fn input(who: &Attendee, send: impl FnOnce() -> Result<(), Refusal>) -> Option<ConsoleEvent> {
    if !who.writes {
        return Some(ConsoleEvent::Refused {
            reason: RefusalReason::NotPermitted,
            detail: None,
        });
    }
    send().err().map(|refusal| ConsoleEvent::Refused {
        reason: refusal.reason(),
        detail: Some(refusal.to_string()),
    })
}

fn messages(update: Update) -> Vec<Message> {
    let event = match update {
        Update::Output { bytes, spans } => {
            let output = Message::Binary(bytes.to_vec().into());
            return match spans.is_empty() {
                true => vec![output],
                false => vec![text(&ConsoleEvent::Spans { spans }), output],
            };
        }
        Update::State { state, message } => ConsoleEvent::state(state, message),
        Update::Unechoed {
            by,
            colour,
            count,
            controls,
        } => ConsoleEvent::input(by, colour, count, &controls),
        Update::Participants(participants) => ConsoleEvent::Participants { participants },
        Update::End(_) => return Vec::new(),
    };
    vec![text(&event)]
}

fn text(value: &impl Serialize) -> Message {
    Message::Text(
        serde_json::to_string(value)
            .expect("a console frame serialises")
            .into(),
    )
}
