//! What a browser on `/ws/serial` exchanges with the console: device bytes in
//! binary frames both ways, and everything else as JSON text frames.

use serde::{Deserialize, Serialize};

/// How many colours a console gives names, the same name the same colour in
/// every console.
pub const COLOURS: u8 = 6;

/// Where a port's monitor is, so a console can say why no bytes are flowing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(rename_all = "snake_case")]
pub enum MonitorState {
    /// Finding the port's path from its USB serial.
    Resolving,
    Opening,
    Reading,
    /// The last resolve or open failed; waiting to retry.
    Backoff,
    /// No attached device has the USB serial.
    TtyMissing,
    /// Let go for a flash; input is refused until it is taken back.
    Paused,
}

impl MonitorState {
    /// What every console shows for it.
    pub fn label(self) -> &'static str {
        match self {
            Self::Resolving => "Finding the port",
            Self::Opening => "Opening the port",
            Self::Reading => "Reading",
            Self::Backoff => "Can't open the port, retrying",
            Self::TtyMissing => "Device not attached",
            Self::Paused => "Paused: flashing",
        }
    }
}

/// Bytes `start..start + len` of the binary frame after it are `by`'s echoed
/// input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub struct Span {
    pub start: u32,
    pub len: u32,
    pub by: String,
    pub colour: u8,
}

/// Someone attached to the port. `via` is where the host says they are
/// attached from; `colour` is below [`COLOURS`].
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub struct Participant {
    pub name: String,
    pub via: String,
    pub colour: u8,
}

/// Why a console's input was not sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(rename_all = "snake_case")]
pub enum RefusalReason {
    /// The port is let go for a flash.
    Paused,
    /// The port is not open.
    NoActiveReader,
    /// This console may watch but not type.
    NotPermitted,
}

/// A text frame to the browser.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ConsoleEvent {
    /// The first frame: who this browser is in the session, whether it may
    /// type, and the rate the port is open at, which the first console to
    /// attach chose.
    Attached {
        name: String,
        writes: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        #[cfg_attr(feature = "ts", ts(optional))]
        baud: Option<u32>,
    },
    State {
        state: MonitorState,
        label: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        #[cfg_attr(feature = "ts", ts(optional))]
        message: Option<String>,
    },
    /// Whose echo is in the binary frame that follows.
    Spans {
        spans: Vec<Span>,
    },
    /// Input the device never echoed, as the marker to show where it went.
    Input {
        by: String,
        colour: u8,
        marker: String,
    },
    Participants {
        participants: Vec<Participant>,
    },
    /// To the console that sent it only: its input was not sent.
    Refused {
        reason: RefusalReason,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        #[cfg_attr(feature = "ts", ts(optional))]
        detail: Option<String>,
    },
    Error {
        message: String,
    },
}

impl ConsoleEvent {
    pub fn state(state: MonitorState, message: Option<String>) -> Self {
        Self::State {
            state,
            label: state.label().to_string(),
            message,
        }
    }

    /// `unechoed` bytes from `by` and the control keys among them, never the
    /// bytes themselves: a device that doesn't echo is usually reading a
    /// secret.
    pub fn input(by: String, colour: u8, unechoed: u32, controls: &str) -> Self {
        let marker = match controls.is_empty() {
            true => format!("⌨{by}·{unechoed}"),
            false => format!("⌨{by}·{unechoed} {controls}"),
        };
        Self::Input { by, colour, marker }
    }
}

/// A text frame from the browser, beside its keystrokes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum ConsoleAction {
    /// Pulse DTR, which resets a board that wires it to its reset pin.
    Reset,
}

/// The last text frame of a bounded console.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub struct Finished {
    pub reason: EndReason,
}

/// Why a bounded subscription ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(rename_all = "snake_case")]
pub enum EndReason {
    /// `wait_for` matched.
    Pattern,
    Lines,
    Duration,
    /// `timeout_ms` passed before `wait_for` matched.
    Timeout,
    /// The replay was sent and `follow` was off.
    Closed,
    /// The port was let go for another program.
    Released,
}

#[cfg(test)]
mod tests {
    use serde::de::DeserializeOwned;

    use super::*;

    /// Serialises to `json` exactly, and reads back from it.
    fn golden<T: Serialize + DeserializeOwned + PartialEq + std::fmt::Debug>(value: T, json: &str) {
        assert_eq!(serde_json::to_string(&value).unwrap(), json);
        assert_eq!(serde_json::from_str::<T>(json).unwrap(), value);
    }

    fn alex(colour: u8) -> Span {
        Span {
            start: 0,
            len: 2,
            by: "alex".into(),
            colour,
        }
    }

    #[test]
    fn monitor_state() {
        let states = [
            (MonitorState::Resolving, "resolving"),
            (MonitorState::Opening, "opening"),
            (MonitorState::Reading, "reading"),
            (MonitorState::Backoff, "backoff"),
            (MonitorState::TtyMissing, "tty_missing"),
            (MonitorState::Paused, "paused"),
        ];
        for (state, name) in states {
            golden(state, &format!("\"{name}\""));
        }
    }

    #[test]
    fn span() {
        golden(alex(1), r#"{"start":0,"len":2,"by":"alex","colour":1}"#);
    }

    #[test]
    fn participant() {
        let olive = Participant {
            name: "olive".into(),
            via: "local".into(),
            colour: 0,
        };
        golden(olive, r#"{"name":"olive","via":"local","colour":0}"#);
    }

    #[test]
    fn attached_carries_the_ports_baud_when_known() {
        let attached = |baud| ConsoleEvent::Attached {
            name: "alex".into(),
            writes: true,
            baud,
        };
        golden(
            attached(Some(115200)),
            r#"{"type":"attached","name":"alex","writes":true,"baud":115200}"#,
        );
        golden(
            attached(None),
            r#"{"type":"attached","name":"alex","writes":true}"#,
        );
    }

    #[test]
    fn state_carries_its_label() {
        golden(
            ConsoleEvent::state(MonitorState::Paused, Some("Writing 40%".into())),
            r#"{"type":"state","state":"paused","label":"Paused: flashing","message":"Writing 40%"}"#,
        );
        golden(
            ConsoleEvent::state(MonitorState::TtyMissing, None),
            r#"{"type":"state","state":"tty_missing","label":"Device not attached"}"#,
        );
    }

    #[test]
    fn spans() {
        golden(
            ConsoleEvent::Spans {
                spans: vec![alex(0)],
            },
            r#"{"type":"spans","spans":[{"start":0,"len":2,"by":"alex","colour":0}]}"#,
        );
    }

    #[test]
    fn unechoed_input_is_a_marker_with_its_control_keys() {
        golden(
            ConsoleEvent::input("alex".into(), 2, 8, "^M"),
            r#"{"type":"input","by":"alex","colour":2,"marker":"⌨alex·8 ^M"}"#,
        );
        golden(
            ConsoleEvent::input("alex".into(), 2, 8, ""),
            r#"{"type":"input","by":"alex","colour":2,"marker":"⌨alex·8"}"#,
        );
    }

    #[test]
    fn participants() {
        let participants = vec![Participant {
            name: "olive".into(),
            via: "controller".into(),
            colour: 3,
        }];
        golden(
            ConsoleEvent::Participants { participants },
            r#"{"type":"participants","participants":[{"name":"olive","via":"controller","colour":3}]}"#,
        );
    }

    #[test]
    fn refused_names_its_reason() {
        let refused = |reason, detail: Option<&str>| ConsoleEvent::Refused {
            reason,
            detail: detail.map(Into::into),
        };
        golden(
            refused(RefusalReason::Paused, Some("paused for a flash")),
            r#"{"type":"refused","reason":"paused","detail":"paused for a flash"}"#,
        );
        golden(
            refused(RefusalReason::NoActiveReader, None),
            r#"{"type":"refused","reason":"no_active_reader"}"#,
        );
        golden(
            refused(RefusalReason::NotPermitted, None),
            r#"{"type":"refused","reason":"not_permitted"}"#,
        );
    }

    #[test]
    fn error() {
        golden(
            ConsoleEvent::Error {
                message: "missing address and usb_serial".into(),
            },
            r#"{"type":"error","message":"missing address and usb_serial"}"#,
        );
    }

    #[test]
    fn reset_action() {
        golden(ConsoleAction::Reset, r#"{"action":"reset"}"#);
    }

    #[test]
    fn finished() {
        let reasons = [
            (EndReason::Pattern, "pattern"),
            (EndReason::Lines, "lines"),
            (EndReason::Duration, "duration"),
            (EndReason::Timeout, "timeout"),
            (EndReason::Closed, "closed"),
            (EndReason::Released, "released"),
        ];
        for (reason, name) in reasons {
            golden(Finished { reason }, &format!(r#"{{"reason":"{name}"}}"#));
        }
    }
}
