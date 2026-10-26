//! What a console and a proxied app say to each other on the app's hooks
//! socket, under `/v1`; never exported to TypeScript. A request refuses an
//! unknown top-level field, and an answer defaults a missing one.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::about::{Fact, Subsystem};
use crate::backup::{Chosen, Contains};
use crate::host::AddressConfig;

/// `GET /v1`: which optional hooks this app serves. About is always served.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
#[non_exhaustive]
pub struct HookIndex {
    /// `POST /v1/notes`.
    pub notes: bool,
    /// `POST /v1/backup/{capture,inspect,restore}`.
    pub backup: bool,
}

/// `GET /v1/about`: the app's own rows for the console's About screen.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
#[non_exhaustive]
pub struct AppAbout {
    pub product: String,
    pub version: String,
    pub facts: Vec<Fact>,
    pub subsystems: Vec<Subsystem>,
}

/// The body `POST /v1/notes` takes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NotesAsked {
    /// A Linux interface name, 1 to 15 bytes.
    pub interface: String,
    /// The change the console is about to make, when it is asking about one.
    #[serde(default)]
    pub change: Option<AddressConfig>,
}

/// What the app knows about an interface, and what `change` would break.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
#[non_exhaustive]
pub struct NetworkNotes {
    pub note: Option<String>,
    /// Each a sentence, never a refusal.
    pub warnings: Vec<String>,
}

/// `POST /v1/backup/inspect`: what a captured blob holds.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
#[non_exhaustive]
pub struct AppInspection {
    pub contains: Contains,
    pub warnings: Vec<String>,
    /// As [`Inspection::blocked`](crate::backup::Inspection::blocked).
    pub blocked: BTreeMap<String, String>,
}

/// The body `POST /v1/backup/restore` takes: a capture's blob, unchanged,
/// and the application-half sections to apply.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppRestore<B> {
    pub chosen: Chosen,
    pub sections: B,
}
