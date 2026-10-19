//! Conventions every Wired Square command line shares: a `--json` switch
//! between tables and JSON, one set of exit codes, where config is found, and
//! `op://` references for secrets.

pub mod exit;
pub mod output;

pub use comfy_table;
pub use exit::Exit;
pub use output::Output;
#[cfg(feature = "clap")]
pub use output::OutputArgs;
