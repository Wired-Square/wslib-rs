//! The bootstrap flags, as groups a consumer flattens into its own parser.
//!
//! No flag has a `default_value` or an `#[arg(env = …)]`: either would hide the
//! file key or variable it overlaps. [`Resolver`](crate::Resolver) applies the
//! defaults after precedence.

use std::net::IpAddr;
use std::path::PathBuf;

/// The bootstrap flags every appliance takes. `Default` is no flags, for
/// resolving without a command line.
///
/// ```ignore
/// #[derive(clap::Parser)]
/// struct Cli {
///     #[command(flatten)]
///     appliance: wslib_appliance_config::ApplianceArgs,
///     /// Whatever else this product needs.
///     #[arg(long)]
///     catalogue: Option<PathBuf>,
/// }
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, clap::Args)]
pub struct ApplianceArgs {
    /// Read settings from this file instead of the default location. It must exist.
    #[arg(long, value_name = "PATH")]
    pub config: Option<PathBuf>,

    /// The SQLite database.
    #[arg(long, value_name = "PATH")]
    pub db: Option<PathBuf>,

    /// The control socket.
    #[arg(long, value_name = "PATH")]
    pub socket: Option<PathBuf>,

    /// The built browser bundle. It must exist.
    #[arg(long, value_name = "PATH")]
    pub ui: Option<PathBuf>,

    /// The path everything the TLS listener or the app socket serves is under,
    /// such as `/apps/name/`. `/` when not given.
    #[arg(long, value_name = "PATH")]
    pub base_path: Option<crate::BasePath>,
}

/// The flags of a product that serves its own HTTPS, given to
/// [`Resolver::serving`](crate::Resolver::serving).
#[derive(Debug, Clone, Default, PartialEq, Eq, clap::Args)]
pub struct ServingArgs {
    /// The address both listeners bind.
    #[arg(long, value_name = "ADDR")]
    pub bind_address: Option<IpAddr>,

    /// The port the HTTPS listener serves on.
    #[arg(long, value_name = "PORT")]
    pub https_port: Option<u16>,

    /// The port to redirect plain HTTP from. `0`, the default, is none.
    #[arg(long, value_name = "PORT")]
    pub redirect_port: Option<u16>,

    /// The TLS certificate chain to serve.
    #[arg(long, value_name = "PATH")]
    pub tls_cert: Option<PathBuf>,

    /// The private key for `--tls-cert`.
    #[arg(long, value_name = "PATH")]
    pub tls_key: Option<PathBuf>,
}
