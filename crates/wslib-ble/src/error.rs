use std::fmt;
use std::time::Duration;

use crate::Address;

const BLUEZ_ERROR: &str = "org.bluez.Error.";
#[cfg(any(target_os = "linux", feature = "testing"))]
const SERVICE_FAILED: &str = "the Bluetooth service call failed";

/// How a device came to be paired.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Paired {
    /// A new bond was made.
    New,
    /// The host already held a bond with the device.
    Existing,
    /// The operating system pairs by itself, so nothing was done here.
    ByTheSystem,
}

/// What forgetting a device found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Forgotten {
    /// The host's bond and its record of the device are gone.
    Removed,
    /// The host had no record of the device.
    NotKnown,
}

/// Why BlueZ ended a pairing it was asked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Refusal {
    /// Also what BlueZ answers when no agent is registered on the host.
    AuthenticationFailed,
    AuthenticationRejected,
    AuthenticationCanceled,
    AuthenticationTimeout,
    ConnectionAttemptFailed,
}

impl Refusal {
    const ALL: [Self; 5] = [
        Self::AuthenticationFailed,
        Self::AuthenticationRejected,
        Self::AuthenticationCanceled,
        Self::AuthenticationTimeout,
        Self::ConnectionAttemptFailed,
    ];

    /// The D-Bus error name BlueZ gave.
    pub const fn name(self) -> &'static str {
        match self {
            Self::AuthenticationFailed => "org.bluez.Error.AuthenticationFailed",
            Self::AuthenticationRejected => "org.bluez.Error.AuthenticationRejected",
            Self::AuthenticationCanceled => "org.bluez.Error.AuthenticationCanceled",
            Self::AuthenticationTimeout => "org.bluez.Error.AuthenticationTimeout",
            Self::ConnectionAttemptFailed => "org.bluez.Error.ConnectionAttemptFailed",
        }
    }

    /// The refusal a D-Bus error name stands for, if it is one.
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|refusal| refusal.name() == name)
    }
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name().trim_start_matches(BLUEZ_ERROR))
    }
}

/// Why a device was not paired.
#[derive(Debug)]
#[non_exhaustive]
pub enum PairError {
    /// The host has no adapter by this name.
    NoAdapter { adapter: String },
    /// The adapter has not discovered the device, which it must before pairing.
    UnknownDevice { adapter: String, address: Address },
    /// The device or the host refused, with the text BlueZ added.
    Refused {
        reason: Refusal,
        detail: Option<String>,
    },
    /// No answer came within the limit; a pairing still running was cancelled.
    TimedOut { limit: Duration },
    /// The connection given already serves a pairing guard's agent.
    AgentExists,
    /// BlueZ was not reached, or answered outside its contract.
    #[cfg(any(target_os = "linux", feature = "testing"))]
    Service(zbus::Error),
}

impl fmt::Display for PairError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoAdapter { adapter } => write!(f, "no Bluetooth adapter {adapter}"),
            Self::UnknownDevice { adapter, address } => {
                write!(f, "{address} is not known to adapter {adapter}")
            }
            Self::Refused {
                reason,
                detail: None,
            } => write!(f, "the pairing was refused: {reason}"),
            Self::Refused {
                reason,
                detail: Some(detail),
            } => write!(f, "the pairing was refused: {reason} ({detail})"),
            Self::TimedOut { limit } => {
                write!(f, "the Bluetooth service did not answer within {limit:?}")
            }
            Self::AgentExists => f.write_str("the connection already serves a pairing agent"),
            #[cfg(any(target_os = "linux", feature = "testing"))]
            Self::Service(_) => f.write_str(SERVICE_FAILED),
        }
    }
}

impl std::error::Error for PairError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            #[cfg(any(target_os = "linux", feature = "testing"))]
            Self::Service(error) => Some(error),
            _ => None,
        }
    }
}

/// Why a device was not forgotten.
#[derive(Debug)]
#[non_exhaustive]
pub enum ForgetError {
    /// This operating system gives no call that removes a bond.
    Unsupported,
    /// The host has no adapter by this name.
    NoAdapter { adapter: String },
    /// BlueZ was not reached, or answered outside its contract.
    #[cfg(any(target_os = "linux", feature = "testing"))]
    Service(zbus::Error),
}

impl fmt::Display for ForgetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsupported => f.write_str("this operating system cannot forget a bond"),
            Self::NoAdapter { adapter } => write!(f, "no Bluetooth adapter {adapter}"),
            #[cfg(any(target_os = "linux", feature = "testing"))]
            Self::Service(_) => f.write_str(SERVICE_FAILED),
        }
    }
}

impl std::error::Error for ForgetError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            #[cfg(any(target_os = "linux", feature = "testing"))]
            Self::Service(error) => Some(error),
            _ => None,
        }
    }
}
