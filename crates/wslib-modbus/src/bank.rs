use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// A Modbus register bank, which sets the function code a read uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(rename_all = "lowercase")]
pub enum RegisterType {
    Input,
    #[default]
    Holding,
    Coil,
    Discrete,
}

impl RegisterType {
    /// Whether one address holds a 16-bit register (input, holding) rather than
    /// one bit (coil, discrete).
    pub fn is_register_bank(self) -> bool {
        matches!(self, RegisterType::Input | RegisterType::Holding)
    }

    /// Whether Modbus can write this bank: holding (FC06/16) and coil (FC05/15).
    pub fn is_writable(self) -> bool {
        matches!(self, RegisterType::Holding | RegisterType::Coil)
    }

    /// The bank a write to this class targets, or `None` for a read-only one.
    pub fn write_bank(self) -> Option<WriteBank> {
        match self {
            RegisterType::Holding => Some(WriteBank::Holding),
            RegisterType::Coil => Some(WriteBank::Coil),
            RegisterType::Input | RegisterType::Discrete => None,
        }
    }

    /// The traditional 1-based address prefix (`register_base = 1`) a wire
    /// address is offset from.
    pub fn base_one_prefix(self) -> u32 {
        match self {
            RegisterType::Coil => 1,
            RegisterType::Discrete => 10001,
            RegisterType::Input => 30001,
            RegisterType::Holding => 40001,
        }
    }

    /// Lowercase tag, matching the manifest spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            RegisterType::Input => "input",
            RegisterType::Holding => "holding",
            RegisterType::Coil => "coil",
            RegisterType::Discrete => "discrete",
        }
    }
}

/// A register type that is none of the four banks.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("Unknown register type '{0}' — use holding, input, coil, or discrete")]
pub struct UnknownRegisterType(pub String);

/// The [`RegisterType::as_str`] tags, in any case.
impl FromStr for RegisterType {
    type Err = UnknownRegisterType;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "input" => Ok(RegisterType::Input),
            "holding" => Ok(RegisterType::Holding),
            "coil" => Ok(RegisterType::Coil),
            "discrete" => Ok(RegisterType::Discrete),
            _ => Err(UnknownRegisterType(s.to_owned())),
        }
    }
}

/// The two banks a Modbus write can target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(rename_all = "lowercase")]
pub enum WriteBank {
    #[default]
    Holding,
    Coil,
}

impl WriteBank {
    /// What one address of this bank is called in a message: `register` or `coil`.
    pub fn noun(self) -> &'static str {
        match self {
            WriteBank::Holding => "register",
            WriteBank::Coil => "coil",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_register_type_parses_its_own_tag_in_any_case() {
        use RegisterType::*;
        for rt in [Input, Holding, Coil, Discrete] {
            assert_eq!(serde_json::to_value(rt).unwrap(), rt.as_str());
            assert_eq!(rt.as_str().parse(), Ok(rt));
            assert_eq!(rt.as_str().to_ascii_uppercase().parse(), Ok(rt));
        }
        assert_eq!(
            "Holdin".parse::<RegisterType>(),
            Err(UnknownRegisterType("Holdin".into()))
        );
        assert_eq!(
            UnknownRegisterType("x".into()).to_string(),
            "Unknown register type 'x' — use holding, input, coil, or discrete"
        );
    }
}
