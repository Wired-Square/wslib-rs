use std::fmt;
use std::str::FromStr;

const OCTETS: usize = 6;
const OCTET_DIGITS: usize = 2;
const HEX: u32 = 16;
const SEPARATOR: char = ':';

/// A device's Bluetooth address, the identity BlueZ knows it by.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Address([u8; OCTETS]);

impl Address {
    /// The address with these octets, in the order it is written.
    pub const fn new(octets: [u8; OCTETS]) -> Self {
        Self(octets)
    }

    /// The octets, in the order the address is written.
    pub const fn octets(&self) -> [u8; OCTETS] {
        self.0
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let [first, rest @ ..] = self.0;
        write!(f, "{first:02X}")?;
        rest.iter()
            .try_for_each(|octet| write!(f, "{SEPARATOR}{octet:02X}"))
    }
}

impl FromStr for Address {
    type Err = AddressParseError;

    /// Parses `AA:BB:CC:DD:EE:FF`, in either case.
    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let refused = || AddressParseError { text: text.into() };
        let mut octets = [0; OCTETS];
        let mut parts = text.split(SEPARATOR);
        for octet in &mut octets {
            let part = parts.next().ok_or_else(refused)?;
            if part.len() != OCTET_DIGITS || !part.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(refused());
            }
            *octet = u8::from_str_radix(part, HEX).map_err(|_| refused())?;
        }
        match parts.next() {
            None => Ok(Self(octets)),
            Some(_) => Err(refused()),
        }
    }
}

/// Text that is not a Bluetooth address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddressParseError {
    text: String,
}

impl AddressParseError {
    /// The text that was refused.
    pub fn text(&self) -> &str {
        &self.text
    }
}

impl fmt::Display for AddressParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?} is not a Bluetooth address", self.text)
    }
}

impl std::error::Error for AddressParseError {}
