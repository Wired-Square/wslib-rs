use std::{convert::Infallible, fmt, str::FromStr};

const MAC_OCTETS: usize = 6;
const HEX_DIGITS_PER_OCTET: usize = 2;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    Address(String),
    Name(String),
}

impl FromStr for Target {
    type Err = Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let octets: Vec<&str> = s.split(':').collect();
        let is_mac = octets.len() == MAC_OCTETS
            && octets.iter().all(|o| {
                o.len() == HEX_DIGITS_PER_OCTET && o.bytes().all(|b| b.is_ascii_hexdigit())
            });
        Ok(if is_mac {
            Target::Address(s.to_owned())
        } else {
            Target::Name(s.to_owned())
        })
    }
}

impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Target::Address(a) | Target::Name(a) => f.write_str(a),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_mac_is_an_address_and_anything_else_is_a_name() {
        assert_eq!(
            "88:6B:0F:81:A9:53".parse::<Target>().unwrap(),
            Target::Address("88:6B:0F:81:A9:53".into())
        );
        assert_eq!(
            "121GW".parse::<Target>().unwrap(),
            Target::Name("121GW".into())
        );
    }
}
