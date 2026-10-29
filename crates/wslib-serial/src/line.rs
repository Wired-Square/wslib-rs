//! A serial line's rate and character framing, and the wire time of its bytes.

use std::fmt;
use std::str::FromStr;
use std::time::Duration;

/// A serial line's parity bit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Parity {
    None,
    Even,
    Odd,
}

impl Parity {
    fn letter(self) -> char {
        match self {
            Parity::None => 'N',
            Parity::Even => 'E',
            Parity::Odd => 'O',
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("parity must be none, even or odd, got {0:?}")]
pub struct UnknownParity(pub String);

/// `none`, `even` or `odd`, in any case.
impl FromStr for Parity {
    type Err = UnknownParity;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "none" => Ok(Parity::None),
            "even" => Ok(Parity::Even),
            "odd" => Ok(Parity::Odd),
            _ => Err(UnknownParity(s.to_owned())),
        }
    }
}

impl fmt::Display for Parity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Parity::None => "none",
            Parity::Even => "even",
            Parity::Odd => "odd",
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum InvalidLineSettings {
    #[error("data_bits must be 5 to 8, got {0}")]
    DataBits(u8),
    #[error("stop_bits must be 1 or 2, got {0}")]
    StopBits(u8),
}

/// Why [`LineSettings::parse`] refused a line.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LineSettingsError {
    #[error(transparent)]
    Parity(#[from] UnknownParity),
    #[error(transparent)]
    Line(#[from] InvalidLineSettings),
}

impl From<LineSettingsError> for String {
    fn from(e: LineSettingsError) -> Self {
        e.to_string()
    }
}

/// A serial line's rate and character framing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LineSettings {
    pub baud: u32,
    /// 5 to 8.
    pub data_bits: u8,
    pub parity: Parity,
    /// 1 or 2.
    pub stop_bits: u8,
}

impl LineSettings {
    /// Start, data, parity and stop bits at the baud rate, in whole microseconds.
    pub fn wire_time(&self, bytes: u64) -> Duration {
        let bits = 1
            + u64::from(self.data_bits)
            + u64::from(self.parity != Parity::None)
            + u64::from(self.stop_bits);
        let micros = bytes
            .saturating_mul(bits * 1_000_000)
            .checked_div(u64::from(self.baud));
        Duration::from_micros(micros.unwrap_or(0))
    }

    /// An absent field reads as 8N1's, and so does an empty parity; a present
    /// one must be valid.
    pub fn parse(
        baud: u32,
        data_bits: Option<u8>,
        stop_bits: Option<u8>,
        parity: Option<&str>,
    ) -> Result<Self, LineSettingsError> {
        let parity = parity
            .filter(|p| !p.is_empty())
            .map_or(Ok(Parity::None), str::parse)?;
        let line = Self {
            baud,
            data_bits: data_bits.unwrap_or(8),
            parity,
            stop_bits: stop_bits.unwrap_or(1),
        };
        line.validate()?;
        Ok(line)
    }

    pub fn validate(&self) -> Result<(), InvalidLineSettings> {
        if !(5..=8).contains(&self.data_bits) {
            Err(InvalidLineSettings::DataBits(self.data_bits))
        } else if !matches!(self.stop_bits, 1 | 2) {
            Err(InvalidLineSettings::StopBits(self.stop_bits))
        } else {
            Ok(())
        }
    }
}

/// `9600 8N1`.
impl fmt::Display for LineSettings {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {}{}{}",
            self.baud,
            self.data_bits,
            self.parity.letter(),
            self.stop_bits
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 10 bits a byte, 1 041.67 µs each.
    const LINE_9600_8N1: LineSettings = LineSettings {
        baud: 9600,
        data_bits: 8,
        parity: Parity::None,
        stop_bits: 1,
    };

    #[test]
    fn wire_time_counts_start_parity_and_stop_bits() {
        let line = |parity, stop_bits| LineSettings {
            parity,
            stop_bits,
            ..LINE_9600_8N1
        };
        let micros = |line: LineSettings, bytes| line.wire_time(bytes).as_micros();
        assert_eq!(micros(line(Parity::None, 1), 1), 1_041, "10 bits");
        assert_eq!(micros(line(Parity::None, 1), 96), 100_000);
        assert_eq!(micros(line(Parity::Even, 2), 1), 1_250, "12 bits");
        assert_eq!(micros(line(Parity::None, 1), 0), 0);
    }

    #[test]
    fn parity_parses_any_case_and_displays_lowercase() {
        for parity in [Parity::None, Parity::Even, Parity::Odd] {
            assert_eq!(parity.to_string().parse(), Ok(parity));
            assert_eq!(parity.to_string().to_uppercase().parse(), Ok(parity));
        }
        assert_eq!("Even".parse(), Ok(Parity::Even));
        assert_eq!("e".parse::<Parity>(), Err(UnknownParity("e".into())));
        assert_eq!("".parse::<Parity>(), Err(UnknownParity(String::new())));
    }

    #[test]
    fn line_settings_display_as_baud_and_framing() {
        assert_eq!(LINE_9600_8N1.to_string(), "9600 8N1");
        let line = LineSettings {
            baud: 19200,
            data_bits: 7,
            parity: Parity::Even,
            stop_bits: 2,
        };
        assert_eq!(line.to_string(), "19200 7E2");
        let odd = LineSettings {
            parity: Parity::Odd,
            ..LINE_9600_8N1
        };
        assert_eq!(odd.to_string(), "9600 8O1");
    }

    #[test]
    fn five_to_eight_data_bits_and_one_or_two_stop_bits_validate() {
        let line = |data_bits, stop_bits| LineSettings {
            data_bits,
            stop_bits,
            ..LINE_9600_8N1
        };
        for data_bits in 5..=8 {
            for stop_bits in 1..=2 {
                assert_eq!(line(data_bits, stop_bits).validate(), Ok(()));
            }
        }
        assert_eq!(line(4, 1).validate(), Err(InvalidLineSettings::DataBits(4)));
        assert_eq!(line(9, 1).validate(), Err(InvalidLineSettings::DataBits(9)));
        assert_eq!(line(8, 0).validate(), Err(InvalidLineSettings::StopBits(0)));
        assert_eq!(line(8, 3).validate(), Err(InvalidLineSettings::StopBits(3)));
        assert_eq!(line(9, 3).validate(), Err(InvalidLineSettings::DataBits(9)));
    }

    #[test]
    fn an_absent_line_field_reads_as_8n1() {
        let parsed = |baud, data_bits, stop_bits, parity| {
            LineSettings::parse(baud, data_bits, stop_bits, parity)
                .unwrap()
                .to_string()
        };
        assert_eq!(parsed(9600, None, None, None), "9600 8N1");
        assert_eq!(parsed(9600, None, None, Some("")), "9600 8N1");
        assert_eq!(parsed(19200, Some(7), Some(2), Some("Even")), "19200 7E2");
    }

    #[test]
    fn a_present_but_invalid_line_field_is_refused() {
        assert_eq!(
            LineSettings::parse(9600, Some(9), None, None),
            Err(InvalidLineSettings::DataBits(9).into())
        );
        assert_eq!(
            LineSettings::parse(9600, None, Some(0), None),
            Err(InvalidLineSettings::StopBits(0).into())
        );
        let mark = LineSettings::parse(9600, None, None, Some("mark")).unwrap_err();
        assert_eq!(
            mark.to_string(),
            "parity must be none, even or odd, got \"mark\""
        );
    }

    #[test]
    fn a_line_settings_error_converts_to_a_string_through_question_mark() {
        fn parse() -> Result<LineSettings, String> {
            Ok(LineSettings::parse(9600, Some(9), None, None)?)
        }
        assert_eq!(parse(), Err("data_bits must be 5 to 8, got 9".to_string()));
    }
}
