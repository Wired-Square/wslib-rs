use std::fmt;

const RADIX: i128 = 10;
const ZERO: &str = "0";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Value {
    pub mantissa: i64,
    pub exponent: i8,
}

fn power_of_ten(exponent: u32) -> Option<i128> {
    RADIX.checked_pow(exponent)
}

impl Value {
    pub const fn new(mantissa: i64, exponent: i8) -> Self {
        Self { mantissa, exponent }
    }

    pub fn rescale(&self, exponent: i8) -> Option<i64> {
        if self.mantissa == 0 {
            return Some(0);
        }
        let shift = i32::from(self.exponent) - i32::from(exponent);
        let mantissa = i128::from(self.mantissa);
        let scaled = if shift >= 0 {
            mantissa.checked_mul(power_of_ten(shift.unsigned_abs())?)?
        } else {
            let divisor = power_of_ten(shift.unsigned_abs())?;
            if mantissa % divisor != 0 {
                return None;
            }
            mantissa / divisor
        };
        i64::try_from(scaled).ok()
    }
}

impl fmt::Display for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.mantissa == 0 && self.exponent >= 0 {
            return f.write_str(ZERO);
        }
        let sign = if self.mantissa < 0 { "-" } else { "" };
        let digits = self.mantissa.unsigned_abs().to_string();
        if self.exponent >= 0 {
            return write!(
                f,
                "{sign}{digits}{}",
                ZERO.repeat(usize::from(self.exponent.unsigned_abs()))
            );
        }
        let fraction = usize::from(self.exponent.unsigned_abs());
        let padded = format!("{digits:0>width$}", width = fraction + 1);
        let (whole, part) = padded.split_at(padded.len() - fraction);
        write!(f, "{sign}{whole}.{part}")
    }
}
