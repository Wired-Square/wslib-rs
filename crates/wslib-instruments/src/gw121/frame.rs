pub const FRAME_LEN: usize = 19;
pub const START: u8 = 0xF2;

const MODE_MASK: u8 = 0x1F;
const SUB_MODE_MASK: u8 = 0xFF;
const VALUE_BITS_17_16_SHIFT: u8 = 6;
const VALUE_BITS_17_16_MASK: u8 = 0x03;
const VALUE_HIGH_SHIFT: u32 = 16;
const SUB_VALUE_HIGH_BITS: u8 = 0;
const OVERLOAD: u8 = 0x80;
const NEGATIVE: u8 = 0x40;
pub const MAIN_CELSIUS: u8 = 0x20;
pub const MAIN_FAHRENHEIT: u8 = 0x10;
pub const MAIN_RANGE_MASK: u8 = 0x0F;
pub const SUB_POINT_MASK: u8 = 0x07;
const ICON_APO: u8 = 0x02;
const ICON_PEAK: u8 = 0x20;
const COUPLING_SHIFT: u8 = 3;
const COUPLING_MASK: u8 = 0x03;
const COUPLING_NONE: u8 = 0;
const COUPLING_DC: u8 = 1;
const COUPLING_AC: u8 = 2;
pub const SUB_KILO: u8 = 0x20;
pub const SUB_HERTZ: u8 = 0x10;
const ICON_BATTERY: u8 = 0x01;
const ICON_BLUETOOTH: u8 = 0x40;
const ICON_RELATIVE: u8 = 0x10;
const ICON_MIN_MAX_MASK: u8 = 0x07;
const ICON_HOLD_MASK: u8 = 0x0C;
const MAIN_MODE: usize = 5;
const MAIN_FLAGS: usize = 6;
const MAIN_VALUE_MSB: usize = 7;
const MAIN_VALUE_LSB: usize = 8;
const SUB_MODE: usize = 9;
const SUB_FLAGS: usize = 10;
const SUB_VALUE_MSB: usize = 11;
const SUB_VALUE_LSB: usize = 12;
const ICONS_1: usize = 15;
const ICONS_2: usize = 16;
const ICONS_3: usize = 17;

fn xor(bytes: &[u8]) -> u8 {
    bytes.iter().fold(0, |x, b| x ^ b)
}

fn from_start(bytes: &[u8]) -> &[u8] {
    bytes
        .iter()
        .position(|&b| b == START)
        .and_then(|at| bytes.get(at..))
        .unwrap_or_default()
}

#[derive(Debug, Default)]
pub struct Assembler {
    buffer: Vec<u8>,
}

impl Assembler {
    pub fn push(&mut self, chunk: &[u8]) -> Vec<[u8; FRAME_LEN]> {
        self.buffer.extend_from_slice(chunk);
        let mut frames = Vec::new();
        let mut rest = self.buffer.as_slice();
        loop {
            rest = from_start(rest);
            let Some((candidate, after)) = rest.split_first_chunk::<FRAME_LEN>() else {
                break;
            };
            rest = if xor(candidate) == 0 {
                frames.push(*candidate);
                after
            } else {
                rest.split_first()
                    .map(|(_, past_start)| past_start)
                    .unwrap_or_default()
            };
        }
        let consumed = self.buffer.len().saturating_sub(rest.len());
        self.buffer.drain(..consumed);
        frames
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Display {
    pub mode: u8,
    pub raw: u32,
    pub negative: bool,
    pub overload: bool,
    pub flags: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Coupling {
    None,
    Dc,
    Ac,
    DcAc,
}

fn coupling(icons: u8) -> Coupling {
    match (icons >> COUPLING_SHIFT) & COUPLING_MASK {
        COUPLING_NONE => Coupling::None,
        COUPLING_DC => Coupling::Dc,
        COUPLING_AC => Coupling::Ac,
        _ => Coupling::DcAc,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Icons {
    pub auto_power_off: bool,
    pub battery_low: bool,
    pub bluetooth: bool,
    pub relative: bool,
    pub min_max: bool,
    pub held: bool,
    pub peak: bool,
    pub coupling: Coupling,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Frame {
    pub main: Display,
    pub sub: Display,
    pub icons: Icons,
}

fn display(mode: u8, flags: u8, value: [u8; size_of::<u16>()], high_bits: u8) -> Display {
    Display {
        mode,
        raw: u32::from(high_bits) << VALUE_HIGH_SHIFT | u32::from(u16::from_be_bytes(value)),
        negative: flags & NEGATIVE != 0,
        overload: flags & OVERLOAD != 0,
        flags,
    }
}

impl Frame {
    pub fn decode(bytes: &[u8; FRAME_LEN]) -> Self {
        let main_high = (bytes[MAIN_MODE] >> VALUE_BITS_17_16_SHIFT) & VALUE_BITS_17_16_MASK;
        Self {
            main: display(
                bytes[MAIN_MODE] & MODE_MASK,
                bytes[MAIN_FLAGS],
                [bytes[MAIN_VALUE_MSB], bytes[MAIN_VALUE_LSB]],
                main_high,
            ),
            sub: display(
                bytes[SUB_MODE] & SUB_MODE_MASK,
                bytes[SUB_FLAGS],
                [bytes[SUB_VALUE_MSB], bytes[SUB_VALUE_LSB]],
                SUB_VALUE_HIGH_BITS,
            ),
            icons: Icons {
                auto_power_off: bytes[ICONS_1] & ICON_APO != 0,
                battery_low: bytes[ICONS_1] & ICON_BATTERY != 0,
                bluetooth: bytes[ICONS_2] & ICON_BLUETOOTH != 0,
                relative: bytes[ICONS_2] & ICON_RELATIVE != 0,
                min_max: bytes[ICONS_2] & ICON_MIN_MAX_MASK != 0,
                held: bytes[ICONS_3] & ICON_HOLD_MASK != 0,
                peak: bytes[ICONS_1] & ICON_PEAK != 0,
                coupling: coupling(bytes[ICONS_1]),
            },
        }
    }
}
