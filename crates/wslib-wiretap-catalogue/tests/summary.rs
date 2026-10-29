//! `CatalogueSummary` against the catalogue reports WireTAP renders from it at cd652a85.

use std::collections::BTreeMap;
use std::path::PathBuf;

use wslib_wiretap_catalogue::summary::{FrameRow, MuxRow, SignalRow};
use wslib_wiretap_catalogue::{CatalogueSummary, Endianness, Protocol};

fn read(name: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name);
    std::fs::read_to_string(path).unwrap()
}

fn summary(input: &str) -> CatalogueSummary {
    CatalogueSummary::from_text(&read(&format!("{input}.toml"))).unwrap()
}

struct Facts {
    input: &'static str,
    version: u32,
    /// CAN, Modbus, serial.
    frames: [usize; 3],
    mux_frames: usize,
    signals: usize,
    enum_signals: usize,
    /// High, medium, low, none.
    confidence: [usize; 4],
    byte_order: &'static str,
}

const FACTS: [Facts; 5] = [
    Facts {
        input: "modbus",
        version: 3,
        frames: [0, 4, 0],
        mux_frames: 0,
        signals: 4,
        enum_signals: 1,
        confidence: [1, 0, 0, 3],
        byte_order: "Modbus big-endian",
    },
    Facts {
        input: "report-edges",
        version: 2,
        frames: [3, 1, 0],
        mux_frames: 1,
        signals: 6,
        enum_signals: 1,
        confidence: [0, 1, 1, 4],
        byte_order: "CAN little-endian, Modbus big-endian",
    },
    Facts {
        input: "report-legacy",
        version: 1,
        frames: [1, 0, 0],
        mux_frames: 0,
        signals: 1,
        enum_signals: 0,
        confidence: [0, 0, 0, 1],
        byte_order: "CAN little-endian",
    },
    Facts {
        input: "sbrxxx",
        version: 11,
        frames: [76, 2, 0],
        mux_frames: 7,
        signals: 170,
        enum_signals: 13,
        confidence: [117, 12, 17, 24],
        byte_order: "CAN little-endian, Modbus big-endian",
    },
    Facts {
        input: "serial",
        version: 1,
        frames: [0, 0, 3],
        mux_frames: 1,
        signals: 4,
        enum_signals: 0,
        confidence: [0, 0, 0, 4],
        byte_order: "Serial little-endian",
    },
];

fn order(e: Endianness, long: bool) -> &'static str {
    match (e, long) {
        (Endianness::Little, false) => "LE",
        (Endianness::Big, false) => "BE",
        (Endianness::Little, true) => "little-endian",
        (Endianness::Big, true) => "big-endian",
    }
}

#[test]
fn the_summary_counts_what_each_report_summarises() {
    for f in FACTS {
        let s = summary(f.input);
        let c = &s.counts;
        let d = &s.defaults;
        let byte_order: Vec<String> = [
            ("CAN", c.frames.can, d.can_byte_order),
            ("Modbus", c.frames.modbus, d.modbus_byte_order),
            ("Serial", c.frames.serial, d.serial_byte_order),
        ]
        .iter()
        .filter(|(_, frames, _)| *frames > 0)
        .map(|(name, _, e)| format!("{name} {}", order(*e, true)))
        .collect();
        let conf = &c.confidence;
        assert_eq!(s.version, f.version, "{}", f.input);
        assert_eq!(
            [c.frames.can, c.frames.modbus, c.frames.serial],
            f.frames,
            "{}",
            f.input
        );
        assert_eq!(
            (c.mux_frames, c.signals, c.enum_signals),
            (f.mux_frames, f.signals, f.enum_signals),
            "{}",
            f.input
        );
        assert_eq!(
            [conf.high, conf.medium, conf.low, conf.none],
            f.confidence,
            "{}",
            f.input
        );
        assert_eq!(byte_order.join(", "), f.byte_order, "{}", f.input);
    }
}

fn scale(factor: Option<f64>, offset: Option<f64>) -> String {
    let factor = factor.filter(|f| *f != 1.0).map(|f| format!("×{f}"));
    let offset = offset.filter(|o| *o != 0.0).map(|o| {
        let sign = if o < 0.0 { "−" } else { "+" };
        format!("{sign} {}", o.abs())
    });
    let parts: Vec<String> = factor.into_iter().chain(offset).collect();
    if parts.is_empty() {
        "—".into()
    } else {
        parts.join(" ")
    }
}

fn signal_rows<'a>(signals: &'a [SignalRow]) -> impl Iterator<Item = String> + 'a {
    signals.iter().filter(|r| !r.signal.inherited).map(|r| {
        let s = &r.signal;
        let enums: Vec<String> = s
            .enum_map
            .iter()
            .flatten()
            .map(|(k, v)| format!("{k}={v}"))
            .collect();
        let cells = [
            format!(
                "{}/{} {}",
                s.start_bit.unwrap_or(0),
                s.bit_length.unwrap_or(0),
                s.name.as_deref().unwrap_or_default()
            ),
            scale(s.factor, s.offset),
            s.unit.clone().unwrap_or_default(),
            if s.signed == Some(true) { "yes" } else { "no" }.into(),
            order(r.byte_order, false).into(),
            s.confidence.map_or("none", |c| c.as_str()).into(),
            enums.join(", "),
            s.notes.join("; "),
        ];
        cells.join(" | ").trim_end().to_string()
    })
}

fn with_notes(head: String, notes: &[String]) -> String {
    if notes.is_empty() {
        head
    } else {
        format!("{head} | {}", notes.join("; "))
    }
}

fn mux_rows(mux: &MuxRow, out: &mut Vec<String>) {
    let name = mux.name.as_deref().unwrap_or("-");
    let head = format!("mux {name} {}/{}", mux.start_bit, mux.bit_length);
    out.push(with_notes(head, &mux.notes));
    for case in &mux.cases {
        out.push(with_notes(format!("case {}", case.key), &case.notes));
        out.extend(signal_rows(&case.signals));
        if let Some(inner) = &case.mux {
            mux_rows(inner, out);
        }
    }
}

/// The frame's line, its own signals, then its own mux: what a mirror or copy
/// inherits is named, not repeated.
fn frame_rows(f: &FrameRow) -> Vec<String> {
    let inherits = |field: &str| f.inherited_fields.iter().any(|i| i == field);
    let mut head = match f.protocol {
        Protocol::Serial => vec![f.key.clone()],
        _ => vec![format!("{}: {}", f.key, f.name.as_deref().unwrap_or("-"))],
    };
    head.push(f.length.to_string());
    head.extend(f.transmitter.iter().map(|t| format!("tx {t}")));
    head.extend(f.interval.iter().map(|i| {
        let default = if i.default { " (default)" } else { "" };
        format!("{} ms{default}", i.ms)
    }));
    head.extend(f.bus.iter().map(|b| format!("bus {b}")));
    let inherited: Vec<&str> = ["signals", "mux"]
        .into_iter()
        .filter(|field| inherits(field))
        .collect();
    if !inherited.is_empty() {
        head.push(format!("inherits {}", inherited.join(", ")));
    }
    let mut out = vec![with_notes(head.join(" | "), &f.notes)];
    out.extend(signal_rows(&f.signals));
    if let Some(mux) = f.mux.as_ref().filter(|_| !inherits("mux")) {
        mux_rows(mux, &mut out);
    }
    out
}

/// `# input`, then each frame's rows, frames apart by a blank line.
fn expected_rows() -> BTreeMap<String, Vec<Vec<String>>> {
    let mut out: BTreeMap<String, Vec<Vec<String>>> = BTreeMap::new();
    let mut frames: Option<&mut Vec<Vec<String>>> = None;
    for line in read("summary-rows.txt").lines() {
        if let Some(input) = line.strip_prefix("# ") {
            frames = Some(out.entry(input.into()).or_default());
        } else if line.is_empty() {
            frames.as_mut().unwrap().push(Vec::new());
        } else {
            let frames = frames.as_mut().unwrap();
            frames.last_mut().unwrap().push(line.into());
        }
    }
    for frames in out.values_mut() {
        frames.retain(|f| !f.is_empty());
    }
    out
}

/// sbrxxx's rows are a spread: every mux frame, both Modbus frames and a few
/// plain and copied CAN ones. Every other input's are all of its frames.
#[test]
fn each_frame_resolves_to_the_rows_its_report_prints() {
    let expected = expected_rows();
    assert_eq!(expected.len(), FACTS.len());
    for (input, frames) in expected {
        let lib: BTreeMap<String, Vec<String>> = summary(&input)
            .frames
            .iter()
            .map(|f| (f.key.clone(), frame_rows(f)))
            .collect();
        if input != "sbrxxx" {
            assert_eq!(frames.len(), lib.len(), "{input}: frame count");
        }
        for rows in frames {
            let key = rows[0].split([':', ' ']).next().unwrap();
            assert_eq!(lib.get(key), Some(&rows), "{input}: {key}");
        }
    }
}
