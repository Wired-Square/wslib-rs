//! A catalogue's Modbus RTU lines: the function codes and length rules its
//! `[meta.modbus.function_code.<code>]` tables declare, and what a `[…tunnel]`
//! table adds, as [`wslib_modbus`]'s stream options. Declarations union: a
//! catalogue's, a tunnel's, a user's [`RtuSettings`] and a caller's builder
//! calls all add codes, and none takes one away.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use wslib_modbus::{CrcPolicy, ModbusRtuOptions, ModbusRtuStream, VendorLength};

use crate::model::{Catalogue, FrameTunnel, FunctionCode, TunnelProtocol};

/// A line's RTU settings as a user picks and stores them, before a catalogue
/// adds its codes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(rename = "ModbusRtuOptions"))]
#[serde(default)]
pub struct RtuSettings {
    /// Device address filter (1-247). `None` syncs on any valid address.
    #[cfg_attr(feature = "ts", ts(optional))]
    pub device_address: Option<u8>,
    /// Whether a message has to pass its CRC to be framed. `false` is a lenient
    /// mode, not "no framing" — see `CrcPolicy::Lenient`.
    #[cfg_attr(feature = "ts", ts(optional = nullable))]
    pub validate_crc: bool,
    /// Function codes the RTU length rules do not model but this line carries.
    /// Framed by CRC search instead; empty leaves stock Modbus untouched.
    #[cfg_attr(feature = "ts", ts(optional = nullable))]
    pub vendor_functions: Vec<u8>,
    /// Whether address 0 may start a message, for a master that broadcasts.
    #[cfg_attr(feature = "ts", ts(optional = nullable))]
    pub allow_broadcast: bool,
    /// Frame every function code, declared or not. What a tap on an unknown
    /// line wants, at the cost of a fabricated message about once in 260
    /// resyncs — see `ModbusRtuStream::frame_any_function`.
    #[cfg_attr(feature = "ts", ts(optional = nullable))]
    pub any_function: bool,
}

/// Stock Modbus: CRC enforced, no vendor codes, no broadcast.
impl Default for RtuSettings {
    fn default() -> Self {
        Self {
            device_address: None,
            validate_crc: true,
            vendor_functions: Vec::new(),
            allow_broadcast: false,
            any_function: false,
        }
    }
}

impl RtuSettings {
    /// A line somebody else already framed, such as an archive's whole
    /// messages: every code and address interprets.
    pub fn tapped() -> Self {
        Self {
            any_function: true,
            allow_broadcast: true,
            ..Default::default()
        }
    }

    /// A line's options: what `catalogue` declares, with these settings on top.
    /// The codes and both opt-ins union; the address and the CRC policy are the
    /// settings'.
    pub fn options(&self, catalogue: Option<&Catalogue>) -> ModbusRtuOptions {
        let crc = if self.validate_crc {
            CrcPolicy::Strict
        } else {
            CrcPolicy::Lenient
        };
        let mut options = catalogue
            .map(Catalogue::rtu_options)
            .unwrap_or_default()
            .with_vendor_functions(&self.vendor_functions)
            .with_device_address(self.device_address)
            .with_crc_policy(crc);
        options.allow_broadcast |= self.allow_broadcast;
        options.any_function |= self.any_function;
        options
    }

    /// A stream for this line with no catalogue.
    pub fn stream(&self) -> ModbusRtuStream {
        self.options(None).stream()
    }
}

pub(crate) fn rtu_options_for(codes: &BTreeMap<u8, FunctionCode>) -> ModbusRtuOptions {
    let functions: Vec<u8> = codes.keys().copied().collect();
    let rules: Vec<VendorLength> = codes
        .iter()
        .flat_map(|(&function, code)| {
            code.lengths.iter().map(move |rule| VendorLength {
                function,
                when: rule.when,
                len: rule.len,
            })
        })
        .collect();
    ModbusRtuOptions::default()
        .with_vendor_functions(&functions)
        .with_vendor_lengths(&rules)
}

impl FrameTunnel {
    /// A stream for this tunnel, with everything its table declares.
    /// [`Catalogue::tunnel_stream`] adds the catalogue's function codes as well.
    pub fn stream(&self) -> ModbusRtuStream {
        debug_assert!(matches!(self.protocol, TunnelProtocol::ModbusRtu));
        let stream = ModbusRtuStream::for_address(self.device_address)
            .with_vendor_functions(&self.vendor_functions);
        if self.allow_broadcast {
            stream.allow_broadcast()
        } else {
            stream
        }
    }
}

impl Catalogue {
    /// A serial line carrying this catalogue's devices: its function codes
    /// declared, with their length rules. Everything else is the default, for
    /// the caller to set.
    pub fn rtu_options(&self) -> ModbusRtuOptions {
        self.modbus
            .as_ref()
            .map(|m| rtu_options_for(&m.function_codes))
            .unwrap_or_default()
    }

    /// The stream for one of this catalogue's tunnels: what its table declares,
    /// plus the catalogue's function codes.
    pub fn tunnel_stream(&self, tunnel: &FrameTunnel) -> ModbusRtuStream {
        let codes = self.rtu_options();
        tunnel
            .stream()
            .with_vendor_functions(&codes.vendor_functions)
            .with_vendor_lengths(&codes.vendor_lengths)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::time::UNIX_EPOCH;

    use wslib_checksum::algorithms::{crc16_modbus_checksum, crc16_modbus_valid};
    use wslib_modbus::{ModbusRtuMessage, RtuTap, Selector, VendorLen};
    use wslib_serial::{LineSettings, Parity};

    use super::*;
    use crate::framing_detect::{Framing, detect};

    fn tunnel(device_address: Option<u8>) -> FrameTunnel {
        FrameTunnel {
            protocol: TunnelProtocol::ModbusRtu,
            device_address,
            vendor_functions: Vec::new(),
            allow_broadcast: false,
            notes: Vec::new(),
        }
    }

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn with_crc(body: &str) -> Vec<u8> {
        let mut m = hex(body);
        m.extend(crc16_modbus_checksum(&m).to_le_bytes());
        m
    }

    fn raws(msgs: &[ModbusRtuMessage]) -> Vec<&[u8]> {
        msgs.iter().map(|m| m.raw.as_slice()).collect()
    }

    /// Every way a line can arrive: byte by byte, split once at each point, and
    /// whole.
    fn every_chunking(line: &[u8]) -> Vec<Vec<Vec<u8>>> {
        let mut chunkings = vec![line.chunks(1).map(<[u8]>::to_vec).collect()];
        chunkings.extend((1..line.len()).map(|at| vec![line[..at].to_vec(), line[at..].to_vec()]));
        chunkings.push(vec![line.to_vec()]);
        chunkings
    }

    fn framed(options: &ModbusRtuOptions, line: &[u8]) -> Vec<Vec<u8>> {
        options
            .stream()
            .push_bytes(line)
            .into_iter()
            .map(|m| m.raw)
            .collect()
    }

    const DISPATCH: VendorLength = VendorLength {
        function: 0x60,
        when: None,
        len: VendorLen::Counted {
            count_at: 6,
            overhead: 9,
        },
    };
    const BATTERY_REQUEST: VendorLength = VendorLength {
        function: 0x20,
        when: Some(Selector {
            offset: 4,
            value: 0x03,
        }),
        len: VendorLen::Fixed(11),
    };

    /// A 19-byte dispatch whose first 18 bytes also pass as a message.
    fn dispatch_short_by_one() -> Vec<u8> {
        let msg = with_crc("0060123400010A01020304050607000064");
        assert!(
            crc16_modbus_valid(&msg[..18]),
            "the fixture is not ambiguous"
        );
        msg
    }

    /// The dispatch's layout, and 0x65 declared with none.
    const DISPATCH_CATALOGUE: &str = r#"
[meta]
name = "x"
[meta.modbus.function_code.0x60]
name = "Dispatch"
lengths = [{ len = { count_at = 6, overhead = 9 } }]
[meta.modbus.function_code.0x65]
[frame.can."0x1E0"]
length = 8
[frame.can."0x1E0".tunnel]
protocol = "modbus_rtu"
allow_broadcast = true
"#;

    fn dispatch_catalogue() -> Catalogue {
        Catalogue::parse(DISPATCH_CATALOGUE).unwrap()
    }

    #[test]
    fn for_address_matches_the_catalogue_constructor() {
        let stream = with_crc("01044DE20002");
        let declared = tunnel(Some(1)).stream().push_bytes(&stream);
        let bare = ModbusRtuStream::for_address(Some(1)).push_bytes(&stream);
        assert_eq!(declared, bare);
        assert_eq!(declared.len(), 1);
    }

    #[test]
    fn a_catalogue_can_declare_what_the_builder_can() {
        let declared = FrameTunnel {
            vendor_functions: vec![0x20, 0x60, 0x65],
            allow_broadcast: true,
            ..tunnel(None)
        };
        let msgs = declared
            .stream()
            .push_bytes(&with_crc("012001C803111A0002"));
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].function, 0x20);
    }

    #[test]
    fn catalogue_and_builder_vendor_codes_are_unioned() {
        let declared = FrameTunnel {
            vendor_functions: vec![0x20],
            ..tunnel(None)
        };
        let mut t = declared.stream().with_vendor_functions(&[0x65]);

        // The catalogue's code survives the builder call...
        let msgs = t.push_bytes(&with_crc("012001C803111A0002"));
        assert_eq!(msgs.len(), 1, "catalogue-declared 0x20");
        // ...and the builder's is framed too.
        let msgs = t.push_bytes(&with_crc("0165020BB8"));
        assert_eq!(msgs.len(), 1, "builder-declared 0x65");
        assert_eq!(msgs[0].function, 0x65);
    }

    /// A tunnel normally pins an address, so a declaration that only worked on
    /// address-less streams would be dead config.
    #[test]
    fn a_pinned_address_still_admits_a_declared_broadcast() {
        let dispatch = with_crc("0060000000050A000401BB03E808");
        let declared = FrameTunnel {
            vendor_functions: vec![0x60],
            allow_broadcast: true,
            ..tunnel(Some(1))
        };
        let msgs = declared.stream().push_bytes(&dispatch);
        assert_eq!(msgs.len(), 1, "a broadcast reaches address 1 as well");
        assert_eq!(msgs[0].device_address, 0);

        // Undeclared, a pinned stream still ignores it.
        let quiet = FrameTunnel {
            vendor_functions: vec![0x60],
            ..tunnel(Some(1))
        };
        assert!(quiet.stream().push_bytes(&dispatch).is_empty());
    }

    #[test]
    fn a_tunnel_inherits_the_catalogues_function_codes() {
        let catalogue = dispatch_catalogue();
        let tunnel = catalogue.frame(0x1E0).unwrap().tunnel.as_ref().unwrap();
        let dispatch = dispatch_short_by_one();
        let bare = with_crc("0165000200");
        let line = [&dispatch[..], &bare[..]].concat();
        for chunks in every_chunking(&line) {
            let mut t = catalogue.tunnel_stream(tunnel);
            let mut got: Vec<_> = chunks.iter().flat_map(|c| t.push_bytes(c)).collect();
            got.extend(t.finish().0);
            assert_eq!(raws(&got), [&dispatch[..], &bare[..]]);
        }

        let mut t = tunnel.stream();
        assert!(t.push_bytes(&dispatch).is_empty(), "no catalogue, no codes");
    }

    #[test]
    fn catalogue_and_builder_rules_are_unioned() {
        let catalogue = dispatch_catalogue();
        let tunnel = catalogue.frame(0x1E0).unwrap().tunnel.as_ref().unwrap();
        let mut t = catalogue
            .tunnel_stream(tunnel)
            .with_vendor_lengths(&[BATTERY_REQUEST]);
        let request = with_crc("0120ABCD0311223344");
        let dispatch = dispatch_short_by_one();
        let line = [&request[..], &dispatch[..]].concat();
        assert_eq!(raws(&t.push_bytes(&line)), [&request[..], &dispatch[..]]);
    }

    #[test]
    fn rtu_options_carry_the_catalogues_codes_and_rules() {
        let options = dispatch_catalogue().rtu_options();
        let expected = ModbusRtuOptions::default()
            .with_vendor_functions(&[0x60, 0x65])
            .with_vendor_lengths(&[DISPATCH]);
        assert_eq!(options, expected);
        assert_eq!(
            Catalogue::parse("[meta]\nname = \"x\"\n")
                .unwrap()
                .rtu_options(),
            ModbusRtuOptions::default()
        );
    }

    #[test]
    fn rtu_rules_read_what_the_full_parse_reads() {
        for text in [DISPATCH_CATALOGUE, "[meta]\nname = \"x\"\n"] {
            let full = Catalogue::parse(text).unwrap();
            let lean = crate::rtu_rules(text).unwrap();
            assert_eq!(lean.options, full.rtu_options());
            assert_eq!(lean.name, full.meta.name);
        }
    }

    /// The full parse drops the rule and frames 0x60 by CRC search; the lean
    /// read refuses, naming it as `validate` would.
    #[test]
    fn rtu_rules_refuse_a_rule_the_parser_would_drop() {
        let text = "[meta]\nname = \"x\"\n[meta.modbus.function_code.0x60]\nlengths = [{ len = { fixed = 9, count_at = 2 } }]\n";
        assert!(Catalogue::parse(text).is_ok());
        match crate::rtu_rules(text) {
            Err(e @ crate::RtuRulesError::Rules(_)) => assert!(
                e.to_string()
                    .starts_with("meta.modbus.function_code.0x60.lengths[0]: "),
                "{e}"
            ),
            other => panic!("expected the rule refused, got {other:?}"),
        }
        assert!(matches!(
            crate::rtu_rules("[meta"),
            Err(crate::RtuRulesError::Toml(_))
        ));
    }

    /// The name is the one field besides the rules that `rtu_rules` returns, so
    /// a catalogue without one is refused as `validate` refuses it.
    #[test]
    fn rtu_rules_refuse_a_catalogue_without_a_name() {
        for (text, field) in [("", "meta"), ("[meta]\nversion = 1\n", "meta.name")] {
            let e = crate::rtu_rules(text).unwrap_err().to_string();
            assert!(e.starts_with(&format!("{field}: ")), "{e}");
        }
    }

    #[test]
    fn rtu_rules_refuse_a_name_that_is_not_a_string() {
        let e = crate::rtu_rules("[meta]\nname = 5\n")
            .unwrap_err()
            .to_string();
        assert_eq!(e, "meta.name: Catalogue name must be a string");
    }

    #[test]
    fn a_tap_on_catalogue_options_frames_ruled_codes_by_rule_and_the_rest_by_search() {
        let options = dispatch_catalogue()
            .rtu_options()
            .allow_broadcast()
            .frame_any_function();
        let dispatch = dispatch_short_by_one();
        let declared_bare = with_crc("0165000200");
        let undeclared = with_crc("017701020304");
        let line = [&dispatch[..], &declared_bare[..], &undeclared[..]].concat();
        assert_eq!(
            framed(&options, &line),
            [dispatch, declared_bare, undeclared]
        );
    }

    #[test]
    fn the_catalogues_codes_and_rules_union_under_the_pickers_settings() {
        let picker = RtuSettings {
            device_address: Some(3),
            validate_crc: false,
            vendor_functions: vec![0x20],
            allow_broadcast: true,
            any_function: false,
        };
        let manual = ModbusRtuOptions::default()
            .with_device_address(Some(3))
            .with_crc_policy(CrcPolicy::Lenient)
            .allow_broadcast();

        assert_eq!(
            picker.options(Some(&dispatch_catalogue())),
            manual
                .clone()
                .with_vendor_functions(&[0x60, 0x65, 0x20])
                .with_vendor_lengths(&[DISPATCH])
        );
        assert_eq!(picker.options(None), manual.with_vendor_functions(&[0x20]));
    }

    #[test]
    fn stock_and_tapped_settings_are_the_stock_and_tapped_options() {
        assert_eq!(
            RtuSettings::default().options(None),
            ModbusRtuOptions::default()
        );
        assert_eq!(
            RtuSettings::tapped().options(None),
            ModbusRtuOptions::tapped()
        );
    }

    #[test]
    fn rtu_settings_keep_their_snake_case_shape_and_defaults() {
        let defaults: RtuSettings = serde_json::from_str("{}").unwrap();
        assert_eq!(defaults, RtuSettings::default());
        assert!(defaults.validate_crc);
        assert_eq!(
            serde_json::to_string(&RtuSettings::tapped()).unwrap(),
            r#"{"device_address":null,"validate_crc":true,"vendor_functions":[],"allow_broadcast":true,"any_function":true}"#
        );
    }

    const LINE_9600_8N1: LineSettings = LineSettings {
        baud: 9600,
        data_bits: 8,
        parity: Parity::None,
        stop_bits: 1,
    };

    fn frame_capture(options: &ModbusRtuOptions, bytes: &[u8], chunk: usize) -> Vec<Vec<u8>> {
        let mut tap = RtuTap::new(options, LINE_9600_8N1.baud, LINE_9600_8N1.bits_per_char());
        let mut got: Vec<_> = bytes
            .chunks(chunk)
            .flat_map(|c| tap.push(c, UNIX_EPOCH))
            .collect();
        got.extend(tap.finish().0);
        got.into_iter().map(|m| m.message.raw).collect()
    }

    fn report(label: &str, raws: &[Vec<u8>], total: usize) -> usize {
        let framed: usize = raws.iter().map(Vec::len).sum();
        eprintln!(
            "{label}: {} messages, {framed} of {total} bytes ({:.4}%)",
            raws.len(),
            framed as f64 / total as f64 * 100.0
        );
        for func in [0x20, 0x60, 0x65] {
            let mut lengths = BTreeMap::<usize, usize>::new();
            for raw in raws.iter().filter(|r| r[1] == func) {
                *lengths.entry(raw.len()).or_default() += 1;
            }
            eprintln!("{label}: {func:#04x} lengths {lengths:?}");
        }
        framed
    }

    /// The Sungrow logger's vendor codes, as a catalogue that declares nothing
    /// else.
    pub(crate) const SUNGROW_FUNCTION_CODES: &str = r#"
[meta]
name = "Sungrow logger RS-485"

[meta.modbus.function_code.0x60]
lengths = [{ len = { count_at = 6, overhead = 9 } }]

# A response's first 11 bytes can also pass CRC, so its counted layout is
# tried before the request that shares its selector.
[meta.modbus.function_code.0x20]
lengths = [
  { when = { offset = 4, value = 0x03 }, len = { fixed = 11 } },
  { when = { offset = 4, value = 0x04 }, len = { count_at = 5, overhead = 8 } },
  { when = { offset = 4, value = 0x04 }, len = { fixed = 11 } },
]

[meta.modbus.function_code.0x65]
lengths = [{ len = { count_at = 4, overhead = 7 } }]
"#;

    fn sungrow_tap() -> ModbusRtuOptions {
        Catalogue::parse(SUNGROW_FUNCTION_CODES)
            .unwrap()
            .rtu_options()
            .allow_broadcast()
            .frame_any_function()
    }

    #[test]
    fn a_catalogue_of_only_function_codes_configures_a_tap() {
        assert!(crate::validate::validate(SUNGROW_FUNCTION_CODES).is_empty());
        let options = sungrow_tap();
        assert_eq!(options.vendor_functions, [0x20, 0x60, 0x65]);
        assert_eq!(options.vendor_lengths.len(), 5);
        assert!(options.allow_broadcast && options.any_function);
    }

    /// The same capture with the Sungrow codes' lengths declared: no message
    /// archived short, and no fewer bytes framed than the search alone managed.
    #[test]
    #[ignore = "needs a capture: WIRETAP_RS485_RAW=<path to rs485.raw>"]
    fn declared_lengths_frame_the_sungrow_capture_whole() {
        let Ok(path) = std::env::var("WIRETAP_RS485_RAW") else {
            return;
        };
        let bytes = std::fs::read(&path).expect("the capture");
        let searched = ModbusRtuOptions::tapped();
        let declared = sungrow_tap();

        report(
            "search only",
            &frame_capture(&searched, &bytes, 4096),
            bytes.len(),
        );
        let got = frame_capture(&declared, &bytes, 64);
        let framed = report("declared", &got, bytes.len());
        for chunk in [4096, 1 << 16] {
            assert!(
                frame_capture(&declared, &bytes, chunk) == got,
                "{chunk}-byte reads frame differently from 64-byte reads"
            );
        }

        let short = |raw: &Vec<u8>| match raw[1] {
            0x60 => matches!(raw.len(), 18 | 26),
            // An 11-byte request reads with the same selector as a response.
            0x20 => {
                raw.get(4) == Some(&0x04)
                    && raw.len() != 11
                    && raw.get(5).map(|&n| 8 + n as usize) != Some(raw.len())
            }
            0x65 => raw.get(4).map(|&n| 7 + n as usize) != Some(raw.len()),
            _ => false,
        };
        assert_eq!(got.iter().filter(|r| short(r)).count(), 0);
        assert!(framed >= 34_029_275, "{framed} bytes framed");
    }

    /// Detection over the capture's tail, sampled as a consumer samples it: the
    /// codes named undeclared, and the catalogue's rules explaining the line.
    #[test]
    #[ignore = "needs a capture: WIRETAP_RS485_RAW=<path to rs485.raw>"]
    fn detection_names_the_sungrow_codes_and_their_rules_frame_the_capture() {
        let path = std::env::var("WIRETAP_RS485_RAW").expect("WIRETAP_RS485_RAW names the capture");
        let bytes = std::fs::read(&path).expect("the capture");
        let sample = &bytes[bytes.len().saturating_sub(100_000)..];
        let rules = Catalogue::parse(SUNGROW_FUNCTION_CODES)
            .unwrap()
            .rtu_options()
            .allow_broadcast();

        let stock = detect(sample, &ModbusRtuOptions::default());
        let declared = detect(sample, &rules);
        for (label, detection) in [("stock", &stock), ("rules", &declared)] {
            let rank = detection
                .candidates
                .iter()
                .position(|c| c.framing == Framing::ModbusRtu);
            let frames = rank.map(|i| detection.candidates[i].frames.count);
            eprintln!(
                "{label}: RTU ranked {rank:?} with {frames:?} frames; {:?}",
                detection.unframed
            );
        }

        for func in [0x20, 0x60, 0x65] {
            assert!(stock.unframed.functions.contains(&func), "{func:#04x}");
            assert!(!declared.unframed.functions.contains(&func), "{func:#04x}");
        }
        assert!(stock.unframed.broadcasts >= 3);
        assert_eq!(declared.candidates[0].framing, Framing::ModbusRtu);
        assert_eq!(declared.unframed.broadcasts, 0);
        assert!(declared.unframed.rejected.is_empty());
    }
}
