use super::*;

fn codes(input: &str) -> Vec<FaultCode> {
    parse(input).faults.iter().map(|fault| fault.code).collect()
}

fn mechanisms(input: &str) -> Vec<Mechanism> {
    let parsed = parse(input);
    assert!(parsed.is_usable(), "{input}: {:?}", parsed.faults);
    parsed.record.directives().map(|(_, m)| m.clone()).collect()
}

fn spec(raw: &str) -> MacroString {
    macros::parse(raw, false).unwrap()
}

#[test]
fn valid_records_from_rfc_7208_appendix_a() {
    for input in [
        "v=spf1 +all",
        "v=spf1 a -all",
        "v=spf1 a:example.org -all",
        "v=spf1 mx -all",
        "v=spf1 mx:example.org -all",
        "v=spf1 mx mx:example.org -all",
        "v=spf1 mx/30 mx:example.org/30 -all",
        "v=spf1 ptr -all",
        "v=spf1 ip4:192.0.2.128/28 -all",
        "v=spf1 include:example.com include:example.net -all",
        "v=spf1 redirect=example.org",
        "v=spf1 mx -all exp=explain._spf.%{d}",
        "v=spf1 exists:%{ir}.%{l1r+-}._spf.%{d} -all",
        "v=spf1 ip6:2001:db8::/32 a//64 a:example.com/24//64 ~all",
        "v=spf1",
    ] {
        let parsed = parse(input);
        assert!(parsed.is_usable(), "{input}: {:?}", parsed.faults);
    }
}

#[test]
fn mechanisms_are_typed() {
    assert_eq!(
        mechanisms(
            "v=spf1 a mx:example.org/30//64 ip4:192.0.2.0/24 ip6:2001:db8::1 include:_spf.example.com -all"
        ),
        [
            Mechanism::A {
                domain: None,
                cidr: DualCidr::default()
            },
            Mechanism::Mx {
                domain: Some(spec("example.org")),
                cidr: DualCidr {
                    ip4: Some(30),
                    ip6: Some(64)
                }
            },
            Mechanism::Ip4 {
                address: "192.0.2.0".parse().unwrap(),
                prefix: Some(24)
            },
            Mechanism::Ip6 {
                address: "2001:db8::1".parse().unwrap(),
                prefix: None
            },
            Mechanism::Include(spec("_spf.example.com")),
            Mechanism::All,
        ]
    );
}

#[test]
fn qualifiers_default_to_pass() {
    let parsed = parse("v=spf1 a +mx -ip4:192.0.2.1 ~include:example.com ?all");
    let qualifiers: Vec<Qualifier> = parsed.record.directives().map(|(q, _)| q).collect();
    assert_eq!(
        qualifiers,
        [
            Qualifier::Pass,
            Qualifier::Pass,
            Qualifier::Fail,
            Qualifier::SoftFail,
            Qualifier::Neutral
        ]
    );
}

#[test]
fn names_are_case_insensitive() {
    assert!(parse("V=SPF1 MX INCLUDE:example.com Redirect=example.net").is_usable());
}

#[test]
fn the_version_must_be_v_spf1_alone() {
    assert_eq!(
        codes("include:example.com -all"),
        [FaultCode::MissingVersion]
    );
    assert_eq!(codes("v=spf10 -all"), [FaultCode::InvalidVersion]);
    assert_eq!(codes("v=spf1;-all"), [FaultCode::InvalidVersion]);
    assert!(is_spf("v=spf1 -all"));
    assert!(is_spf("\"v=spf1\""));
    assert!(!is_spf("v=spf10"));
    assert!(!is_spf("v=spf1\t-all"));
    assert!(!is_spf("spf2.0/pra"));
}

#[test]
fn every_fault_code() {
    for (input, code) in [
        ("v=spf1 foo:example.com", FaultCode::UnknownMechanism),
        ("v=spf1 ip:192.0.2.1", FaultCode::UnknownMechanism),
        ("v=spf1 all:example.com", FaultCode::InvalidTerm),
        ("v=spf1 -redirect=example.com", FaultCode::InvalidTerm),
        ("v=spf1 1x=y", FaultCode::InvalidTerm),
        ("v=spf1 ptr/24", FaultCode::InvalidTerm),
        ("v=spf1 ptrx", FaultCode::UnknownMechanism),
        ("v=spf1 include", FaultCode::MissingDomainSpec),
        ("v=spf1 include:", FaultCode::MissingDomainSpec),
        ("v=spf1 exists", FaultCode::MissingDomainSpec),
        ("v=spf1 a:", FaultCode::MissingDomainSpec),
        ("v=spf1 redirect=", FaultCode::MissingDomainSpec),
        ("v=spf1 include:localhost", FaultCode::InvalidDomainSpec),
        ("v=spf1 include:192.0.2.1", FaultCode::InvalidDomainSpec),
        ("v=spf1 include:%{x}.example.com", FaultCode::InvalidMacro),
        ("v=spf1 exists:%{c}.example.com", FaultCode::InvalidMacro),
        ("v=spf1 ip4:192.0.2.0/33", FaultCode::InvalidCidr),
        ("v=spf1 ip4:192.0.2.0/024", FaultCode::InvalidCidr),
        ("v=spf1 ip6:2001:db8::/129", FaultCode::InvalidCidr),
        ("v=spf1 a/33", FaultCode::InvalidCidr),
        ("v=spf1 mx//64/24", FaultCode::InvalidCidr),
        ("v=spf1 ip4:192.0.2", FaultCode::InvalidAddress),
        ("v=spf1 ip4:2001:db8::1", FaultCode::InvalidAddress),
        ("v=spf1 ip6:192.0.2.1", FaultCode::InvalidAddress),
        ("v=spf1 ip4", FaultCode::InvalidAddress),
        (
            "v=spf1 redirect=a.example.com redirect=b.example.com",
            FaultCode::DuplicateModifier,
        ),
        (
            "v=spf1 exp=a.example.com exp=b.example.com",
            FaultCode::DuplicateModifier,
        ),
    ] {
        let parsed = parse(input);
        assert_eq!(codes(input), [code], "{input}");
        assert!(!parsed.is_usable(), "{input}");
    }
}

#[test]
fn unknown_modifiers_are_kept_and_not_faults() {
    let parsed = parse("v=spf1 moo=cow -all");
    assert!(parsed.is_usable());
    assert_eq!(
        parsed.record.terms[0].term,
        Term::UnknownModifier {
            name: "moo".into(),
            value: "cow".into()
        }
    );
}

#[test]
fn parsing_continues_past_faults_and_spans_point_at_the_term() {
    let input = "\u{feff}\"v=spf1 include:example.com bogus ip4:192.0.2.300 -all\"";
    let parsed = parse(input);
    assert_eq!(parsed.record.terms.len(), 4);
    assert_eq!(parsed.record.all(), Some((3, Qualifier::Fail)));
    let spans: Vec<&str> = parsed
        .faults
        .iter()
        .map(|f| &input[f.span.clone()])
        .collect();
    assert_eq!(spans, ["bogus", "ip4:192.0.2.300"]);
}

#[test]
fn accessors_find_redirect_explanation_and_includes() {
    let parsed = parse(
        "v=spf1 include:a.example.com include:%{d}.example.net redirect=b.example.com exp=c.example.com",
    );
    assert_eq!(parsed.record.redirect().unwrap().raw, "b.example.com");
    assert_eq!(parsed.record.explanation().unwrap().raw, "c.example.com");
    assert_eq!(
        parsed.record.includes().collect::<Vec<_>>(),
        ["a.example.com"]
    );
    assert!(parsed.record.all().is_none());
}

#[test]
fn display_is_canonical() {
    let parsed = parse("  V=SPF1   +A  MX:Example.org/30//64 IP4:192.0.2.0/24 ~ALL  ");
    assert_eq!(
        parsed.record.to_string(),
        "v=spf1 a mx:Example.org/30//64 ip4:192.0.2.0/24 ~all"
    );
    let parsed = parse("v=spf1 bogus redirect=example.com");
    assert_eq!(
        parsed.record.to_string(),
        "v=spf1 bogus redirect=example.com"
    );
}

#[test]
fn with_includes_inserts_before_all_and_skips_existing() {
    assert_eq!(
        with_includes(
            "v=spf1 ip4:192.0.2.1 ~all",
            ["_spf.example.com", "_spf.example.net"]
        ),
        "v=spf1 ip4:192.0.2.1 include:_spf.example.com include:_spf.example.net ~all"
    );
    assert_eq!(
        with_includes(
            "v=spf1 include:_SPF.example.com -all",
            ["_spf.example.com", "_spf.example.net"]
        ),
        "v=spf1 include:_SPF.example.com include:_spf.example.net -all"
    );
    assert_eq!(
        with_includes("\"v=spf1 mx redirect=example.org\"", ["_spf.example.com"]),
        "v=spf1 mx redirect=example.org include:_spf.example.com"
    );
    assert_eq!(
        with_includes("v=spf1 -all", ["a.example.com", "a.example.com"]),
        "v=spf1 include:a.example.com -all"
    );
}
