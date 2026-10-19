use super::*;

fn codes(input: &str) -> Vec<FaultCode> {
    parse(input).faults.iter().map(|fault| fault.code).collect()
}

#[test]
fn a_full_record_reads_every_tag() {
    let parsed = parse(
        "v=DMARC1; p=quarantine; sp=reject; np=reject; psd=n; t=y; adkim=s; aspf=r; pct=50; \
         fo=0:1:d:s; rf=afrf; ri=3600; rua=mailto:agg@example.com!10m; ruf=mailto:fail@example.com",
    );
    assert_eq!(parsed.faults, []);
    let r = &parsed.record;
    assert_eq!(r.policy, Some(Policy::Quarantine));
    assert_eq!(r.subdomain_policy, Some(Policy::Reject));
    assert_eq!(r.non_existent_policy, Some(Policy::Reject));
    assert_eq!(r.public_suffix_domain, Some(Psd::No));
    assert_eq!(r.testing, Some(true));
    assert_eq!(r.dkim_alignment, Some(Alignment::Strict));
    assert_eq!(r.spf_alignment, Some(Alignment::Relaxed));
    assert_eq!(r.percent, Some(50));
    assert_eq!(
        r.failure_options,
        Some(vec![
            FailureOption::AllFail,
            FailureOption::AnyFail,
            FailureOption::Dkim,
            FailureOption::Spf
        ])
    );
    assert_eq!(r.report_formats, Some(vec!["afrf".to_owned()]));
    assert_eq!(r.report_interval, Some(3600));
    assert_eq!(r.aggregate[0].mailbox(), Some("agg@example.com"));
    assert_eq!(r.aggregate[0].max_size, Some(10 << 20));
    assert_eq!(r.failure[0].mailbox(), Some("fail@example.com"));
    assert_eq!(r.tags.len(), 14);
    assert!(parsed.is_usable());
}

#[test]
fn defaults_apply_where_tags_are_absent() {
    let r = parse("v=DMARC1; p=reject").record;
    assert_eq!(r.effective_policy(), Some(Policy::Reject));
    assert_eq!(r.effective_subdomain_policy(), Some(Policy::Reject));
    assert_eq!(r.effective_non_existent_policy(), Some(Policy::Reject));
    assert_eq!(r.effective_dkim_alignment(), Alignment::Relaxed);
    assert_eq!(r.effective_spf_alignment(), Alignment::Relaxed);
    assert_eq!(r.effective_percent(), 100);
    assert!(!r.effective_testing());
    assert_eq!(r.effective_public_suffix_domain(), Psd::Unknown);
    assert_eq!(r.effective_failure_options(), [FailureOption::AllFail]);
    assert_eq!(r.effective_report_interval(), 86_400);
    assert_eq!(r.percent, None);
}

#[test]
fn np_defaults_to_sp_which_defaults_to_p() {
    let r = parse("v=DMARC1; p=reject; sp=quarantine").record;
    assert_eq!(r.effective_non_existent_policy(), Some(Policy::Quarantine));
    let r = parse("v=DMARC1; p=none; np=reject").record;
    assert_eq!(r.effective_subdomain_policy(), Some(Policy::None));
    assert_eq!(r.effective_non_existent_policy(), Some(Policy::Reject));
}

#[test]
fn an_invalid_or_missing_policy_is_treated_as_none_when_rua_is_valid() {
    for input in [
        "v=DMARC1; rua=mailto:r@example.com",
        "v=DMARC1; p=block; rua=mailto:r@example.com",
        "v=DMARC1; p=reject; sp=block; rua=mailto:r@example.com",
    ] {
        let parsed = parse(input);
        assert!(parsed.record.policy_treated_as_none(), "{input}");
        assert_eq!(
            parsed.record.effective_policy(),
            Some(Policy::None),
            "{input}"
        );
        assert!(parsed.is_usable(), "{input}");
    }
    for input in [
        "v=DMARC1",
        "v=DMARC1; p=block",
        "v=DMARC1; p=block; rua=r@example.com",
    ] {
        let parsed = parse(input);
        assert_eq!(parsed.record.effective_policy(), None, "{input}");
        assert!(!parsed.is_usable(), "{input}");
    }
}

#[test]
fn the_version_must_come_first() {
    assert_eq!(codes("p=none; v=DMARC1"), [FaultCode::VersionNotFirst]);
    assert!(!parse("p=none; v=DMARC1").is_usable());
    assert_eq!(codes("v=DMARC2; p=none"), [FaultCode::InvalidVersion]);
    assert_eq!(codes("p=none"), [FaultCode::MissingVersion]);
    assert!(is_dmarc("v=DMARC1; p=none"));
    assert!(is_dmarc(" \"V = dmarc1;p=none\""));
    assert!(!is_dmarc("p=none; v=DMARC1"));
    assert!(!is_dmarc("v=spf1 -all"));
}

#[test]
fn every_fault_code() {
    for (input, code, name) in [
        ("v=DMARC1; p=none; junk", FaultCode::MalformedTag, None),
        (
            "v=DMARC1; p=none; p=reject",
            FaultCode::DuplicateTag,
            Some("p"),
        ),
        (
            "v=DMARC1; p=none; foo=bar",
            FaultCode::UnknownTag,
            Some("foo"),
        ),
        ("v=DMARC1; sp=none", FaultCode::MissingTag, Some("p")),
        (
            "v=DMARC1; p=none; pct=101",
            FaultCode::InvalidTagValue,
            Some("pct"),
        ),
        (
            "v=DMARC1; p=none; pct=+5",
            FaultCode::InvalidTagValue,
            Some("pct"),
        ),
        (
            "v=DMARC1; p=none; adkim=x",
            FaultCode::InvalidTagValue,
            Some("adkim"),
        ),
        (
            "v=DMARC1; p=none; aspf=relaxed",
            FaultCode::InvalidTagValue,
            Some("aspf"),
        ),
        (
            "v=DMARC1; p=none; fo=0:2",
            FaultCode::InvalidTagValue,
            Some("fo"),
        ),
        (
            "v=DMARC1; p=none; rf=af-rf",
            FaultCode::InvalidTagValue,
            Some("rf"),
        ),
        (
            "v=DMARC1; p=none; ri=daily",
            FaultCode::InvalidTagValue,
            Some("ri"),
        ),
        (
            "v=DMARC1; p=none; np=block",
            FaultCode::InvalidTagValue,
            Some("np"),
        ),
        (
            "v=DMARC1; p=none; psd=maybe",
            FaultCode::InvalidTagValue,
            Some("psd"),
        ),
        (
            "v=DMARC1; p=none; t=yes",
            FaultCode::InvalidTagValue,
            Some("t"),
        ),
        (
            "v=DMARC1; p=none; rua=reports@example.com",
            FaultCode::InvalidUri,
            Some("rua"),
        ),
        (
            "v=DMARC1; p=none; ruf=mailto:",
            FaultCode::InvalidUri,
            Some("ruf"),
        ),
    ] {
        let parsed = parse(input);
        assert_eq!(codes(input), [code], "{input}");
        assert_eq!(parsed.faults[0].name.as_deref(), name, "{input}");
    }
}

#[test]
fn tag_names_and_keywords_are_case_insensitive_and_the_first_duplicate_wins() {
    let parsed = parse("V=DMARC1; P=Reject; ADKIM=S; p=none");
    assert_eq!(parsed.record.policy, Some(Policy::Reject));
    assert_eq!(parsed.record.dkim_alignment, Some(Alignment::Strict));
    assert_eq!(parsed.record.tags[1].name, "p");
}

#[test]
fn spans_point_at_the_offending_text() {
    let input = "\u{feff}\"v=DMARC1; p=none; pct=200; rua=mailto:a@example.com,bad\"";
    let parsed = parse(input);
    let spans: Vec<&str> = parsed
        .faults
        .iter()
        .map(|f| &input[f.span.clone()])
        .collect();
    assert_eq!(spans, ["200", "bad"]);
}

#[test]
fn reports_to_compares_mailboxes_exactly() {
    let r = parse("v=DMARC1; p=none; rua=mailto:Reports@example.com,mailto:x@example.net; ruf=mailto:ours@example.com").record;
    assert!(r.reports_to("reports@example.com"));
    assert!(r.reports_to("mailto:x@example.net"));
    assert!(!r.reports_to("ours@example.com"));
    assert!(!r.reports_to("ports@example.com"));
}

#[test]
fn display_renders_the_tags_as_written() {
    let parsed = parse("  v=DMARC1 ;p = reject;  RUA=mailto:r@example.com;  ");
    assert_eq!(
        parsed.record.to_string(),
        "v=DMARC1; p=reject; rua=mailto:r@example.com"
    );
}

#[test]
fn the_builder_orders_tags_canonically() {
    let record = DmarcBuilder::new(Policy::Reject)
        .aggregate("r@example.com")
        .aggregate("mailto:s@example.net!10m")
        .percent(150)
        .subdomain_policy(Policy::Quarantine)
        .dkim_alignment(Alignment::Strict)
        .failure_option(FailureOption::Dkim)
        .failure_option(FailureOption::Spf)
        .build();
    assert_eq!(
        record,
        "v=DMARC1; p=reject; sp=quarantine; adkim=s; pct=100; fo=d:s; rua=mailto:r@example.com,mailto:s@example.net!10m"
    );
    let parsed = parse(&record);
    assert_eq!(parsed.faults, []);
    assert_eq!(DmarcBuilder::new(Policy::None).build(), "v=DMARC1; p=none");
}

#[test]
fn with_aggregate_appends_or_adds_rua_and_keeps_the_rest() {
    assert_eq!(
        with_aggregate("v=DMARC1; p=none", "r@example.com"),
        "v=DMARC1; p=none; rua=mailto:r@example.com"
    );
    assert_eq!(
        with_aggregate(
            "\"v=DMARC1; p=reject; RUA=mailto:a@example.net; adkim=s;\"",
            "mailto:r@example.com"
        ),
        "v=DMARC1; p=reject; RUA=mailto:a@example.net,mailto:r@example.com; adkim=s"
    );
    assert_eq!(
        with_aggregate(
            "v=DMARC1; p=none; rua=mailto:R@example.com",
            "r@example.com"
        ),
        "v=DMARC1; p=none; rua=mailto:R@example.com"
    );
}

#[test]
fn an_invalid_sp_without_a_usable_rua_means_no_dmarc_processing() {
    let parsed = parse("v=DMARC1; p=reject; sp=bogus");
    assert!(!parsed.record.policy_treated_as_none());
    assert_eq!(parsed.record.effective_policy(), None);
    assert_eq!(parsed.record.effective_subdomain_policy(), None);
    assert_eq!(parsed.record.effective_non_existent_policy(), None);
    assert!(!parsed.is_usable());
    let parsed = parse("v=DMARC1; p=reject; sp=bogus; rua=reports@example.com");
    assert_eq!(parsed.record.effective_policy(), None);
    assert!(!parsed.is_usable());
}

#[test]
fn the_wrong_case_of_dmarc1_is_out_of_spec_but_usable() {
    let input = "v=dmarc1; p=none";
    let parsed = parse(input);
    assert_eq!(codes(input), [FaultCode::NoncanonicalVersion]);
    assert_eq!(&input[parsed.faults[0].span.clone()], "dmarc1");
    assert!(parsed.is_usable());
}

#[test]
fn p_belongs_directly_after_v() {
    let input = "v=DMARC1; rua=mailto:r@example.com; p=reject";
    let parsed = parse(input);
    assert_eq!(codes(input), [FaultCode::TagOutOfOrder]);
    assert_eq!(parsed.faults[0].name.as_deref(), Some("p"));
    assert_eq!(&input[parsed.faults[0].span.clone()], "p=reject");
    assert_eq!(parsed.record.effective_policy(), Some(Policy::Reject));
    assert!(parsed.is_usable());
    assert_eq!(codes("p=none; v=DMARC1"), [FaultCode::VersionNotFirst]);
}
