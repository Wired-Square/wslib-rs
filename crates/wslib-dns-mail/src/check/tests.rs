use std::collections::HashSet;
use std::net::IpAddr;

use wslib_dns::{FakeResolver, LookupError, RecordType};

use super::*;
use crate::discover::block_on;

const RSA_512: &str = include_str!("../../testdata/dkim/rsa512.b64");
const RSA_1024: &str = include_str!("../../testdata/dkim/rsa1024.b64");
const RSA_2048: &str = include_str!("../../testdata/dkim/rsa2048.b64");

fn ip(text: &str) -> IpAddr {
    text.parse().unwrap()
}

fn codes(findings: &[Finding]) -> Vec<FindingCode> {
    findings.iter().map(|finding| finding.code).collect()
}

fn spf(dns: &FakeResolver, domain: &str) -> Vec<FindingCode> {
    codes(&block_on(check_spf(dns, domain, WalkLimits::default())).findings)
}

fn dmarc(dns: &FakeResolver, domain: &str) -> Vec<FindingCode> {
    codes(&block_on(check_dmarc(dns, domain, DmarcDiscoveryMode::Rfc7489)).findings)
}

fn with_spf(record: &str) -> FakeResolver {
    FakeResolver::new()
        .with_txt("example.com", [record])
        .with_ip("example.com", [ip("198.51.100.1")])
}

#[test]
fn every_code_has_a_unique_snake_case_name() {
    let names: HashSet<&str> = FindingCode::ALL.iter().map(|code| code.as_str()).collect();
    assert_eq!(names.len(), FindingCode::ALL.len());
    for code in FindingCode::ALL {
        let name = code.as_str();
        assert!(
            name.bytes().all(|b| b.is_ascii_lowercase() || b == b'_'),
            "{name}"
        );
    }
}

#[cfg(feature = "serde")]
#[test]
fn codes_serialise_by_their_names() {
    for code in FindingCode::ALL {
        assert_eq!(
            serde_json::to_string(code).unwrap(),
            format!("\"{}\"", code.as_str())
        );
    }
    let finding = Finding::new(
        FindingCode::DmarcPctPartial,
        "_dmarc.example.com",
        Detail::Percent { percent: 50 },
    );
    assert_eq!(
        serde_json::to_string(&finding).unwrap(),
        r#"{"code":"dmarc_pct_partial","kind":"practice","severity":"warning","subject":"_dmarc.example.com","reference":"RFC 7489 §6.3","detail":{"kind":"percent","percent":50}}"#
    );
}

#[test]
fn a_clean_spf_record_has_no_findings() {
    assert_eq!(
        spf(&with_spf("v=spf1 a ip4:192.0.2.0/24 -all"), "example.com"),
        []
    );
}

#[test]
fn spf_presence_and_syntax() {
    for (records, expected) in [
        (vec![], FindingCode::SpfMissing),
        (
            vec!["v=spf1 -all", "v=spf1 ~all"],
            FindingCode::SpfMultipleRecords,
        ),
        (vec!["v=spf1 bogus -all"], FindingCode::SpfSyntax),
        (vec!["v=spf1 a\t-all"], FindingCode::SpfInvalidSeparator),
        (
            vec!["v=spf1 include=_spf.example.net -all"],
            FindingCode::SpfModifierNamedLikeMechanism,
        ),
    ] {
        let dns = FakeResolver::new()
            .with_ip("example.com", [ip("198.51.100.1")])
            .with_txt("example.com", records.clone());
        assert_eq!(spf(&dns, "example.com"), [expected], "{records:?}");
    }
}

#[test]
fn spf_limits() {
    let dns = with_spf(&format!("v=spf1 {} -all", ["a"; 11].join(" ")));
    assert_eq!(
        spf(&dns, "example.com"),
        [FindingCode::SpfLookupLimitExceeded]
    );
    let dns = with_spf("v=spf1 a:v1.example.com a:v2.example.com a:v3.example.com -all");
    assert_eq!(
        spf(&dns, "example.com"),
        [FindingCode::SpfVoidLookupLimitExceeded]
    );
    let mut dns = with_spf("v=spf1 mx -all");
    for n in 0..11 {
        dns = dns.with_mx("example.com", n, &format!("mx{n}.example.com"));
    }
    assert_eq!(
        spf(&dns, "example.com"),
        [FindingCode::SpfMxPtrNameLimitExceeded]
    );
}

#[test]
fn spf_targets_loops_and_failures() {
    let dns = with_spf("v=spf1 include:nothing.example.net -all");
    assert_eq!(
        spf(&dns, "example.com"),
        [FindingCode::SpfIncludeTargetMissing]
    );
    let dns = with_spf("v=spf1 redirect=nothing.example.net");
    assert_eq!(
        spf(&dns, "example.com"),
        [FindingCode::SpfRedirectTargetMissing]
    );
    let dns = with_spf("v=spf1 include:broken.example.net -all").with_error(
        "broken.example.net",
        RecordType::Txt,
        LookupError::ServFail,
    );
    assert_eq!(spf(&dns, "example.com"), [FindingCode::SpfLookupFailed]);
    let dns = with_spf("v=spf1 include:example.net -all")
        .with_txt("example.net", ["v=spf1 include:example.com -all"]);
    assert_eq!(spf(&dns, "example.com"), [FindingCode::SpfLoop]);
    let dns = FakeResolver::new().with_error("example.com", RecordType::Txt, LookupError::Timeout);
    assert_eq!(spf(&dns, "example.com"), [FindingCode::LookupFailed]);
}

#[test]
fn spf_practices() {
    for (record, expected) in [
        ("v=spf1 ptr -all", vec![FindingCode::SpfPtrUsed]),
        ("v=spf1 +all", vec![FindingCode::SpfPermissiveAll]),
        ("v=spf1 a ?all", vec![FindingCode::SpfNeutralAll]),
        ("v=spf1 a", vec![FindingCode::SpfNoAll]),
        ("v=spf1 -all a", vec![FindingCode::SpfTermsAfterAll]),
        (
            "v=spf1 -all redirect=_spf.example.net",
            vec![FindingCode::SpfRedirectIgnored],
        ),
        (
            "v=spf1 ip4:10.0.0.0/8 -all",
            vec![FindingCode::SpfPrivateNetblock],
        ),
    ] {
        assert_eq!(spf(&with_spf(record), "example.com"), expected, "{record}");
    }
    let long = format!(
        "v=spf1 {} -all",
        (0..40)
            .map(|n| format!("ip4:192.0.2.{n}"))
            .collect::<Vec<_>>()
            .join(" ")
    );
    assert_eq!(
        spf(&with_spf(&long), "example.com"),
        [FindingCode::SpfRecordTooLong]
    );
}

#[test]
fn a_clean_dmarc_record_has_no_findings() {
    let dns = FakeResolver::new().with_txt(
        "_dmarc.example.com",
        ["v=DMARC1; p=reject; rua=mailto:dmarc@example.com"],
    );
    assert_eq!(dmarc(&dns, "example.com"), []);
}

#[test]
fn dmarc_presence_and_syntax() {
    for (records, expected) in [
        (vec![], vec![FindingCode::DmarcMissing]),
        (
            vec!["v=DMARC1; p=none", "v=DMARC1; p=reject"],
            vec![FindingCode::DmarcMultipleRecords],
        ),
        (
            vec!["p=reject; v=DMARC1"],
            vec![FindingCode::DmarcVersionNotFirst, FindingCode::DmarcMissing],
        ),
        (
            vec!["v=dmarc1; p=reject; rua=mailto:d@example.com"],
            vec![FindingCode::DmarcVersionNoncanonical],
        ),
        (
            vec!["v=DMARC1; rua=mailto:d@example.com; p=reject"],
            vec![FindingCode::DmarcPolicyOutOfOrder],
        ),
        (
            vec!["v=DMARC1; p=reject; junk; rua=mailto:d@example.com"],
            vec![FindingCode::DmarcSyntax],
        ),
        (
            vec!["v=DMARC1; p=reject; pct=200; rua=mailto:d@example.com"],
            vec![FindingCode::DmarcTagValueInvalid],
        ),
        (
            vec!["v=DMARC1; p=reject; p=none; rua=mailto:d@example.com"],
            vec![FindingCode::DmarcTagDuplicate],
        ),
        (
            vec!["v=DMARC1; p=reject; foo=bar; rua=mailto:d@example.com"],
            vec![FindingCode::DmarcTagUnknown],
        ),
        (
            vec!["v=DMARC1; p=reject; rua=d@example.com"],
            vec![
                FindingCode::DmarcReportUriInvalid,
                FindingCode::DmarcNoAggregateReports,
            ],
        ),
    ] {
        let dns = FakeResolver::new().with_txt("_dmarc.example.com", records.clone());
        assert_eq!(dmarc(&dns, "example.com"), expected, "{records:?}");
    }
}

#[test]
fn a_broken_policy_says_whether_rua_saves_it() {
    let check = |record: &str| {
        let dns = FakeResolver::new().with_txt("_dmarc.example.com", [record]);
        block_on(check_dmarc(
            &dns,
            "example.com",
            DmarcDiscoveryMode::Rfc7489,
        ))
        .findings
    };
    let missing = check("v=DMARC1; rua=mailto:d@example.com");
    assert_eq!(
        codes(&missing),
        [
            FindingCode::DmarcPolicyMissing,
            FindingCode::DmarcPolicyNone
        ]
    );
    assert_eq!(
        missing[0].detail,
        Detail::Policy {
            tag: "p".into(),
            treated_as_none: true
        }
    );
    let invalid = check("v=DMARC1; p=block");
    assert_eq!(
        codes(&invalid),
        [
            FindingCode::DmarcPolicyInvalid,
            FindingCode::DmarcNoAggregateReports
        ]
    );
    assert_eq!(
        invalid[0].detail,
        Detail::Policy {
            tag: "p".into(),
            treated_as_none: false
        }
    );
}

#[test]
fn dmarc_practices_and_inheritance() {
    for (record, expected) in [
        (
            "v=DMARC1; p=reject; pct=50; rua=mailto:d@example.com",
            vec![FindingCode::DmarcPctPartial],
        ),
        (
            "v=DMARC1; p=reject; sp=none; rua=mailto:d@example.com",
            vec![FindingCode::DmarcSubdomainPolicyWeaker],
        ),
        (
            "v=DMARC1; p=reject",
            vec![FindingCode::DmarcNoAggregateReports],
        ),
        (
            "v=DMARC1; p=none; rua=mailto:d@example.com",
            vec![FindingCode::DmarcPolicyNone],
        ),
    ] {
        let dns = FakeResolver::new().with_txt("_dmarc.example.com", [record]);
        assert_eq!(dmarc(&dns, "example.com"), expected, "{record}");
    }
    let dns = FakeResolver::new()
        .with_ip("mail.example.com", [ip("192.0.2.1")])
        .with_txt(
            "_dmarc.example.com",
            ["v=DMARC1; p=reject; rua=mailto:d@example.com"],
        );
    assert_eq!(
        dmarc(&dns, "mail.example.com"),
        [FindingCode::DmarcPolicyInherited]
    );
}

#[test]
fn external_report_destinations_must_authorise() {
    let dns = FakeResolver::new()
        .with_txt(
            "_dmarc.example.com",
            ["v=DMARC1; p=reject; rua=mailto:d@reports.example.net,mailto:e@other.example.net,mailto:f@slow.example.org"],
        )
        .with_txt("example.com._report._dmarc.reports.example.net", ["v=DMARC1"])
        .with_error("example.com._report._dmarc.slow.example.org", RecordType::Txt, LookupError::Timeout);
    assert_eq!(
        dmarc(&dns, "example.com"),
        [
            FindingCode::DmarcExternalReportUnauthorised,
            FindingCode::DmarcExternalReportLookupFailed
        ]
    );
}

fn dkim(dns: &FakeResolver, selectors: &[&str]) -> Vec<FindingCode> {
    let selectors: Vec<String> = selectors.iter().map(|s| (*s).to_owned()).collect();
    codes(&block_on(check_dkim(dns, "example.com", &selectors, false)).findings)
}

#[test]
fn dkim_findings_per_selector() {
    let key = |name: &str, record: String| {
        FakeResolver::new().with_txt(&format!("{name}._domainkey.example.com"), [record.as_str()])
    };
    assert_eq!(
        dkim(&key("s1", format!("v=DKIM1; p={RSA_2048}")), &["s1"]),
        []
    );
    assert_eq!(
        dkim(&FakeResolver::new(), &["s1"]),
        [FindingCode::DkimKeyMissing]
    );
    let two =
        FakeResolver::new().with_txt("s1._domainkey.example.com", ["v=DKIM1; p=", "v=DKIM1; p="]);
    assert_eq!(dkim(&two, &["s1"]), [FindingCode::DkimMultipleRecords]);
    for (record, expected) in [
        ("v=DKIM1; p=not*base64".to_owned(), FindingCode::DkimSyntax),
        ("v=DKIM1; p=".to_owned(), FindingCode::DkimKeyRevoked),
        (
            format!("v=DKIM1; t=y; p={RSA_2048}"),
            FindingCode::DkimTestingMode,
        ),
        (
            format!("v=DKIM1; p={RSA_512}"),
            FindingCode::DkimRsaKeyTooShort,
        ),
        (
            format!("v=DKIM1; p={RSA_1024}"),
            FindingCode::DkimRsaKeyWeak,
        ),
    ] {
        assert_eq!(
            dkim(&key("s1", record.clone()), &["s1"]),
            [expected],
            "{record}"
        );
    }
    let lowercase = dkim_findings(
        &block_on(check_dkim(
            &key("s1", "v=dkim1; p=".into()),
            "example.com",
            &["s1".into()],
            false,
        ))
        .selectors,
    );
    assert_eq!(lowercase[0].severity, Severity::Warning);
}

#[test]
fn probing_reports_only_what_it_finds() {
    let dns = FakeResolver::new().with_txt(
        "google._domainkey.example.com",
        [format!("v=DKIM1; p={RSA_1024}").as_str()],
    );
    let check = block_on(check_dkim(&dns, "example.com", &[], true));
    assert_eq!(check.selectors.len(), 1);
    assert_eq!(codes(&check.findings), [FindingCode::DkimRsaKeyWeak]);
}

fn mx(dns: &FakeResolver, zones: &[&str]) -> Vec<FindingCode> {
    let zones: Vec<String> = zones.iter().map(|z| (*z).to_owned()).collect();
    codes(&block_on(check_mx(dns, "example.com", &zones)).findings)
}

fn good_mx() -> FakeResolver {
    FakeResolver::new()
        .with_mx("example.com", 10, "mail.example.com")
        .with_ip("mail.example.com", [ip("192.0.2.25")])
        .with_ptr(ip("192.0.2.25"), "mail.example.com")
}

#[test]
fn mx_findings_per_exchange() {
    assert_eq!(mx(&good_mx(), &[]), []);
    assert_eq!(
        mx(
            &FakeResolver::new().with_ip("example.com", [ip("192.0.2.1")]),
            &[]
        ),
        [FindingCode::MxMissing]
    );
    let null = FakeResolver::new().with_mx("example.com", 0, ".");
    assert_eq!(mx(&null, &[]), []);
    let mixed = good_mx().with_mx("example.com", 0, ".");
    assert_eq!(mx(&mixed, &[]), [FindingCode::MxNullWithOthers]);
    let servfail_on_cname =
        good_mx().with_error("mail.example.com", RecordType::Cname, LookupError::ServFail);
    assert_eq!(mx(&servfail_on_cname, &[]), []);
    let alias = good_mx()
        .with_cname("mail.example.com", "host.example.net")
        .with_ip("host.example.net", [ip("192.0.2.25")]);
    assert_eq!(mx(&alias, &[]), [FindingCode::MxExchangeIsCname]);
    let literal = FakeResolver::new().with_mx("example.com", 10, "192.0.2.25");
    assert_eq!(mx(&literal, &[]), [FindingCode::MxExchangeIsIpLiteral]);
    let nowhere = FakeResolver::new().with_mx("example.com", 10, "gone.example.com");
    assert_eq!(mx(&nowhere, &[]), [FindingCode::MxExchangeNoAddress]);
    let severity = |dns: &FakeResolver| {
        let check = block_on(check_mx(dns, "example.com", &[]));
        check
            .findings
            .iter()
            .find(|f| f.code == FindingCode::MxExchangeNoAddress)
            .map(|f| f.severity)
    };
    assert_eq!(severity(&nowhere), Some(Severity::Error));
    let alongside = good_mx().with_mx("example.com", 50, "token.verify.example.net");
    assert_eq!(mx(&alongside, &[]), [FindingCode::MxExchangeNoAddress]);
    assert_eq!(severity(&alongside), Some(Severity::Warning));
    let no_ptr = FakeResolver::new()
        .with_mx("example.com", 10, "mail.example.com")
        .with_ip("mail.example.com", [ip("192.0.2.25")]);
    assert_eq!(mx(&no_ptr, &[]), [FindingCode::MxPtrMissing]);
    let mismatch = no_ptr.with_ptr(ip("192.0.2.25"), "other.example.net");
    assert_eq!(mx(&mismatch, &[]), [FindingCode::MxFcrdnsMismatch]);
}

#[test]
fn mx_addresses_against_blocklists() {
    let dns = good_mx()
        .with_ip("25.2.0.192.listed.example.org", [ip("127.0.0.2")])
        .with_ip("25.2.0.192.blocked.example.org", [ip("127.255.255.254")]);
    assert_eq!(
        mx(
            &dns,
            &[
                "listed.example.org",
                "blocked.example.org",
                "clean.example.org"
            ]
        ),
        [FindingCode::MxListed, FindingCode::MxDnsblQueryBlocked]
    );
}

fn bimi_codes(bimi: &str, dmarc: &str) -> Vec<FindingCode> {
    let dns = FakeResolver::new()
        .with_txt("default._bimi.example.com", [bimi])
        .with_txt("_dmarc.example.com", [dmarc]);
    let records = block_on(discover::bimi(&dns, "example.com", "default"));
    let discovery = block_on(discover::dmarc(
        &dns,
        "example.com",
        DmarcDiscoveryMode::Rfc7489,
    ));
    codes(&bimi_findings(&records, &[&discovery]))
}

#[test]
fn bimi_needs_https_and_an_enforcing_dmarc_policy() {
    let enforcing = "v=DMARC1; p=reject";
    assert_eq!(
        bimi_codes("v=BIMI1; l=https://example.com/logo.svg", enforcing),
        []
    );
    assert_eq!(
        bimi_codes("v=BIMI1; l=http://example.com/logo.svg", enforcing),
        [FindingCode::BimiInsecureUri]
    );
    assert_eq!(
        bimi_codes("v=BIMI1; l=https://example.com/logo.svg; l=", enforcing),
        [FindingCode::BimiSyntax]
    );
    for dmarc in [
        "v=DMARC1; p=none",
        "v=DMARC1; p=reject; pct=50",
        "v=DMARC1; p=reject; sp=none",
    ] {
        assert_eq!(
            bimi_codes("v=BIMI1; l=https://example.com/logo.svg", dmarc),
            [FindingCode::BimiDmarcNotEnforcing],
            "{dmarc}"
        );
    }
    assert_eq!(bimi_codes("v=BIMI1; l=", "v=DMARC1; p=none"), []);
}

fn sts(
    record: &str,
    tls_rpt: Option<&str>,
    policy: Option<PolicyFetch>,
    dns: FakeResolver,
) -> Vec<FindingCode> {
    let mut dns = dns.with_txt("_mta-sts.example.com", [record]);
    if let Some(tls_rpt) = tls_rpt {
        dns = dns.with_txt("_smtp._tls.example.com", [tls_rpt]);
    }
    let record = block_on(discover::mta_sts(&dns, "example.com"));
    let tls = block_on(discover::tls_rpt(&dns, "example.com"));
    let mx = block_on(discover::mx(&dns, "example.com"));
    codes(&mta_sts_findings(&record, policy.as_ref(), &tls, Some(&mx)))
}

fn fetched(body: &str) -> Option<PolicyFetch> {
    Some(PolicyFetch::Fetched {
        url: "https://mta-sts.example.com/.well-known/mta-sts.txt".into(),
        body: body.into(),
        policy: crate::mta_sts::parse_policy(body),
    })
}

#[test]
fn mta_sts_and_tls_rpt() {
    let rpt = Some("v=TLSRPTv1; rua=mailto:tls@example.com");
    let good = "version: STSv1\nmode: enforce\nmx: mail.example.com\nmax_age: 86400\n";
    assert_eq!(sts("v=STSv1; id=1", rpt, fetched(good), good_mx()), []);
    assert_eq!(
        sts("v=STSv1; id=", rpt, None, good_mx()),
        [FindingCode::MtaStsSyntax]
    );
    assert_eq!(
        sts("v=STSv1; id=1", None, None, good_mx()),
        [FindingCode::TlsRptMissingWithMtaSts]
    );
    assert_eq!(
        sts("v=STSv1; id=1", Some("v=TLSRPTv1"), None, good_mx()),
        [FindingCode::TlsRptSyntax]
    );
    let unreachable = Some(PolicyFetch::Unreachable {
        url: "https://mta-sts.example.com/.well-known/mta-sts.txt".into(),
        reason: "connection refused".into(),
    });
    assert_eq!(
        sts("v=STSv1; id=1", rpt, unreachable, good_mx()),
        [FindingCode::MtaStsPolicyUnreachable]
    );
    let testing = "version: STSv1\nmode: testing\nmx: *.example.net\nmax_age: 86400\n";
    assert_eq!(
        sts("v=STSv1; id=1", rpt, fetched(testing), good_mx()),
        [FindingCode::MtaStsTesting, FindingCode::MtaStsMxNotCovered]
    );
    let too_long = "version: STSv1\nmode: enforce\nmx: mail.example.com\nmax_age: 99999999\n";
    assert_eq!(
        sts("v=STSv1; id=1", rpt, fetched(too_long), good_mx()),
        [FindingCode::MtaStsMaxAgeOutOfRange]
    );
    let two = FakeResolver::new().with_txt("_mta-sts.example.com", ["v=STSv1; id=2"]);
    assert_eq!(
        sts("v=STSv1; id=1", rpt, None, two),
        [FindingCode::MtaStsMultipleRecords]
    );
}

fn clean_domain() -> FakeResolver {
    good_mx()
        .with_txt("example.com", ["v=spf1 mx -all"])
        .with_txt(
            "_dmarc.example.com",
            ["v=DMARC1; p=reject; rua=mailto:dmarc@example.com"],
        )
        .with_txt(
            "s1._domainkey.example.com",
            [format!("v=DKIM1; p={RSA_2048}").as_str()],
        )
}

#[test]
fn check_domain_runs_every_family() {
    let options = CheckOptions {
        dkim_selectors: vec!["s1".into()],
        query_log: true,
        ..CheckOptions::default()
    };
    let report = block_on(check_domain(&clean_domain(), "Example.COM", &options));
    assert_eq!(report.domain, "example.com");
    assert_eq!(codes(&report.findings), []);
    assert!(report.spf.root.record().is_some());
    assert!(report.dmarc.records.found().is_some());
    assert_eq!(report.dkim.len(), 1);
    assert_eq!(report.mx.hosts.len(), 1);
    let log = report.queries.unwrap();
    assert_eq!(u32::try_from(log.len()).unwrap(), report.queries_sent);
}

#[test]
fn the_budget_cuts_checks_short_with_one_incomplete_finding() {
    let options = CheckOptions {
        max_queries: Some(0),
        dkim_selectors: vec!["s1".into()],
        ..CheckOptions::default()
    };
    let report = block_on(check_domain(&clean_domain(), "example.com", &options));
    let incomplete: Vec<&Finding> = report
        .findings
        .iter()
        .filter(|f| f.code == FindingCode::Incomplete)
        .collect();
    assert_eq!(incomplete.len(), 1);
    let Detail::Incomplete { checks } = &incomplete[0].detail else {
        panic!("an incomplete finding names its checks");
    };
    assert_eq!(
        checks,
        &["bimi", "dkim", "dmarc", "mta_sts", "mx", "spf", "tls_rpt"]
    );
    assert!(
        report
            .findings
            .iter()
            .all(|f| f.code != FindingCode::LookupFailed)
    );
    assert!(!codes(&report.findings).contains(&FindingCode::SpfMissing));
    assert_eq!(report.queries_sent, 0);
}

#[test]
fn a_past_deadline_sends_nothing() {
    let options = CheckOptions {
        deadline: Some(std::time::Duration::ZERO),
        ..CheckOptions::default()
    };
    let report = block_on(check_domain(&clean_domain(), "example.com", &options));
    assert_eq!(report.queries_sent, 0);
    assert!(codes(&report.findings).contains(&FindingCode::Incomplete));
}

#[test]
fn bimi_checks_the_organisational_domain_policy_too() {
    let dns = FakeResolver::new()
        .with_ip("news.example.com", [ip("192.0.2.1")])
        .with_txt(
            "default._bimi.news.example.com",
            ["v=BIMI1; l=https://example.com/logo.svg"],
        )
        .with_txt(
            "_dmarc.news.example.com",
            ["v=DMARC1; p=reject; rua=mailto:d@example.com"],
        )
        .with_txt(
            "_dmarc.example.com",
            ["v=DMARC1; p=none; rua=mailto:d@example.com"],
        );
    let report = block_on(check_domain(
        &dns,
        "news.example.com",
        &CheckOptions::default(),
    ));
    let not_enforcing: Vec<&Finding> = report
        .findings
        .iter()
        .filter(|f| f.code == FindingCode::BimiDmarcNotEnforcing)
        .collect();
    assert_eq!(not_enforcing.len(), 1);
    assert!(
        matches!(&not_enforcing[0].detail, Detail::Enforcement { domain, .. } if domain == "example.com")
    );
}
