use std::net::IpAddr;

use wslib_dns::{FakeResolver, LookupError, RecordType};

use super::tree::{NotEvaluated, TermOutcome, WalkLimits, walk};
use super::*;
use crate::discover::block_on;

fn ip(text: &str) -> IpAddr {
    text.parse().unwrap()
}

fn tree(dns: &FakeResolver, domain: &str) -> tree::SpfTree {
    block_on(walk(dns, domain, WalkLimits::default()))
}

fn chained() -> FakeResolver {
    FakeResolver::new()
        .with_txt(
            "example.com",
            ["v=spf1 include:_spf.example.net a/24 mx -all"],
        )
        .with_txt(
            "_spf.example.net",
            ["v=spf1 ip4:192.0.2.0/24 include:_spf.example.org ~all"],
        )
        .with_txt(
            "_spf.example.org",
            ["v=spf1 ip6:2001:db8::/32 ip4:192.0.2.128/25 -all"],
        )
        .with_ip("example.com", [ip("198.51.100.7")])
        .with_mx("example.com", 10, "mail.example.com")
        .with_ip(
            "mail.example.com",
            [ip("198.51.100.20"), ip("2001:db8:1::20")],
        )
}

#[test]
fn lookups_are_numbered_in_evaluation_order() {
    let tree = tree(&chained(), "example.com");
    assert_eq!(tree.accounting.lookups, 4);
    assert_eq!(tree.accounting.void_lookups, 0);
    let numbers: Vec<(String, u32)> = tree
        .nodes()
        .iter()
        .flat_map(|(_, node)| node.lookups.iter().map(|l| (l.text.clone(), l.number)))
        .collect();
    assert_eq!(
        numbers,
        [
            ("include:_spf.example.net".to_owned(), 1),
            ("a/24".to_owned(), 3),
            ("mx".to_owned(), 4),
            ("include:_spf.example.org".to_owned(), 2),
        ]
    );
}

#[test]
fn the_lookup_limit_is_crossed_where_the_eleventh_term_is() {
    let includes: Vec<String> = (0..12)
        .map(|n| format!("include:i{n}.example.net"))
        .collect();
    let mut dns = FakeResolver::new()
        .with_txt(
            "example.com",
            [format!("v=spf1 a {} -all", includes.join(" ")).as_str()],
        )
        .with_txt("i11.example.net", ["v=spf1 include:deep.example.net -all"])
        .with_txt("deep.example.net", ["v=spf1 -all"]);
    for n in 0..11 {
        dns = dns.with_txt(&format!("i{n}.example.net"), ["v=spf1 -all"]);
    }
    let walked = tree(&dns, "example.com");
    assert_eq!(walked.accounting.lookups, 14);
    assert!(walked.accounting.exceeds_lookup_limit());
    let crossed = walked.accounting.lookup_limit_crossed.unwrap();
    assert_eq!(crossed.text, "include:i9.example.net");
    assert_eq!(crossed.domains, ["example.com"]);
    assert!(!walked.accounting.truncated);
}

#[test]
fn void_lookups_count_nxdomain_and_nodata() {
    let dns = FakeResolver::new()
        .with_txt("example.com", ["v=spf1 a:gone.example.com mx:example.net exists:none.example.org include:absent.example.com -all"])
        .with_txt("example.net", ["unrelated"])
        .with_txt("absent.example.com", ["not spf"]);
    let walked = tree(&dns, "example.com");
    assert_eq!(walked.accounting.void_lookups, 4);
    assert!(walked.accounting.exceeds_void_limit());
    assert_eq!(
        walked.accounting.void_limit_crossed.unwrap().text,
        "exists:none.example.org"
    );
}

#[test]
fn more_than_ten_mx_names_are_reported() {
    let mut dns = FakeResolver::new().with_txt("example.com", ["v=spf1 mx -all"]);
    for n in 0..11 {
        dns = dns.with_mx("example.com", n, &format!("mx{n}.example.com"));
    }
    let walked = tree(&dns, "example.com");
    assert_eq!(walked.accounting.name_limit_exceeded.len(), 1);
    assert_eq!(walked.accounting.name_limit_exceeded[0].1, 11);
}

#[test]
fn loops_are_detected_and_not_followed() {
    let dns = FakeResolver::new()
        .with_txt("example.com", ["v=spf1 include:example.net -all"])
        .with_txt("example.net", ["v=spf1 include:example.com -all"]);
    let walked = tree(&dns, "example.com");
    assert_eq!(walked.accounting.loops.len(), 1);
    assert_eq!(
        walked.accounting.loops[0].domains,
        ["example.com", "example.net"]
    );
    assert_eq!(walked.accounting.lookups, 2);
}

#[test]
fn redirect_is_followed_last_and_ignored_beside_all() {
    let dns = FakeResolver::new()
        .with_txt("example.com", ["v=spf1 redirect=_spf.example.com mx"])
        .with_txt("_spf.example.com", ["v=spf1 -all"])
        .with_txt("example.net", ["v=spf1 -all redirect=_spf.example.com"]);
    let followed = tree(&dns, "example.com");
    let texts: Vec<&str> = followed
        .root
        .lookups
        .iter()
        .map(|l| l.text.as_str())
        .collect();
    assert_eq!(texts, ["mx", "redirect=_spf.example.com"]);
    assert!(followed.targets()[0].redirect);
    let ignored = tree(&dns, "example.net");
    assert_eq!(ignored.accounting.lookups, 0);
    assert!(ignored.root.lookups.is_empty());
}

#[test]
fn targets_without_a_message_are_counted_but_not_queried() {
    let dns = FakeResolver::new()
        .with_txt(
            "example.com",
            ["v=spf1 exists:%{i}._spf.%{d} include:%{d}.spf.example.net ptr -all"],
        )
        .with_txt("example.com.spf.example.net", ["v=spf1 -all"]);
    let walked = tree(&dns, "example.com");
    assert_eq!(walked.accounting.lookups, 3);
    let outcomes: Vec<&TermOutcome> = walked.root.lookups.iter().map(|l| &l.outcome).collect();
    assert_eq!(
        outcomes[0],
        &TermOutcome::NotEvaluated(NotEvaluated::NeedsMessage)
    );
    assert!(matches!(outcomes[1], TermOutcome::Record(_)));
    assert_eq!(
        outcomes[2],
        &TermOutcome::NotEvaluated(NotEvaluated::NeedsClient)
    );
}

#[test]
fn the_ceiling_stops_queries_but_keeps_counting() {
    let dns = chained();
    let walked = block_on(walk(
        &dns,
        "example.com",
        WalkLimits {
            max_lookups: 1,
            max_depth: 12,
        },
    ));
    assert!(walked.accounting.truncated);
    assert_eq!(walked.accounting.lookups, 4);
    assert_eq!(dns.queries("mail.example.com", RecordType::A), 0);
}

#[test]
fn targets_list_every_include_and_its_record() {
    let targets = tree(&chained(), "example.com").targets();
    let listed: Vec<(&str, Option<&str>)> = targets
        .iter()
        .map(|t| (t.domain.as_str(), t.record.as_deref()))
        .collect();
    assert_eq!(
        listed,
        [
            (
                "_spf.example.net",
                Some("v=spf1 ip4:192.0.2.0/24 include:_spf.example.org ~all")
            ),
            (
                "_spf.example.org",
                Some("v=spf1 ip6:2001:db8::/32 ip4:192.0.2.128/25 -all")
            ),
        ]
    );
    assert_eq!(targets[1].at.domains, ["example.com", "_spf.example.net"]);
}

#[test]
fn flattening_collects_netblocks_with_their_paths() {
    let flat = tree(&chained(), "example.com").flatten();
    let blocks: Vec<(&str, bool, Vec<&str>)> = flat
        .netblocks
        .iter()
        .map(|b| {
            (
                b.cidr.as_str(),
                b.dynamic,
                b.source.iter().map(String::as_str).collect(),
            )
        })
        .collect();
    assert_eq!(
        blocks,
        [
            (
                "192.0.2.0/24",
                false,
                vec!["example.com", "include:_spf.example.net"]
            ),
            (
                "2001:db8::/32",
                false,
                vec![
                    "example.com",
                    "include:_spf.example.net",
                    "include:_spf.example.org"
                ]
            ),
            (
                "192.0.2.128/25",
                false,
                vec![
                    "example.com",
                    "include:_spf.example.net",
                    "include:_spf.example.org"
                ]
            ),
            (
                "198.51.100.0/24",
                true,
                vec!["example.com", "a:example.com"]
            ),
            (
                "198.51.100.20/32",
                true,
                vec!["example.com", "mx:example.com", "mail.example.com"]
            ),
            (
                "2001:db8:1::20/128",
                true,
                vec!["example.com", "mx:example.com", "mail.example.com"]
            ),
        ]
    );
    assert_eq!(flat.netblocks[0].qualifier, Qualifier::Pass);
    assert_eq!(flat.total_ipv4_addresses, 256 + 256);
    assert_eq!(flat.ipv6_prefix_count, 2);
    let overlaps: Vec<(&str, &str)> = flat
        .overlaps
        .iter()
        .map(|o| (o.cidr.as_str(), o.within.as_str()))
        .collect();
    assert_eq!(
        overlaps,
        [
            ("192.0.2.128/25", "192.0.2.0/24"),
            ("198.51.100.20/32", "198.51.100.0/24"),
            ("2001:db8:1::20/128", "2001:db8::/32")
        ]
    );
    assert!(flat.duplicates.is_empty());
}

#[test]
fn the_same_network_by_two_paths_is_a_duplicate() {
    let dns = FakeResolver::new()
        .with_txt(
            "example.com",
            ["v=spf1 ip4:192.0.2.1 include:example.net -all"],
        )
        .with_txt("example.net", ["v=spf1 ip4:192.0.2.1/32 -all"]);
    let flat = tree(&dns, "example.com").flatten();
    assert_eq!(flat.duplicates.len(), 1);
    assert_eq!(flat.duplicates[0].cidr, "192.0.2.1/32");
    assert_eq!(flat.duplicates[0].occurrences, 2);
    assert_eq!(flat.total_ipv4_addresses, 1);
}

fn check(dns: &FakeResolver, client: &str, sender: &str) -> CheckHost {
    block_on(check_host(dns, ip(client), "mx.example.org", sender))
}

#[test]
fn check_host_results() {
    let dns = chained()
        .with_txt("example.net", ["v=spf1 ?ip4:203.0.113.1 ~all"])
        .with_txt("neutral.example.com", ["v=spf1 ip4:203.0.113.9"]);
    for (client, sender, result) in [
        ("192.0.2.10", "a@example.com", SpfResult::Pass),
        ("192.0.2.200", "a@example.com", SpfResult::Pass),
        ("2001:db8::5", "a@example.com", SpfResult::Pass),
        ("198.51.100.99", "a@example.com", SpfResult::Pass),
        ("198.51.100.20", "a@example.com", SpfResult::Pass),
        ("2001:db8:1::20", "a@example.com", SpfResult::Pass),
        ("::ffff:192.0.2.10", "a@example.com", SpfResult::Pass),
        ("203.0.113.5", "a@example.com", SpfResult::Fail),
        ("203.0.113.1", "a@example.net", SpfResult::Neutral),
        ("203.0.113.2", "a@example.net", SpfResult::SoftFail),
        ("203.0.113.2", "a@neutral.example.com", SpfResult::Neutral),
        ("203.0.113.2", "a@nothing.example.com", SpfResult::None),
        ("203.0.113.2", "a@localhost", SpfResult::None),
    ] {
        assert_eq!(
            check(&dns, client, sender).result,
            result,
            "{client} {sender}"
        );
    }
}

#[test]
fn the_matched_term_is_reported_with_its_path() {
    let result = check(&chained(), "192.0.2.10", "a@example.com");
    let matched = result.matched.unwrap();
    assert_eq!(matched.text, "ip4:192.0.2.0/24");
    assert_eq!(matched.domains, ["example.com", "_spf.example.net"]);
    assert_eq!(result.lookups, 1);
}

#[test]
fn an_empty_sender_checks_the_helo_domain() {
    let dns = FakeResolver::new().with_txt("mx.example.org", ["v=spf1 ip4:192.0.2.1 -all"]);
    assert_eq!(check(&dns, "192.0.2.1", "").result, SpfResult::Pass);
    assert_eq!(check(&dns, "192.0.2.1", "<>").result, SpfResult::None);
}

#[test]
fn permerrors_and_temperrors() {
    let dns = FakeResolver::new()
        .with_txt("multiple.example.com", ["v=spf1 -all", "v=spf1 +all"])
        .with_txt("syntax.example.com", ["v=spf1 bogus -all"])
        .with_txt(
            "include.example.com",
            ["v=spf1 include:nothing.example.com -all"],
        )
        .with_txt(
            "redirect.example.com",
            ["v=spf1 redirect=nothing.example.com"],
        )
        .with_error("timeout.example.com", RecordType::Txt, LookupError::Timeout)
        .with_txt(
            "deep.example.com",
            ["v=spf1 include:timeout.example.com -all"],
        )
        .with_txt("aerror.example.com", ["v=spf1 a:broken.example.com -all"])
        .with_error("broken.example.com", RecordType::A, LookupError::ServFail);
    for (sender, result) in [
        ("a@multiple.example.com", SpfResult::PermError),
        ("a@syntax.example.com", SpfResult::PermError),
        ("a@include.example.com", SpfResult::PermError),
        ("a@redirect.example.com", SpfResult::PermError),
        ("a@timeout.example.com", SpfResult::TempError),
        ("a@deep.example.com", SpfResult::TempError),
        ("a@aerror.example.com", SpfResult::TempError),
    ] {
        assert_eq!(check(&dns, "192.0.2.1", sender).result, result, "{sender}");
    }
    let include = check(&dns, "192.0.2.1", "a@include.example.com");
    assert!(matches!(
        include.reason,
        Some(Reason::IncludeWithoutRecord { .. })
    ));
}

#[test]
fn check_host_enforces_the_lookup_void_and_name_limits() {
    let mut dns = FakeResolver::new()
        .with_txt(
            "voids.example.com",
            ["v=spf1 a:v1.example.com a:v2.example.com a:v3.example.com -all"],
        )
        .with_txt("many.example.com", ["v=spf1 mx -all"])
        .with_txt("long.example.com", ["v=spf1 a a a a a a a a a a a -all"])
        .with_ip("long.example.com", [ip("198.51.100.1")]);
    for n in 0..11 {
        dns = dns.with_mx("many.example.com", n, &format!("mx{n}.example.com"));
    }
    let voids = check(&dns, "192.0.2.1", "a@voids.example.com");
    assert_eq!(voids.result, SpfResult::PermError);
    assert!(matches!(voids.reason, Some(Reason::VoidLookupLimit { .. })));
    let many = check(&dns, "192.0.2.1", "a@many.example.com");
    assert!(matches!(
        many.reason,
        Some(Reason::NameLimit { names: 11, .. })
    ));
    let long = check(&dns, "192.0.2.1", "a@long.example.com");
    assert!(matches!(long.reason, Some(Reason::LookupLimit { .. })));
    assert_eq!(long.lookups, 11);
}

#[test]
fn macros_expand_for_exists_and_exp_explains_a_fail() {
    let dns = FakeResolver::new()
        .with_txt(
            "example.com",
            ["v=spf1 exists:%{ir}.%{l1r+-}._spf.%{d} -all exp=explain._spf.%{d}"],
        )
        .with_ip("1.2.0.192.strong._spf.example.com", [ip("127.0.0.2")])
        .with_txt(
            "explain._spf.example.com",
            ["%{i} is not one of %{d}'s designated mail servers."],
        );
    assert_eq!(
        check(&dns, "192.0.2.1", "strong-bad@example.com").result,
        SpfResult::Pass
    );
    let failed = check(&dns, "192.0.2.9", "strong-bad@example.com");
    assert_eq!(failed.result, SpfResult::Fail);
    assert_eq!(
        failed.explanation.as_deref(),
        Some("192.0.2.9 is not one of example.com's designated mail servers.")
    );
}

#[test]
fn ptr_matches_a_validated_name_in_the_domain() {
    let dns = FakeResolver::new()
        .with_txt("example.com", ["v=spf1 ptr -all"])
        .with_ptr(ip("192.0.2.5"), "mail.example.com")
        .with_ip("mail.example.com", [ip("192.0.2.5")])
        .with_ptr(ip("192.0.2.6"), "spoof.example.com");
    assert_eq!(
        check(&dns, "192.0.2.5", "a@example.com").result,
        SpfResult::Pass
    );
    assert_eq!(
        check(&dns, "192.0.2.6", "a@example.com").result,
        SpfResult::Fail
    );
}

#[test]
fn redirect_hands_over_to_the_target_record() {
    let dns = FakeResolver::new()
        .with_txt("example.com", ["v=spf1 redirect=_spf.example.net"])
        .with_txt("_spf.example.net", ["v=spf1 ip4:192.0.2.0/24 -all"]);
    assert_eq!(
        check(&dns, "192.0.2.7", "a@example.com").result,
        SpfResult::Pass
    );
    let failed = check(&dns, "203.0.113.7", "a@example.com");
    assert_eq!(failed.result, SpfResult::Fail);
    assert_eq!(
        failed.matched.unwrap().domains,
        ["example.com", "_spf.example.net"]
    );
}
