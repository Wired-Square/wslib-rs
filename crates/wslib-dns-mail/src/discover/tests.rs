use std::net::IpAddr;

use wslib_dns::{FakeResolver, LookupError, RecordType};

use super::*;
use crate::dmarc::Policy;

fn ip(text: &str) -> IpAddr {
    text.parse().unwrap()
}

#[test]
fn spf_keeps_every_spf_record_and_ignores_other_txt() {
    let dns = FakeResolver::new()
        .with_txt(
            "example.com",
            ["google-site-verification=abc", "v=spf1 mx -all"],
        )
        .with_txt("example.net", ["v=spf1 -all", "v=spf1 mx -all"])
        .with_txt("example.org", ["v=spf10 -all"]);
    block_on(async {
        let one = spf(&dns, "example.com").await;
        assert_eq!(one.single().unwrap().text, "v=spf1 mx -all");
        assert!(one.single().unwrap().parsed.is_usable());
        assert!(spf(&dns, "example.net").await.is_multiple());
        let none = spf(&dns, "example.org").await;
        assert!(none.is_absent() && none.error.is_none());
        let gone = spf(&dns, "missing.example.com").await;
        assert!(gone.is_absent());
        assert_eq!(gone.error, Some(LookupError::NxDomain));
    });
}

#[test]
fn a_failed_lookup_is_not_absence() {
    let dns = FakeResolver::new().with_error("example.com", RecordType::Txt, LookupError::Timeout);
    let set = block_on(spf(&dns, "example.com"));
    assert!(!set.is_absent());
    assert_eq!(set.failure(), Some(&LookupError::Timeout));
}

#[test]
fn txt_names_follow_each_specification() {
    let dns = FakeResolver::new()
        .with_txt("_mta-sts.example.com", ["v=STSv1; id=20240101"])
        .with_txt(
            "_smtp._tls.example.com",
            ["v=TLSRPTv1; rua=mailto:tls@example.com"],
        );
    block_on(async {
        assert!(mta_sts(&dns, "Example.COM.").await.single().is_some());
        assert!(tls_rpt(&dns, "example.com").await.single().is_some());
    });
}

#[test]
fn dmarc_uses_the_domains_own_record_and_its_p() {
    let dns = FakeResolver::new().with_txt("_dmarc.example.com", ["v=DMARC1; p=reject; sp=none"]);
    let found = block_on(dmarc(&dns, "example.com", DmarcDiscoveryMode::Rfc7489));
    assert_eq!(found.records.outcome, Outcome::Found { at: 0 });
    assert_eq!(found.records.inherited_from(), None);
    assert_eq!(
        found.applies,
        Some(AppliedPolicy {
            tag: PolicyTag::P,
            policy: Some(Policy::Reject)
        })
    );
}

#[test]
fn dmarc_falls_back_to_the_organisational_domain_and_its_sp() {
    let dns = FakeResolver::new()
        .with_ip("mail.example.com.au", [ip("192.0.2.1")])
        .with_txt(
            "_dmarc.example.com.au",
            ["v=DMARC1; p=reject; sp=quarantine; np=none"],
        );
    let found = block_on(dmarc(
        &dns,
        "mail.example.com.au",
        DmarcDiscoveryMode::Rfc7489,
    ));
    assert_eq!(found.records.attempts.len(), 2);
    assert_eq!(found.records.inherited_from(), Some("example.com.au"));
    assert_eq!(
        found.applies,
        Some(AppliedPolicy {
            tag: PolicyTag::Sp,
            policy: Some(Policy::Quarantine)
        })
    );
}

#[test]
fn a_name_that_does_not_exist_gets_np() {
    let dns =
        FakeResolver::new().with_txt("_dmarc.example.com", ["v=DMARC1; p=reject; np=quarantine"]);
    let found = block_on(dmarc(
        &dns,
        "nothing.example.com",
        DmarcDiscoveryMode::Rfc7489,
    ));
    assert_eq!(
        found.applies,
        Some(AppliedPolicy {
            tag: PolicyTag::Np,
            policy: Some(Policy::Quarantine)
        })
    );
}

#[test]
fn a_name_with_no_address_or_mx_under_an_existing_parent_gets_np() {
    let dns = FakeResolver::new()
        .with_txt("empty.example.com", ["unrelated"])
        .with_txt("_dmarc.example.com", ["v=DMARC1; p=reject; np=quarantine"]);
    let found = block_on(dmarc(
        &dns,
        "empty.example.com",
        DmarcDiscoveryMode::Rfc7489,
    ));
    assert_eq!(
        found.applies.map(|applied| applied.tag),
        Some(PolicyTag::Np)
    );
    for record_type in [RecordType::A, RecordType::Aaaa, RecordType::Mx] {
        assert_eq!(dns.queries("empty.example.com", record_type), 1);
    }
}

#[test]
fn a_name_with_only_an_mx_exists() {
    let dns = FakeResolver::new()
        .with_mx("mail.example.com", 10, "mx.example.net")
        .with_txt(
            "_dmarc.example.com",
            ["v=DMARC1; p=reject; sp=none; np=quarantine"],
        );
    let found = block_on(dmarc(&dns, "mail.example.com", DmarcDiscoveryMode::Rfc7489));
    assert_eq!(
        found.applies.map(|applied| applied.tag),
        Some(PolicyTag::Sp)
    );
}

#[test]
fn a_failed_existence_check_leaves_the_tag_unknown() {
    let dns = FakeResolver::new()
        .with_txt("mail.example.com", ["unrelated"])
        .with_error("mail.example.com", RecordType::Aaaa, LookupError::Timeout)
        .with_txt("_dmarc.example.com", ["v=DMARC1; p=reject"]);
    let found = block_on(dmarc(&dns, "mail.example.com", DmarcDiscoveryMode::Rfc7489));
    assert_eq!(found.applies, None);
    assert_eq!(found.existence_error, Some(LookupError::Timeout));
    assert!(found.records.found().is_some());
    assert_eq!(dns.queries("mail.example.com", RecordType::Mx), 0);
}

#[test]
fn nxdomain_settles_existence_with_one_query() {
    let dns = FakeResolver::new().with_txt("_dmarc.example.com", ["v=DMARC1; p=reject"]);
    block_on(dmarc(&dns, "gone.example.com", DmarcDiscoveryMode::Rfc7489));
    assert_eq!(dns.queries("gone.example.com", RecordType::A), 1);
    assert_eq!(dns.queries("gone.example.com", RecordType::Aaaa), 0);
}

#[test]
fn several_records_or_a_failure_end_discovery_without_a_policy() {
    let dns = FakeResolver::new()
        .with_txt(
            "_dmarc.a.example.com",
            ["v=DMARC1; p=none", "v=DMARC1; p=reject"],
        )
        .with_error(
            "_dmarc.b.example.com",
            RecordType::Txt,
            LookupError::ServFail,
        )
        .with_txt("_dmarc.example.com", ["v=DMARC1; p=reject"]);
    block_on(async {
        let multiple = dmarc(&dns, "a.example.com", DmarcDiscoveryMode::Rfc7489).await;
        assert_eq!(multiple.records.outcome, Outcome::Multiple { at: 0 });
        assert_eq!(multiple.applies, None);
        let failed = dmarc(&dns, "b.example.com", DmarcDiscoveryMode::Rfc7489).await;
        assert_eq!(failed.records.outcome, Outcome::Failed { at: 0 });
        assert_eq!(failed.records.attempts.len(), 1);
    });
    assert_eq!(dns.queries("_dmarc.example.com", RecordType::Txt), 0);
}

#[test]
fn dmarc_reports_missing_after_looking_everywhere() {
    let dns = FakeResolver::new().with_txt("_dmarc.example.com", ["v=spf1 -all"]);
    let found = block_on(dmarc(&dns, "mail.example.com", DmarcDiscoveryMode::Rfc7489));
    assert_eq!(found.records.outcome, Outcome::Missing);
    assert_eq!(found.records.attempts.len(), 2);
}

#[test]
fn the_tree_walk_finds_the_nearest_ancestor() {
    let dns = FakeResolver::new()
        .with_ip("a.b.example.com", [ip("192.0.2.1")])
        .with_txt("_dmarc.b.example.com", ["v=DMARC1; p=quarantine"])
        .with_txt("_dmarc.example.com", ["v=DMARC1; p=reject"]);
    block_on(async {
        let walked = dmarc(&dns, "a.b.example.com", DmarcDiscoveryMode::TreeWalk).await;
        assert_eq!(walked.records.inherited_from(), Some("b.example.com"));
        let rfc = dmarc(&dns, "a.b.example.com", DmarcDiscoveryMode::Rfc7489).await;
        assert_eq!(rfc.records.inherited_from(), Some("example.com"));
    });
}

#[test]
fn external_report_destinations_need_an_authorisation_record() {
    let dns = FakeResolver::new()
        .with_txt(
            "example.com._report._dmarc.reports.example.net",
            ["v=DMARC1"],
        )
        .with_error(
            "example.com._report._dmarc.example.org",
            RecordType::Txt,
            LookupError::Timeout,
        );
    let uri = |text: &str| {
        crate::dmarc::parse(&format!("v=DMARC1; p=none; rua={text}"))
            .record
            .aggregate[0]
            .clone()
    };
    block_on(async {
        assert_eq!(
            dmarc_report_authorisation(&dns, "example.com", &uri("mailto:d@mail.example.com"))
                .await,
            ReportAuthorisation::SameOrganisation
        );
        assert_eq!(
            dmarc_report_authorisation(&dns, "example.com", &uri("mailto:d@reports.example.net"))
                .await,
            ReportAuthorisation::Authorised {
                name: "example.com._report._dmarc.reports.example.net".into()
            }
        );
        assert_eq!(
            dmarc_report_authorisation(&dns, "example.com", &uri("mailto:d@other.example.net"))
                .await,
            ReportAuthorisation::Unauthorised {
                name: "example.com._report._dmarc.other.example.net".into()
            }
        );
        assert!(matches!(
            dmarc_report_authorisation(&dns, "example.com", &uri("mailto:d@example.org")).await,
            ReportAuthorisation::Failed {
                error: LookupError::Timeout,
                ..
            }
        ));
    });
}

#[test]
fn dkim_exposes_the_terminal_name_of_a_delegated_selector() {
    let dns = FakeResolver::new()
        .with_cname("s1._domainkey.example.com", "s1.dkim.example.net")
        .with_txt(
            "s1.dkim.example.net",
            ["v=DKIM1; k=ed25519; p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo="],
        );
    let found = block_on(dkim(&dns, "s1", "example.com"));
    assert_eq!(found.terminal(), Some("s1.dkim.example.net"));
    assert!(found.records.single().unwrap().parsed.is_usable());
}

#[test]
fn a_selector_is_judged_by_where_its_aliases_reach() {
    let dns = FakeResolver::new()
        .with_cname("via._domainkey.example.com", "via.dkim.example.org")
        .with_cname("via.dkim.example.org", "via.dkim.provider.example")
        .with_cname(
            "other._domainkey.example.com",
            "other.dkim.elsewhere.example",
        )
        .with_txt("own._domainkey.example.com", ["v=DKIM1; p="])
        .with_error(
            "broken._domainkey.example.com",
            RecordType::Cname,
            LookupError::ServFail,
        );
    let verdict = |selector: &str| {
        block_on(dkim(&dns, selector, "example.com"))
            .aliased_to(&format!("{selector}.DKIM.Provider.example."))
    };
    assert_eq!(verdict("via"), Ok(AliasVerdict::Reaches));
    assert_eq!(verdict("other"), Ok(AliasVerdict::Elsewhere));
    assert_eq!(verdict("own"), Ok(AliasVerdict::NotAliased));
    assert_eq!(verdict("missing"), Ok(AliasVerdict::NotAliased));
    assert_eq!(verdict("broken"), Err(LookupError::ServFail));
}

#[test]
fn probing_keeps_selectors_with_a_record_or_a_failure() {
    let dns = FakeResolver::new()
        .with_txt("google._domainkey.example.com", ["v=DKIM1; p="])
        .with_txt("k1._domainkey.example.com", ["v=DKIM1; p="])
        .with_error(
            "s1._domainkey.example.com",
            RecordType::Txt,
            LookupError::Timeout,
        );
    let found = block_on(probe_dkim(
        &dns,
        "example.com",
        COMMON_SELECTORS.iter().copied(),
    ));
    let selectors: Vec<&str> = found.iter().map(|f| f.selector.as_str()).collect();
    assert_eq!(selectors, ["google", "k1", "s1"]);
    assert_eq!(dns.queries("k3._domainkey.example.com", RecordType::Txt), 1);
}

#[test]
fn mx_inspects_every_exchange() {
    let dns = FakeResolver::new()
        .with_mx("example.com", 20, "mx2.example.com")
        .with_mx("example.com", 10, "mx1.example.com")
        .with_ip("mx1.example.com", [ip("192.0.2.10"), ip("2001:db8::10")])
        .with_ptr(ip("192.0.2.10"), "mx1.example.com")
        .with_ptr(ip("2001:db8::10"), "other.example.net")
        .with_cname("mx2.example.com", "mx1.example.com");
    let found = block_on(mx(&dns, "example.com"));
    let first = &found.hosts[0];
    assert_eq!(first.exchange, "mx1.example.com");
    assert_eq!(first.addresses.len(), 2);
    assert!(first.reverse[0].forward_confirmed);
    assert_eq!(first.reverse[1].names, ["other.example.net"]);
    assert!(!first.reverse[1].forward_confirmed);
    assert_eq!(found.hosts[1].cname.as_deref(), Some("mx1.example.com"));
    assert_eq!(dns.queries("mx2.example.com", RecordType::Cname), 0);
    assert!(!found.is_null());
}

#[test]
fn null_mx_ip_literals_and_hosts_without_addresses() {
    let dns = FakeResolver::new()
        .with_mx("example.com", 0, ".")
        .with_mx("example.net", 0, ".")
        .with_mx("example.net", 10, "192.0.2.25")
        .with_mx("example.net", 20, "gone.example.net");
    block_on(async {
        let null = mx(&dns, "example.com").await;
        assert!(null.is_null());
        assert!(!null.has_null_with_others());
        let mixed = mx(&dns, "example.net").await;
        assert!(mixed.has_null_with_others());
        assert!(mixed.hosts[1].is_ip_literal());
        assert!(mixed.hosts[1].address_error.is_none());
        assert_eq!(mixed.hosts[2].address_error, Some(LookupError::NxDomain));
    });
    assert_eq!(dns.queries("192.0.2.25", RecordType::A), 0);
}

#[test]
fn dnsbl_tells_listed_clean_blocked_and_failed_apart() {
    let dns = FakeResolver::new()
        .with_ip("10.2.0.192.bl.example.org", [ip("127.0.0.2")])
        .with_txt("10.2.0.192.bl.example.org", ["listed for spam"])
        .with_ip("11.2.0.192.bl.example.org", [ip("127.255.255.254")])
        .with_error(
            "12.2.0.192.bl.example.org",
            RecordType::A,
            LookupError::ServFail,
        )
        .with_ip(
            &format!(
                "{}.bl.example.org",
                wslib_dns::reversed_labels(ip("2001:db8::1"))
            ),
            [ip("127.0.0.4")],
        );
    block_on(async {
        let listed = dnsbl(&dns, ip("192.0.2.10"), "bl.example.org").await;
        assert!(listed.is_listed());
        assert_eq!(listed.reason.as_deref(), Some("listed for spam"));
        assert_eq!(
            dnsbl(&dns, ip("192.0.2.9"), "bl.example.org").await.status,
            DnsblStatus::NotListed
        );
        let blocked = dnsbl(&dns, ip("192.0.2.11"), "bl.example.org").await;
        assert_eq!(blocked.status, DnsblStatus::QueryBlocked);
        assert_eq!(blocked.codes, [ip("127.255.255.254")]);
        assert_eq!(
            dnsbl(&dns, ip("192.0.2.12"), "bl.example.org").await.status,
            DnsblStatus::Failed(LookupError::ServFail)
        );
        assert!(
            dnsbl(&dns, ip("2001:db8::1"), "bl.example.org")
                .await
                .is_listed()
        );
    });
}

#[test]
fn bimi_falls_back_to_the_organisational_domain() {
    let dns = FakeResolver::new().with_txt(
        "default._bimi.example.com",
        ["v=BIMI1; l=https://example.com/logo.svg"],
    );
    block_on(async {
        let own = bimi(&dns, "example.com", "default").await;
        assert_eq!(own.inherited_from(), None);
        assert!(own.found().is_some());
        let inherited = bimi(&dns, "news.example.com", "default").await;
        assert_eq!(inherited.inherited_from(), Some("example.com"));
    });
}
