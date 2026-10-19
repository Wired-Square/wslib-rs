use wslib_dns::{LookupError, Resolver};

use super::{Detail, Finding, FindingCode, incomplete, lookup_failure};
use crate::spf::tree::{
    LOOKUP_LIMIT, SpfNode, SpfTree, TermLookup, TermOutcome, TermPath, VOID_LOOKUP_LIMIT,
    WalkLimits, walk,
};
use crate::spf::{Mechanism, Qualifier, Term};
use crate::{FaultCode, Parsed};

/// The record length past which some resolvers truncate a UDP answer
/// (RFC 7208 §3.4 suggests staying near 450 bytes).
pub const SPF_LENGTH_LIMIT: usize = 450;

/// A domain's SPF tree and what's wrong with it.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SpfCheck {
    pub tree: SpfTree,
    pub findings: Vec<Finding>,
}

pub async fn check_spf(resolver: &impl Resolver, domain: &str, limits: WalkLimits) -> SpfCheck {
    let tree = walk(resolver, domain, limits).await;
    let findings = spf_findings(&tree);
    SpfCheck { tree, findings }
}

/// The findings for an SPF tree.
pub fn spf_findings(tree: &SpfTree) -> Vec<Finding> {
    let mut findings = Vec::new();
    let root = &tree.root;
    if let Some(error) = root.records.failure() {
        findings.push(lookup_failure("spf", &root.domain, error));
        return findings;
    }
    if root.records.is_absent() {
        findings.push(Finding::new(
            FindingCode::SpfMissing,
            &root.domain,
            Detail::None,
        ));
        return findings;
    }

    for (domains, node) in tree.nodes() {
        record_findings(node, &domains, domains.len() == 1, &mut findings);
        for lookup in &node.lookups {
            lookup_findings(node, &domains, lookup, &mut findings);
        }
    }

    let accounting = &tree.accounting;
    if accounting.exceeds_lookup_limit() {
        findings.push(Finding::new(
            FindingCode::SpfLookupLimitExceeded,
            &root.domain,
            Detail::Count {
                count: accounting.lookups,
                limit: LOOKUP_LIMIT,
                crossed_at: accounting.lookup_limit_crossed.clone(),
                truncated: accounting.truncated,
            },
        ));
    }
    if accounting.exceeds_void_limit() {
        findings.push(Finding::new(
            FindingCode::SpfVoidLookupLimitExceeded,
            &root.domain,
            Detail::Count {
                count: accounting.void_lookups,
                limit: VOID_LOOKUP_LIMIT,
                crossed_at: accounting.void_limit_crossed.clone(),
                truncated: accounting.truncated,
            },
        ));
    }
    for (at, names) in &accounting.name_limit_exceeded {
        findings.push(Finding::new(
            FindingCode::SpfMxPtrNameLimitExceeded,
            at.domains.last().cloned().unwrap_or_default(),
            Detail::Names {
                at: at.clone(),
                names: *names,
            },
        ));
    }
    for at in &accounting.loops {
        findings.push(Finding::new(
            FindingCode::SpfLoop,
            at.domains.last().cloned().unwrap_or_default(),
            Detail::Term { at: at.clone() },
        ));
    }
    for netblock in tree
        .flatten()
        .netblocks
        .iter()
        .filter(|n| !n.dynamic && n.is_private())
    {
        findings.push(Finding::new(
            FindingCode::SpfPrivateNetblock,
            netblock.source.last().cloned().unwrap_or_default(),
            Detail::Netblock {
                source: netblock.source.clone(),
                cidr: netblock.cidr.clone(),
            },
        ));
    }
    findings
}

fn path(domains: &[String], term: usize, text: String) -> TermPath {
    TermPath {
        domains: domains.to_vec(),
        term,
        text,
    }
}

/// What a single record says about itself; the root alone is held to the
/// practices that only matter for the policy a domain publishes.
fn record_findings(node: &SpfNode, domains: &[String], is_root: bool, findings: &mut Vec<Finding>) {
    let domain = &node.domain;
    if node.records.is_multiple() {
        let texts = node
            .records
            .records
            .iter()
            .map(|r| r.text.clone())
            .collect();
        findings.push(Finding::new(
            FindingCode::SpfMultipleRecords,
            domain,
            Detail::Records { texts },
        ));
        return;
    }
    let Some(published) = node.records.single() else {
        return;
    };
    syntax_findings(domain, &published.text, &published.parsed, findings);
    let record = &published.parsed.record;
    let at = |index: usize| path(domains, index, record.terms[index].term.to_string());

    if published.text.len() > SPF_LENGTH_LIMIT {
        findings.push(Finding::new(
            FindingCode::SpfRecordTooLong,
            domain,
            Detail::Length {
                bytes: published.text.len(),
                limit: SPF_LENGTH_LIMIT,
            },
        ));
    }
    for (index, term) in record.terms.iter().enumerate() {
        match &term.term {
            Term::Directive {
                mechanism: Mechanism::Ptr(_),
                ..
            } => findings.push(Finding::new(
                FindingCode::SpfPtrUsed,
                domain,
                Detail::Term { at: at(index) },
            )),
            Term::Directive {
                qualifier: Qualifier::Pass,
                mechanism: Mechanism::All,
            } => findings.push(Finding::new(
                FindingCode::SpfPermissiveAll,
                domain,
                Detail::Term { at: at(index) },
            )),
            Term::UnknownModifier { name, .. } if is_mechanism_name(name) => {
                findings.push(Finding::new(
                    FindingCode::SpfModifierNamedLikeMechanism,
                    domain,
                    Detail::Term { at: at(index) },
                ))
            }
            _ => {}
        }
    }
    match record.all() {
        Some((index, qualifier)) => {
            if is_root && qualifier == Qualifier::Neutral {
                findings.push(Finding::new(
                    FindingCode::SpfNeutralAll,
                    domain,
                    Detail::Term { at: at(index) },
                ));
            }
            let unreachable = record.terms[index + 1..]
                .iter()
                .any(|term| matches!(term.term, Term::Directive { .. }));
            if unreachable {
                findings.push(Finding::new(
                    FindingCode::SpfTermsAfterAll,
                    domain,
                    Detail::Term { at: at(index) },
                ));
            }
            if let Some((redirect, _)) = record.redirect_at() {
                findings.push(Finding::new(
                    FindingCode::SpfRedirectIgnored,
                    domain,
                    Detail::Term { at: at(redirect) },
                ));
            }
        }
        None if is_root && record.redirect().is_none() => {
            findings.push(Finding::new(FindingCode::SpfNoAll, domain, Detail::None));
        }
        None => {}
    }
}

fn syntax_findings(
    domain: &str,
    text: &str,
    parsed: &Parsed<crate::spf::SpfRecord>,
    findings: &mut Vec<Finding>,
) {
    for fault in &parsed.faults {
        let code = match fault.code {
            FaultCode::InvalidSeparator => FindingCode::SpfInvalidSeparator,
            _ => FindingCode::SpfSyntax,
        };
        findings.push(Finding::new(
            code,
            domain,
            Detail::Fault {
                fault: fault.clone(),
                text: text.to_owned(),
            },
        ));
    }
}

fn lookup_findings(
    node: &SpfNode,
    domains: &[String],
    lookup: &TermLookup,
    findings: &mut Vec<Finding>,
) {
    let at = || path(domains, lookup.term, lookup.text.clone());
    let redirect = lookup.text.to_ascii_lowercase().starts_with("redirect=");
    match &lookup.outcome {
        TermOutcome::Record(child) => {
            if let Some(error) = child.records.failure() {
                findings.push(spf_lookup_failed(&node.domain, &child.domain, error));
            } else if child.records.is_absent() {
                let code = if redirect {
                    FindingCode::SpfRedirectTargetMissing
                } else {
                    FindingCode::SpfIncludeTargetMissing
                };
                findings.push(Finding::new(
                    code,
                    &node.domain,
                    Detail::Target {
                        at: at(),
                        target: child.domain.clone(),
                    },
                ));
            }
        }
        TermOutcome::Failed(error) => {
            let name = lookup.target.clone().unwrap_or_default();
            findings.push(spf_lookup_failed(&node.domain, &name, error));
        }
        TermOutcome::Exchanges(exchanges) => {
            for exchange in exchanges {
                if let Some(error) = exchange.error.as_ref().filter(|error| !error.is_absent()) {
                    findings.push(spf_lookup_failed(&node.domain, &exchange.host, error));
                }
            }
        }
        _ => {}
    }
}

/// A temperror somewhere in the tree; a query never sent marks the check
/// incomplete instead.
fn spf_lookup_failed(domain: &str, name: &str, error: &LookupError) -> Finding {
    match error {
        LookupError::NotSent => return incomplete("spf", domain),
        LookupError::Bogus => return lookup_failure("spf", name, error),
        _ => {}
    }
    Finding::new(
        FindingCode::SpfLookupFailed,
        domain,
        Detail::Lookup {
            name: name.to_owned(),
            error: error.clone(),
        },
    )
}

fn is_mechanism_name(name: &str) -> bool {
    ["all", "include", "a", "mx", "ptr", "ip4", "ip6", "exists"]
        .iter()
        .any(|mechanism| name.eq_ignore_ascii_case(mechanism))
}
