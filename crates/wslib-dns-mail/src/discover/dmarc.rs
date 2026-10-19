use wslib_dns::{LookupError, Resolver, registrable_domain};

use super::{Inherited, ascii, walk};
use crate::ReportUri;
use crate::dmarc::{DmarcRecord, Policy, is_dmarc, parse};

/// How far beyond the domain itself DMARC discovery looks.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum DmarcDiscoveryMode {
    /// RFC 7489 §6.6.3: the domain, then its organisational domain.
    #[default]
    Rfc7489,
    /// DMARCbis: the domain, then each parent up to the top-level domain, at
    /// most eight names.
    TreeWalk,
}

/// The policy record that governs a domain, and which of its policies
/// applies.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct DmarcDiscovery {
    pub records: Inherited<DmarcRecord>,
    /// Set when a record was found.
    pub applies: Option<AppliedPolicy>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct AppliedPolicy {
    pub tag: PolicyTag,
    /// With the RFC defaults applied; `None` when the record yields no
    /// policy at all.
    pub policy: Option<Policy>,
}

/// Which policy tag governs the queried name.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum PolicyTag {
    /// The domain's own record.
    P,
    /// Inherited, for a name that exists.
    Sp,
    /// Inherited, for a name that doesn't exist (DMARCbis).
    Np,
}

/// Finds the DMARC record for `domain` (RFC 7489 §6.6.3). One record at a
/// name ends the walk with a policy; several, or a failed lookup, end it
/// without one.
pub async fn dmarc(
    resolver: &impl Resolver,
    domain: &str,
    mode: DmarcDiscoveryMode,
) -> DmarcDiscovery {
    let domain = ascii(domain);
    let domains = match mode {
        DmarcDiscoveryMode::Rfc7489 => {
            let mut domains = vec![domain.clone()];
            domains.extend(registrable_domain(&domain).filter(|org| *org != domain));
            domains
        }
        DmarcDiscoveryMode::TreeWalk => tree_walk(&domain),
    };
    let records = walk(
        resolver,
        domain.clone(),
        domains,
        |d| format!("_dmarc.{d}"),
        is_dmarc,
        parse,
    )
    .await;
    let applies = match (records.found(), records.inherited_from()) {
        (Some(found), None) => Some(AppliedPolicy {
            tag: PolicyTag::P,
            policy: found.parsed.record.effective_policy(),
        }),
        (Some(found), Some(_)) => {
            let exists = !matches!(resolver.a(&domain).await, Err(LookupError::NxDomain));
            let record = &found.parsed.record;
            Some(if exists {
                AppliedPolicy {
                    tag: PolicyTag::Sp,
                    policy: record.effective_subdomain_policy(),
                }
            } else {
                AppliedPolicy {
                    tag: PolicyTag::Np,
                    policy: record.effective_non_existent_policy(),
                }
            })
        }
        (None, _) => None,
    };
    DmarcDiscovery { records, applies }
}

/// The domain, then — skipping to the last seven labels of a longer name —
/// each parent down to the top-level domain.
fn tree_walk(domain: &str) -> Vec<String> {
    let labels: Vec<&str> = domain.split('.').collect();
    let mut names = vec![domain.to_owned()];
    for keep in (1..labels.len().min(8)).rev() {
        names.push(labels[labels.len() - keep..].join("."));
    }
    names
}

/// Whether a report destination will take reports for a policy domain
/// (RFC 7489 §7.1).
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case", tag = "kind"))]
pub enum ReportAuthorisation {
    /// The destination shares the policy's organisational domain; no check
    /// is needed.
    SameOrganisation,
    Authorised {
        name: String,
    },
    /// No `v=DMARC1` record at `name`, so reports won't be sent there.
    Unauthorised {
        name: String,
    },
    Failed {
        name: String,
        error: LookupError,
    },
    /// The URI names no domain to check.
    NoDomain,
}

/// Checks that `uri` accepts reports about `policy_domain`, the domain whose
/// record lists it: by organisational domain, or by a `v=DMARC1` record at
/// `<policy-domain>._report._dmarc.<destination>`.
pub async fn dmarc_report_authorisation(
    resolver: &impl Resolver,
    policy_domain: &str,
    uri: &ReportUri,
) -> ReportAuthorisation {
    let Some(destination) = uri.domain() else {
        return ReportAuthorisation::NoDomain;
    };
    let policy_domain = ascii(policy_domain);
    let destination = ascii(&destination);
    let organisation = |d: &str| registrable_domain(d).unwrap_or_else(|| d.to_owned());
    if organisation(&policy_domain) == organisation(&destination) {
        return ReportAuthorisation::SameOrganisation;
    }
    let name = format!("{policy_domain}._report._dmarc.{destination}");
    match resolver.txt(&name).await {
        Ok(answer) if answer.records.iter().any(|txt| is_dmarc(&txt.joined())) => {
            ReportAuthorisation::Authorised { name }
        }
        Ok(_) => ReportAuthorisation::Unauthorised { name },
        Err(error) if error.is_absent() => ReportAuthorisation::Unauthorised { name },
        Err(error) => ReportAuthorisation::Failed { name, error },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_tree_walk_skips_to_seven_labels_and_ends_at_the_tld() {
        assert_eq!(
            tree_walk("a.mail.example.com"),
            [
                "a.mail.example.com",
                "mail.example.com",
                "example.com",
                "com"
            ]
        );
        let long = "a.b.c.d.e.f.g.h.i.example.com";
        let walk = tree_walk(long);
        assert_eq!(walk.len(), 8);
        assert_eq!(walk[1], "e.f.g.h.i.example.com");
        assert_eq!(walk.last().map(String::as_str), Some("com"));
        assert_eq!(tree_walk("com"), ["com"]);
    }
}
