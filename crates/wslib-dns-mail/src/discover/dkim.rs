use wslib_dns::{CnameChain, CnameChainError, DEFAULT_MAX_CNAME_HOPS, LookupError, Resolver};

use super::{RecordSet, ascii, join_all, txt_set};
use crate::dkim::{DkimKeyRecord, parse};

/// Selectors in common use, for [`probe_dkim`]. There is no standard way to
/// list a domain's selectors, so probing is a guess.
pub const COMMON_SELECTORS: &[&str] = &[
    "default",
    "google",
    "selector1",
    "selector2",
    "k1",
    "k2",
    "k3",
    "s1",
    "s2",
    "dkim",
    "mail",
    "smtp",
    "mandrill",
    "mxvault",
    "everlytickey1",
    "everlytickey2",
    "zendesk1",
    "zendesk2",
    "sig1",
    "protonmail",
    "protonmail2",
    "protonmail3",
    "fm1",
    "fm2",
    "fm3",
];

/// The key records at one selector, and the aliases the name passed through
/// to reach them.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct DkimDiscovery {
    pub selector: String,
    /// Every TXT string at the name: `v=` is optional in a key record, so
    /// none can be told apart as foreign.
    pub records: RecordSet<DkimKeyRecord>,
    /// The aliases from the selector's name to the key's, when they could be
    /// followed.
    pub chain: Option<CnameChain>,
    pub chain_error: Option<CnameChainError>,
}

impl DkimDiscovery {
    /// The name the key is published under, past any aliases: a provider's
    /// host when the selector is delegated to one.
    pub fn terminal(&self) -> Option<&str> {
        self.chain.as_ref().map(CnameChain::terminal)
    }

    /// Whether the selector's aliases reach `expected`, for a provider that
    /// has the selector CNAMEd to its own host. A failed CNAME lookup is the
    /// error.
    pub fn aliased_to(&self, expected: &str) -> Result<AliasVerdict, LookupError> {
        if let Some(CnameChainError::Lookup { error, .. }) = &self.chain_error {
            return Err(error.clone());
        }
        Ok(match &self.chain {
            Some(chain) if !chain.is_aliased() => AliasVerdict::NotAliased,
            Some(chain) if chain.reaches(expected) => AliasVerdict::Reaches,
            _ => AliasVerdict::Elsewhere,
        })
    }
}

/// Where a selector's CNAME chain leads, against the host it should reach.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum AliasVerdict {
    Reaches,
    /// The selector's name is not an alias at all.
    NotAliased,
    /// An alias to somewhere else, or a chain that loops or runs too long.
    Elsewhere,
}

/// Looks up `<selector>._domainkey.<domain>`.
pub async fn dkim(resolver: &impl Resolver, selector: &str, domain: &str) -> DkimDiscovery {
    let name = format!(
        "{}._domainkey.{}",
        selector.to_ascii_lowercase(),
        ascii(domain)
    );
    let chain = resolver.cname_chain(&name, DEFAULT_MAX_CNAME_HOPS).await;
    let records = txt_set(resolver, name, |_| true, parse).await;
    let (chain, chain_error) = match chain {
        Ok(chain) => (Some(chain), None),
        Err(error) => (None, Some(error)),
    };
    DkimDiscovery {
        selector: selector.to_owned(),
        records,
        chain,
        chain_error,
    }
}

/// Looks up each selector concurrently and keeps those with a record or a
/// failed lookup, in the order given.
pub async fn probe_dkim<'a>(
    resolver: &impl Resolver,
    domain: &str,
    selectors: impl IntoIterator<Item = &'a str>,
) -> Vec<DkimDiscovery> {
    join_all(
        selectors
            .into_iter()
            .map(|selector| dkim(resolver, selector, domain)),
    )
    .await
    .into_iter()
    .filter(|found| !found.records.is_absent())
    .collect()
}
