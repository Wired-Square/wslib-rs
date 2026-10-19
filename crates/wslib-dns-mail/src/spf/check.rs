//! `check_host()` (RFC 7208 §4): whether a host may send for a domain.

use std::net::IpAddr;
use std::time::{SystemTime, UNIX_EPOCH};

use wslib_dns::{LookupError, Resolver};

use super::tree::{LOOKUP_LIMIT, NAME_LIMIT, TermPath, VOID_LOOKUP_LIMIT};
use super::{MacroContext, MacroString, Mechanism, Qualifier, Term, macros};
use crate::discover::{ascii, txt_set};

/// The result of `check_host()` (RFC 7208 §2.6).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum SpfResult {
    None,
    Neutral,
    Pass,
    Fail,
    SoftFail,
    TempError,
    PermError,
}

impl From<Qualifier> for SpfResult {
    fn from(qualifier: Qualifier) -> Self {
        match qualifier {
            Qualifier::Pass => Self::Pass,
            Qualifier::Fail => Self::Fail,
            Qualifier::SoftFail => Self::SoftFail,
            Qualifier::Neutral => Self::Neutral,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct CheckHost {
    pub result: SpfResult,
    /// The mechanism that decided the result, through any `include:`s, or
    /// `None` for a default result.
    pub matched: Option<TermPath>,
    /// The `exp=` text, for a `fail`.
    pub explanation: Option<String>,
    /// Why the result is `temperror`, `permerror` or `none`.
    pub reason: Option<Reason>,
    pub lookups: u32,
    pub void_lookups: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case", tag = "kind"))]
pub enum Reason {
    /// Not a multi-label domain name, so `none` (§4.3).
    InvalidDomain {
        domain: String,
    },
    NoRecord {
        domain: String,
    },
    Lookup {
        domain: String,
        error: LookupError,
    },
    MultipleRecords {
        domain: String,
    },
    Syntax {
        domain: String,
    },
    LookupLimit {
        at: TermPath,
    },
    VoidLookupLimit {
        at: TermPath,
    },
    NameLimit {
        at: TermPath,
        names: usize,
    },
    /// An `include:` target with no SPF record (§5.2).
    IncludeWithoutRecord {
        at: TermPath,
    },
    /// A `redirect=` target with no SPF record (§6.1).
    RedirectWithoutRecord {
        at: TermPath,
    },
}

/// Evaluates the SPF record of the sender's domain, or of `helo` for an
/// empty sender, for a client at `ip`.
pub async fn check_host(
    resolver: &impl Resolver,
    ip: IpAddr,
    helo: &str,
    sender: &str,
) -> CheckHost {
    let ip = match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        v4 => v4,
    };
    let helo = wslib_dns::normalise(helo);
    let sender = match sender.trim().rsplit_once('@') {
        _ if sender.trim().is_empty() => format!("postmaster@{helo}"),
        Some(("", domain)) => format!("postmaster@{domain}"),
        Some(_) => sender.trim().to_owned(),
        None => format!("postmaster@{}", sender.trim()),
    };
    let domain = sender
        .rsplit_once('@')
        .map_or(helo.as_str(), |(_, d)| d)
        .to_owned();
    let mut check = Check {
        ip,
        sender,
        helo,
        lookups: 0,
        void_lookups: 0,
        stack: Vec::new(),
        included_match: None,
    };
    let evaluated = check.evaluate(resolver, ascii(&domain)).await;
    CheckHost {
        result: evaluated.result,
        matched: evaluated.matched,
        explanation: evaluated.explanation,
        reason: evaluated.reason,
        lookups: check.lookups,
        void_lookups: check.void_lookups,
    }
}

struct Check {
    ip: IpAddr,
    sender: String,
    helo: String,
    lookups: u32,
    void_lookups: u32,
    stack: Vec<String>,
    /// The term that made the last passing `include:` pass.
    included_match: Option<TermPath>,
}

struct Evaluated {
    result: SpfResult,
    matched: Option<TermPath>,
    explanation: Option<String>,
    reason: Option<Reason>,
}

impl Evaluated {
    fn error(result: SpfResult, reason: Reason) -> Self {
        Self {
            result,
            matched: None,
            explanation: None,
            reason: Some(reason),
        }
    }
}

/// A mechanism's verdict, or the result that ends evaluation.
type Matched = Result<bool, Box<Evaluated>>;

type Boxed<'a, T> = std::pin::Pin<Box<dyn std::future::Future<Output = T> + Send + 'a>>;

impl Check {
    fn path(&self, term: usize, text: &str) -> TermPath {
        TermPath {
            domains: self.stack.clone(),
            term,
            text: text.to_owned(),
        }
    }

    fn context(&self, domain: &str) -> MacroContext {
        MacroContext {
            sender: Some(self.sender.clone()),
            domain: domain.to_owned(),
            ip: Some(self.ip),
            helo: Some(self.helo.clone()),
            validated_domain: None,
            receiver: None,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .ok()
                .map(|d| d.as_secs()),
        }
    }

    fn evaluate<'a, R: Resolver>(
        &'a mut self,
        resolver: &'a R,
        domain: String,
    ) -> Boxed<'a, Evaluated> {
        Box::pin(async move {
            let multi_label =
                domain.contains('.') && wslib_dns::validate_service_name(&domain).is_ok();
            if !multi_label {
                return Evaluated::error(SpfResult::None, Reason::InvalidDomain { domain });
            }
            let set = txt_set(resolver, domain.clone(), super::is_spf, super::parse).await;
            if let Some(error) = set.failure() {
                let error = error.clone();
                return Evaluated::error(SpfResult::TempError, Reason::Lookup { domain, error });
            }
            if set.is_multiple() {
                return Evaluated::error(SpfResult::PermError, Reason::MultipleRecords { domain });
            }
            let Some(published) = set.single() else {
                return Evaluated::error(SpfResult::None, Reason::NoRecord { domain });
            };
            if !published.parsed.is_usable() {
                return Evaluated::error(SpfResult::PermError, Reason::Syntax { domain });
            }
            let record = published.parsed.record.clone();
            self.stack.push(domain.clone());
            let evaluated = self.evaluate_record(resolver, &domain, &record).await;
            self.stack.pop();
            evaluated
        })
    }

    async fn evaluate_record<R: Resolver>(
        &mut self,
        resolver: &R,
        domain: &str,
        record: &super::SpfRecord,
    ) -> Evaluated {
        let mut context = self.context(domain);
        let uses_p = record.terms.iter().any(|term| match &term.term {
            Term::Directive { mechanism, .. } => {
                spec_of(mechanism).is_some_and(MacroString::uses_validated_domain)
            }
            Term::Redirect(spec) | Term::Explanation(spec) => spec.uses_validated_domain(),
            _ => false,
        });
        if uses_p {
            context.validated_domain = Some(self.validated_domain(resolver, domain).await);
        }
        for (index, term) in record.terms.iter().enumerate() {
            let Term::Directive {
                qualifier,
                mechanism,
            } = &term.term
            else {
                continue;
            };
            let text = term.term.to_string();
            match self
                .mechanism(resolver, index, &text, mechanism, &context)
                .await
            {
                Ok(false) => {}
                Ok(true) => {
                    let result = SpfResult::from(*qualifier);
                    let explanation = match result {
                        SpfResult::Fail => self.explanation(resolver, record, &context).await,
                        _ => None,
                    };
                    let matched = match mechanism {
                        Mechanism::Include(_) => self.included_match.take(),
                        _ => None,
                    };
                    return Evaluated {
                        result,
                        matched: matched.or_else(|| Some(self.path(index, &text))),
                        explanation,
                        reason: None,
                    };
                }
                Err(ended) => return *ended,
            }
        }
        if record.all().is_none()
            && let Some((index, target)) = record.redirect_at()
        {
            let text = record.terms[index].term.to_string();
            if let Err(ended) = self.count(index, &text) {
                return *ended;
            }
            let target = target.expand_domain(&context).unwrap_or_default();
            let evaluated = self.evaluate(resolver, target).await;
            if evaluated.result == SpfResult::None {
                let at = self.path(index, &text);
                return Evaluated::error(
                    SpfResult::PermError,
                    Reason::RedirectWithoutRecord { at },
                );
            }
            return evaluated;
        }
        Evaluated {
            result: SpfResult::Neutral,
            matched: None,
            explanation: None,
            reason: None,
        }
    }

    fn count(&mut self, index: usize, text: &str) -> Result<(), Box<Evaluated>> {
        self.lookups += 1;
        if self.lookups > LOOKUP_LIMIT {
            let at = self.path(index, text);
            return Err(Box::new(Evaluated::error(
                SpfResult::PermError,
                Reason::LookupLimit { at },
            )));
        }
        Ok(())
    }

    /// A lookup that found nothing: counted, and a permerror past the limit.
    fn void(&mut self, index: usize, text: &str) -> Matched {
        self.void_lookups += 1;
        if self.void_lookups > VOID_LOOKUP_LIMIT {
            let at = self.path(index, text);
            return Err(Box::new(Evaluated::error(
                SpfResult::PermError,
                Reason::VoidLookupLimit { at },
            )));
        }
        Ok(false)
    }

    fn failed(&self, domain: String, error: LookupError) -> Matched {
        Err(Box::new(Evaluated::error(
            SpfResult::TempError,
            Reason::Lookup { domain, error },
        )))
    }

    async fn mechanism<R: Resolver>(
        &mut self,
        resolver: &R,
        index: usize,
        text: &str,
        mechanism: &Mechanism,
        context: &MacroContext,
    ) -> Matched {
        if mechanism.queries_dns() {
            self.count(index, text)?;
        }
        let target = || {
            spec_of(mechanism)
                .and_then(|spec| spec.expand_domain(context))
                .unwrap_or_else(|| context.domain.clone())
        };
        match mechanism {
            Mechanism::All => Ok(true),
            Mechanism::Ip4 { address, prefix } => {
                Ok(within(self.ip, IpAddr::V4(*address), prefix.unwrap_or(32)))
            }
            Mechanism::Ip6 { address, prefix } => {
                Ok(within(self.ip, IpAddr::V6(*address), prefix.unwrap_or(128)))
            }
            Mechanism::Include(_) => {
                let name = target();
                let evaluated = self.evaluate(resolver, name).await;
                match evaluated.result {
                    SpfResult::Pass => {
                        self.included_match = evaluated.matched;
                        Ok(true)
                    }
                    SpfResult::Fail | SpfResult::SoftFail | SpfResult::Neutral => Ok(false),
                    SpfResult::None => {
                        let at = self.path(index, text);
                        Err(Box::new(Evaluated::error(
                            SpfResult::PermError,
                            Reason::IncludeWithoutRecord { at },
                        )))
                    }
                    SpfResult::TempError | SpfResult::PermError => Err(Box::new(evaluated)),
                }
            }
            Mechanism::A { cidr, .. } => {
                let name = target();
                match self.addresses(resolver, &name).await {
                    Ok(addresses) => Ok(addresses
                        .iter()
                        .any(|&a| within(self.ip, a, cidr.prefix_for(self.ip)))),
                    Err(error) if error.is_absent() => self.void(index, text),
                    Err(error) => self.failed(name, error),
                }
            }
            Mechanism::Mx { cidr, .. } => {
                let name = target();
                let exchanges = match resolver.mx(&name).await {
                    Ok(answer) => answer.records,
                    Err(error) if error.is_absent() => return self.void(index, text),
                    Err(error) => return self.failed(name, error),
                };
                if exchanges.len() > NAME_LIMIT {
                    let at = self.path(index, text);
                    let names = exchanges.len();
                    return Err(Box::new(Evaluated::error(
                        SpfResult::PermError,
                        Reason::NameLimit { at, names },
                    )));
                }
                for exchange in exchanges {
                    match self.addresses(resolver, &exchange.exchange).await {
                        Ok(addresses)
                            if addresses
                                .iter()
                                .any(|&a| within(self.ip, a, cidr.prefix_for(self.ip))) =>
                        {
                            return Ok(true);
                        }
                        Ok(_) => {}
                        Err(error) if error.is_absent() => {}
                        Err(error) => return self.failed(exchange.exchange, error),
                    }
                }
                Ok(false)
            }
            Mechanism::Ptr(_) => {
                let name = target();
                let validated = self.validated_names(resolver).await;
                Ok(validated
                    .iter()
                    .any(|host| host == &name || host.ends_with(&format!(".{name}"))))
            }
            Mechanism::Exists(_) => {
                let name = target();
                match resolver.a(&name).await {
                    Ok(_) => Ok(true),
                    Err(error) if error.is_absent() => self.void(index, text),
                    Err(error) => self.failed(name, error),
                }
            }
        }
    }

    /// A or AAAA by the client's family, as `a` and `mx` compare (§5.3).
    async fn addresses<R: Resolver>(
        &self,
        resolver: &R,
        name: &str,
    ) -> Result<Vec<IpAddr>, LookupError> {
        match self.ip {
            IpAddr::V4(_) => resolver
                .a(name)
                .await
                .map(|a| a.records.into_iter().map(IpAddr::V4).collect()),
            IpAddr::V6(_) => resolver
                .aaaa(name)
                .await
                .map(|a| a.records.into_iter().map(IpAddr::V6).collect()),
        }
    }

    /// The client's PTR names that resolve back to it, at most ten tried
    /// (§5.5). Lookup errors make no names, not an error.
    async fn validated_names<R: Resolver>(&self, resolver: &R) -> Vec<String> {
        let Ok(answer) = resolver.ptr(self.ip).await else {
            return Vec::new();
        };
        let mut validated = Vec::new();
        for name in answer.records.into_iter().take(NAME_LIMIT) {
            if self
                .addresses(resolver, &name)
                .await
                .is_ok_and(|addresses| addresses.contains(&self.ip))
            {
                validated.push(name);
            }
        }
        validated
    }

    /// `%{p}` (§7.3): a validated name in the domain if there is one, else
    /// any validated name, else `unknown`.
    async fn validated_domain<R: Resolver>(&self, resolver: &R, domain: &str) -> String {
        let names = self.validated_names(resolver).await;
        names
            .iter()
            .find(|name| *name == domain || name.ends_with(&format!(".{domain}")))
            .or(names.first())
            .cloned()
            .unwrap_or_else(|| "unknown".into())
    }

    /// The `exp=` explanation (§6.2). Any problem just means none.
    async fn explanation<R: Resolver>(
        &self,
        resolver: &R,
        record: &super::SpfRecord,
        context: &MacroContext,
    ) -> Option<String> {
        let name = record.explanation()?.expand_domain(context)?;
        let answer = resolver.txt(&name).await.ok()?;
        let [txt] = answer.records.as_slice() else {
            return None;
        };
        macros::parse(&txt.joined(), true).ok()?.expand(context)
    }
}

fn spec_of(mechanism: &Mechanism) -> Option<&MacroString> {
    match mechanism {
        Mechanism::Include(spec) | Mechanism::Exists(spec) => Some(spec),
        Mechanism::A { domain, .. } | Mechanism::Mx { domain, .. } | Mechanism::Ptr(domain) => {
            domain.as_ref()
        }
        _ => None,
    }
}

/// Whether `ip` is in `network`/`prefix`; never across address families.
fn within(ip: IpAddr, network: IpAddr, prefix: u8) -> bool {
    let (ip, network, bits) = match (ip, network) {
        (IpAddr::V4(ip), IpAddr::V4(network)) => (
            u128::from(u32::from(ip)),
            u128::from(u32::from(network)),
            32u8,
        ),
        (IpAddr::V6(ip), IpAddr::V6(network)) => (u128::from(ip), u128::from(network), 128),
        _ => return false,
    };
    let mask = !crate::address::host_mask(bits, prefix);
    ip & mask == network & mask
}
