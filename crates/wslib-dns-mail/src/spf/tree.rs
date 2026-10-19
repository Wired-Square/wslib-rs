//! Walking an SPF record and everything it reaches, without a message: what a
//! domain publishes, and what it costs a receiver to evaluate (RFC 7208
//! §4.6.4).

use std::future::Future;
use std::net::IpAddr;
use std::pin::Pin;

use wslib_dns::{LookupError, Resolver};

use super::{MacroContext, MacroString, Mechanism, SpfRecord, Term};
use crate::Parsed;
use crate::discover::{Published, RecordSet, ascii, txt_set};

/// The §4.6.4 limits: ten DNS-querying terms, two void lookups, and ten names
/// behind one `mx` or `ptr`.
pub const LOOKUP_LIMIT: u32 = 10;
pub const VOID_LOOKUP_LIMIT: u32 = 2;
pub const NAME_LIMIT: usize = 10;

/// Bounds on the walk itself, against records built to be expensive. The walk
/// goes past the RFC limits to report the real cost, up to these.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WalkLimits {
    /// DNS-querying terms to follow before counting without querying.
    pub max_lookups: u32,
    /// Nested `include`s and `redirect`s.
    pub max_depth: usize,
}

/// 50 lookups, depth 12.
impl Default for WalkLimits {
    fn default() -> Self {
        Self {
            max_lookups: 50,
            max_depth: 12,
        }
    }
}

/// A domain's SPF record, everything it reaches, and the cost.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SpfTree {
    pub root: SpfNode,
    pub accounting: Accounting,
}

/// The SPF records at one domain and the lookups its terms made.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SpfNode {
    pub domain: String,
    pub records: RecordSet<SpfRecord>,
    /// One per DNS-querying term, and the `redirect=` when it applies, in
    /// evaluation order.
    pub lookups: Vec<TermLookup>,
}

impl SpfNode {
    /// The record, when there is exactly one.
    pub fn record(&self) -> Option<&Parsed<SpfRecord>> {
        self.records.single().map(|published| &published.parsed)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct TermLookup {
    /// Index into the record's terms.
    pub term: usize,
    /// The term as written.
    pub text: String,
    /// Its place in the §4.6.4 count, from 1.
    pub number: u32,
    /// The domain queried; `None` when it needs a message to expand.
    pub target: Option<String>,
    pub outcome: TermOutcome,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum TermOutcome {
    /// An `include:` or `redirect=` target.
    Record(Box<SpfNode>),
    /// `a` or `exists`.
    Addresses(Vec<IpAddr>),
    /// `mx`: each exchange and its addresses.
    Exchanges(Vec<Exchange>),
    /// The term's query found nothing: NXDOMAIN or NODATA.
    Void(LookupError),
    Failed(LookupError),
    NotEvaluated(NotEvaluated),
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Exchange {
    pub host: String,
    pub addresses: Vec<IpAddr>,
    pub error: Option<LookupError>,
}

/// Why a counted term wasn't looked up.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum NotEvaluated {
    /// Its domain-spec uses macros only a message supplies.
    NeedsMessage,
    /// `ptr` depends on the connecting client.
    NeedsClient,
    /// The target is already being evaluated further up.
    Loop,
    TooDeep,
    /// Past [`WalkLimits::max_lookups`].
    Ceiling,
}

/// Where a term sits: the domains from the root to its record, and the term.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct TermPath {
    pub domains: Vec<String>,
    pub term: usize,
    pub text: String,
}

/// The cost of evaluating the record when nothing matches, the worst case a
/// receiver meets.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Accounting {
    /// DNS-querying terms. A lower bound when `truncated`.
    pub lookups: u32,
    pub void_lookups: u32,
    /// The term that took the count past [`LOOKUP_LIMIT`].
    pub lookup_limit_crossed: Option<TermPath>,
    /// The term that took the void count past [`VOID_LOOKUP_LIMIT`].
    pub void_limit_crossed: Option<TermPath>,
    /// Each `mx` or `ptr` with more than [`NAME_LIMIT`] names, and how many.
    pub name_limit_exceeded: Vec<(TermPath, usize)>,
    pub loops: Vec<TermPath>,
    /// The walk stopped at [`WalkLimits`], so there may be more.
    pub truncated: bool,
}

impl Accounting {
    pub fn exceeds_lookup_limit(&self) -> bool {
        self.lookups > LOOKUP_LIMIT
    }

    pub fn exceeds_void_limit(&self) -> bool {
        self.void_lookups > VOID_LOOKUP_LIMIT
    }
}

/// Walks the SPF record of `domain` through every `include:` and applicable
/// `redirect=`, in evaluation order, looking up each `a`, `mx` and `exists`
/// whose target it can expand without a message.
pub async fn walk(resolver: &impl Resolver, domain: &str, limits: WalkLimits) -> SpfTree {
    let mut state = Walk {
        limits,
        accounting: Accounting::default(),
        stack: Vec::new(),
    };
    let root = node(resolver, ascii(domain), None, &mut state).await;
    SpfTree {
        root,
        accounting: state.accounting,
    }
}

/// As [`walk`], but from a record that needn't be published, such as a draft:
/// only what it reaches is looked up.
pub async fn walk_record(
    resolver: &impl Resolver,
    domain: &str,
    record: &str,
    limits: WalkLimits,
) -> SpfTree {
    let domain = ascii(domain);
    let records = RecordSet {
        name: domain.clone(),
        error: None,
        ttl: None,
        records: vec![Published {
            text: record.trim().to_owned(),
            parsed: super::parse(record),
        }],
        others: Vec::new(),
        dnssec: None,
    };
    let mut state = Walk {
        limits,
        accounting: Accounting::default(),
        stack: Vec::new(),
    };
    let root = node(resolver, domain, Some(records), &mut state).await;
    SpfTree {
        root,
        accounting: state.accounting,
    }
}

struct Walk {
    limits: WalkLimits,
    accounting: Accounting,
    /// The domains being evaluated, root first.
    stack: Vec<String>,
}

impl Walk {
    fn path(&self, term: usize, text: &str) -> TermPath {
        TermPath {
            domains: self.stack.clone(),
            term,
            text: text.to_owned(),
        }
    }

    /// Counts a DNS-querying term and returns its number.
    fn count(&mut self, term: usize, text: &str) -> u32 {
        self.accounting.lookups += 1;
        if self.accounting.lookups == LOOKUP_LIMIT + 1 {
            self.accounting.lookup_limit_crossed = Some(self.path(term, text));
        }
        self.accounting.lookups
    }

    fn void(&mut self, term: usize, text: &str) {
        self.accounting.void_lookups += 1;
        if self.accounting.void_lookups == VOID_LOOKUP_LIMIT + 1 {
            self.accounting.void_limit_crossed = Some(self.path(term, text));
        }
    }

    fn over_ceiling(&mut self) -> bool {
        let over = self.accounting.lookups > self.limits.max_lookups;
        self.accounting.truncated |= over;
        over
    }
}

type Boxed<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// The node for `domain`, querying its records unless they're given.
fn node<'a, R: Resolver>(
    resolver: &'a R,
    domain: String,
    records: Option<RecordSet<SpfRecord>>,
    state: &'a mut Walk,
) -> Boxed<'a, SpfNode> {
    Box::pin(async move {
        let records = match records {
            Some(records) => records,
            None => txt_set(resolver, domain.clone(), super::is_spf, super::parse).await,
        };
        state.stack.push(domain.clone());
        let mut lookups = Vec::new();
        if let Some(record) = records
            .single()
            .map(|published| published.parsed.record.clone())
        {
            let context = MacroContext {
                domain: domain.clone(),
                ..MacroContext::default()
            };
            for (index, term) in record.terms.iter().enumerate() {
                if let Term::Directive { mechanism, .. } = &term.term
                    && mechanism.queries_dns()
                {
                    let text = term.term.to_string();
                    lookups.push(
                        mechanism_lookup(resolver, index, &text, mechanism, &context, state).await,
                    );
                }
            }
            if record.all().is_none()
                && let Some((index, target)) = record.redirect_at()
            {
                let text = record.terms[index].term.to_string();
                lookups.push(follow(resolver, index, &text, target, &context, state).await);
            }
        }
        state.stack.pop();
        SpfNode {
            domain,
            records,
            lookups,
        }
    })
}

async fn mechanism_lookup<R: Resolver>(
    resolver: &R,
    index: usize,
    text: &str,
    mechanism: &Mechanism,
    context: &MacroContext,
    state: &mut Walk,
) -> TermLookup {
    let target_spec = match mechanism {
        Mechanism::Include(spec) => {
            return follow(resolver, index, text, spec, context, state).await;
        }
        Mechanism::A { domain, .. } | Mechanism::Mx { domain, .. } => domain.as_ref(),
        Mechanism::Exists(spec) => Some(spec),
        Mechanism::Ptr(domain) => domain.as_ref(),
        _ => unreachable!("only DNS-querying mechanisms are looked up"),
    };
    let number = state.count(index, text);
    let target = match target_spec {
        Some(spec) => spec.expand_domain(context),
        None => Some(context.domain.clone()),
    };
    let lookup = |target: Option<String>, outcome| TermLookup {
        term: index,
        text: text.to_owned(),
        number,
        target,
        outcome,
    };
    if matches!(mechanism, Mechanism::Ptr(_)) {
        return lookup(target, TermOutcome::NotEvaluated(NotEvaluated::NeedsClient));
    }
    let Some(name) = target else {
        return lookup(None, TermOutcome::NotEvaluated(NotEvaluated::NeedsMessage));
    };
    if state.over_ceiling() {
        return lookup(Some(name), TermOutcome::NotEvaluated(NotEvaluated::Ceiling));
    }
    let outcome = match mechanism {
        Mechanism::Mx { .. } => match resolver.mx(&name).await {
            Ok(answer) => {
                if answer.records.len() > NAME_LIMIT {
                    let path = state.path(index, text);
                    state
                        .accounting
                        .name_limit_exceeded
                        .push((path, answer.records.len()));
                }
                let mut exchanges = Vec::new();
                for mx in answer.records {
                    let (addresses, error) = match resolver.ip(&mx.exchange).await {
                        Ok(answer) => (answer.records, None),
                        Err(error) => (Vec::new(), Some(error)),
                    };
                    exchanges.push(Exchange {
                        host: mx.exchange,
                        addresses,
                        error,
                    });
                }
                TermOutcome::Exchanges(exchanges)
            }
            Err(error) => absent_or_failed(error, index, text, state),
        },
        Mechanism::Exists(_) => match resolver.a(&name).await {
            Ok(answer) => {
                TermOutcome::Addresses(answer.records.into_iter().map(IpAddr::V4).collect())
            }
            Err(error) => absent_or_failed(error, index, text, state),
        },
        _ => match resolver.ip(&name).await {
            Ok(answer) => TermOutcome::Addresses(answer.records),
            Err(error) => absent_or_failed(error, index, text, state),
        },
    };
    lookup(Some(name), outcome)
}

fn absent_or_failed(error: LookupError, index: usize, text: &str, state: &mut Walk) -> TermOutcome {
    if error.is_absent() {
        state.void(index, text);
        TermOutcome::Void(error)
    } else {
        TermOutcome::Failed(error)
    }
}

/// An `include:` or `redirect=`: counted, then the target's record walked.
async fn follow<R: Resolver>(
    resolver: &R,
    index: usize,
    text: &str,
    spec: &MacroString,
    context: &MacroContext,
    state: &mut Walk,
) -> TermLookup {
    let number = state.count(index, text);
    let target = spec.expand_domain(context);
    let outcome = match &target {
        None => TermOutcome::NotEvaluated(NotEvaluated::NeedsMessage),
        Some(name) if state.stack.contains(name) => {
            let path = state.path(index, text);
            state.accounting.loops.push(path);
            TermOutcome::NotEvaluated(NotEvaluated::Loop)
        }
        Some(_) if state.stack.len() > state.limits.max_depth => {
            state.accounting.truncated = true;
            TermOutcome::NotEvaluated(NotEvaluated::TooDeep)
        }
        Some(_) if state.over_ceiling() => TermOutcome::NotEvaluated(NotEvaluated::Ceiling),
        Some(name) => {
            let child = node(resolver, name.clone(), None, state).await;
            // §4.6.4: void means NXDOMAIN or an empty answer, not an answer
            // that merely holds no SPF record.
            if child
                .records
                .error
                .as_ref()
                .is_some_and(LookupError::is_absent)
            {
                state.void(index, text);
            }
            TermOutcome::Record(Box::new(child))
        }
    };
    TermLookup {
        term: index,
        text: text.to_owned(),
        number,
        target,
        outcome,
    }
}

/// An `include:` or `redirect=` target and the record found there.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Target {
    pub redirect: bool,
    pub domain: String,
    /// The SPF record's text, when there is exactly one.
    pub record: Option<String>,
    pub at: TermPath,
}

impl SpfTree {
    /// Every node, root first, depth-first in evaluation order, with the
    /// domains leading to it.
    pub fn nodes(&self) -> Vec<(Vec<String>, &SpfNode)> {
        let mut out = Vec::new();
        collect(&self.root, &mut Vec::new(), &mut out);
        out
    }

    /// Every `include:` and `redirect=` target that was walked.
    pub fn targets(&self) -> Vec<Target> {
        let mut out = Vec::new();
        for (domains, node) in self.nodes() {
            for lookup in &node.lookups {
                if let TermOutcome::Record(child) = &lookup.outcome {
                    out.push(Target {
                        redirect: lookup.text.to_ascii_lowercase().starts_with("redirect="),
                        domain: child.domain.clone(),
                        record: child
                            .records
                            .single()
                            .map(|published| published.text.clone()),
                        at: TermPath {
                            domains: domains.clone(),
                            term: lookup.term,
                            text: lookup.text.clone(),
                        },
                    });
                }
            }
        }
        out
    }
}

fn collect<'a>(
    node: &'a SpfNode,
    domains: &mut Vec<String>,
    out: &mut Vec<(Vec<String>, &'a SpfNode)>,
) {
    domains.push(node.domain.clone());
    out.push((domains.clone(), node));
    for lookup in &node.lookups {
        if let TermOutcome::Record(child) = &lookup.outcome {
            collect(child, domains, out);
        }
    }
    domains.pop();
}
