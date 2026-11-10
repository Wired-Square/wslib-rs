//! DNS lookups that say why they came back empty, with the name handling DNS
//! work needs: hostname validation, IDNA and the Public Suffix List.
//!
//! Every query answers with a [`Lookup`], which keeps NXDOMAIN, NODATA,
//! SERVFAIL, REFUSED and a timeout apart, so "no record" is never confused with
//! "couldn't tell". The [`Resolver`] trait is the seam: `hickory` provides
//! [`HickoryResolver`] and [`AuthoritativeResolver`], and `testing` an
//! in-memory [`FakeResolver`] that counts queries.

mod address;
mod budget;
mod logging;
mod lookup;
mod name;
mod resolver;
pub mod txt;

#[cfg(feature = "hickory")]
mod authoritative;
#[cfg(any(test, feature = "testing"))]
mod fake;
#[cfg(feature = "hickory")]
mod hickory;
#[cfg(feature = "hickory")]
mod public;

pub use address::{is_global, is_global_network};
#[cfg(feature = "hickory")]
pub use authoritative::{AuthoritativeOptions, AuthoritativeResolver};
pub use budget::BudgetResolver;
#[cfg(any(test, feature = "testing"))]
pub use fake::FakeResolver;
#[cfg(feature = "hickory")]
pub use hickory::{HickoryOptions, HickoryResolver};
pub use logging::{LoggingResolver, QueryRecord};
pub use lookup::{
    Answer, DnssecStatus, Ds, Lookup, LookupError, Mx, RecordType, Tlsa, Txt, present,
};
pub use name::{
    HostnameError, IdnaError, normalise, public_suffix, registrable_domain, reverse_name,
    reversed_labels, to_ascii, to_unicode, validate_hostname, validate_service_name,
};
#[cfg(feature = "hickory")]
pub use public::{PUBLIC_RESOLVERS, PublicAnswer, PublicProbe, PublicResolver, probe_public};
pub use resolver::{CnameChain, CnameChainError, DEFAULT_MAX_CNAME_HOPS, Resolver};
