//! DNS lookups that say why they came back empty, with the name handling DNS
//! work needs: hostname validation, IDNA and the Public Suffix List.
//!
//! Every query answers with a [`Lookup`], which keeps NXDOMAIN, NODATA,
//! SERVFAIL, REFUSED and a timeout apart, so "no record" is never confused with
//! "couldn't tell". The [`Resolver`] trait is the seam: `hickory` provides
//! [`HickoryResolver`] and `testing` an in-memory [`FakeResolver`] that counts
//! queries.

mod logging;
mod lookup;
mod name;
mod resolver;

#[cfg(any(test, feature = "testing"))]
mod fake;
#[cfg(feature = "hickory")]
mod hickory;

#[cfg(any(test, feature = "testing"))]
pub use fake::FakeResolver;
#[cfg(feature = "hickory")]
pub use hickory::{HickoryOptions, HickoryResolver};
pub use logging::{LoggingResolver, QueryRecord};
pub use lookup::{Answer, Lookup, LookupError, Mx, RecordType, Txt};
pub use name::{
    HostnameError, IdnaError, normalise, public_suffix, registrable_domain, reverse_name,
    reversed_labels, to_ascii, to_unicode, validate_hostname, validate_service_name,
};
pub use resolver::{CnameChain, CnameChainError, DEFAULT_MAX_CNAME_HOPS, Resolver};
