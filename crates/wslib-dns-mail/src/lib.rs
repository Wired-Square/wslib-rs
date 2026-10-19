//! Email-authentication records published in DNS: SPF, DMARC, DKIM keys, BIMI,
//! MTA-STS and TLS-RPT.
//!
//! Each parser is lenient: it reads past faults so every tag can still be
//! shown, and returns a [`Parsed`] whose [`SyntaxFault`]s carry byte spans
//! into the input. Whether a receiver would use the record is answered from
//! those faults, by each record type's `is_usable`.
//!
//! ```
//! use wslib_dns_mail::{FaultCode, dmarc};
//!
//! let input = "v=DMARC1; p=reject; pct=200; rua=mailto:dmarc@example.com";
//! let parsed = dmarc::parse(input);
//! assert_eq!(parsed.record.effective_percent(), 100);
//! assert_eq!(parsed.faults[0].code, FaultCode::InvalidTagValue);
//! assert_eq!(&input[parsed.faults[0].span.clone()], "200");
//! assert!(parsed.is_usable());
//! ```

mod address;
mod fault;
mod inflate;
mod text;
mod uri;

pub mod bimi;
pub mod check;
pub mod dane;
pub mod discover;
pub mod dkim;
pub mod dmarc;
pub mod mta_sts;
pub mod spf;
pub mod tls_rpt;

pub use fault::{FaultCode, Parsed, SyntaxFault};
pub use text::Tag;
pub use uri::ReportUri;
