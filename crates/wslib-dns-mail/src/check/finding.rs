use std::borrow::Cow;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr};

use wslib_dns::LookupError;

use crate::SyntaxFault;
use crate::dmarc::Policy;
use crate::spf::tree::TermPath;

/// One way a domain's records break a specification or a common practice.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Finding {
    pub code: FindingCode,
    pub kind: Kind,
    pub severity: Severity,
    /// The DNS name or record it's about.
    pub subject: String,
    /// The specification section, such as `RFC 7208 §4.6.4`.
    pub reference: Cow<'static, str>,
    pub detail: Detail,
}

impl Finding {
    /// A finding with its code's kind, severity and reference.
    pub fn new(code: FindingCode, subject: impl Into<String>, detail: Detail) -> Self {
        let (kind, severity, reference) = code.defaults();
        Self {
            code,
            kind,
            severity,
            subject: subject.into(),
            reference: Cow::Borrowed(reference),
            detail,
        }
    }

    pub(crate) fn severity(mut self, severity: Severity) -> Self {
        self.severity = severity;
        self
    }
}

/// Whether a finding breaks a MUST of a specification or is merely unwise.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum Kind {
    /// Out of spec: a MUST is broken, or a receiver errors.
    Spec,
    /// In spec, but inadvisable.
    Practice,
    /// Neither: a fact about the domain or about the check itself.
    Observation,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum Severity {
    Info,
    Warning,
    Error,
}

macro_rules! finding_codes {
    ($($code:ident => $name:literal, $kind:ident, $severity:ident, $reference:literal;)+) => {
        /// What a finding is about. The serialised names are stable.
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
        #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
        #[non_exhaustive]
        pub enum FindingCode {
            $(#[cfg_attr(feature = "serde", serde(rename = $name))] $code,)+
        }

        impl FindingCode {
            /// Every code, in catalogue order.
            pub const ALL: &[FindingCode] = &[$(Self::$code,)+];

            /// The snake_case name it serialises as.
            pub fn as_str(self) -> &'static str {
                match self {
                    $(Self::$code => $name,)+
                }
            }

            fn defaults(self) -> (Kind, Severity, &'static str) {
                match self {
                    $(Self::$code => (Kind::$kind, Severity::$severity, $reference),)+
                }
            }
        }
    };
}

finding_codes! {
    SpfMissing => "spf_missing", Practice, Warning, "RFC 7208";
    SpfMultipleRecords => "spf_multiple_records", Spec, Error, "RFC 7208 §4.5";
    SpfSyntax => "spf_syntax", Spec, Error, "RFC 7208 §4.6, §12";
    SpfInvalidSeparator => "spf_invalid_separator", Spec, Warning, "RFC 7208 §12";
    SpfLookupLimitExceeded => "spf_lookup_limit_exceeded", Spec, Error, "RFC 7208 §4.6.4";
    SpfVoidLookupLimitExceeded => "spf_void_lookup_limit_exceeded", Spec, Error, "RFC 7208 §4.6.4";
    SpfMxPtrNameLimitExceeded => "spf_mx_ptr_name_limit_exceeded", Spec, Error, "RFC 7208 §4.6.4";
    SpfIncludeTargetMissing => "spf_include_target_missing", Spec, Error, "RFC 7208 §5.2";
    SpfRedirectTargetMissing => "spf_redirect_target_missing", Spec, Error, "RFC 7208 §6.1";
    SpfLookupFailed => "spf_lookup_failed", Spec, Warning, "RFC 7208 §4.4";
    SpfLoop => "spf_loop", Spec, Error, "RFC 7208 §4.6.4";
    SpfPtrUsed => "spf_ptr_used", Practice, Warning, "RFC 7208 §5.5";
    SpfPermissiveAll => "spf_permissive_all", Practice, Error, "RFC 7208 §5.1";
    SpfNeutralAll => "spf_neutral_all", Practice, Warning, "RFC 7208 §5.1";
    SpfNoAll => "spf_no_all", Practice, Warning, "RFC 7208 §4.7";
    SpfTermsAfterAll => "spf_terms_after_all", Practice, Info, "RFC 7208 §5.1";
    SpfRedirectIgnored => "spf_redirect_ignored", Practice, Info, "RFC 7208 §6.1";
    SpfRecordTooLong => "spf_record_too_long", Practice, Warning, "RFC 7208 §3.4";
    SpfPrivateNetblock => "spf_private_netblock", Practice, Warning, "RFC 7208 §5.6";
    SpfModifierNamedLikeMechanism => "spf_modifier_named_like_mechanism", Practice, Warning, "RFC 7208 §6";
    DmarcMissing => "dmarc_missing", Practice, Warning, "RFC 7489";
    DmarcMultipleRecords => "dmarc_multiple_records", Spec, Error, "RFC 7489 §6.6.3";
    DmarcVersionNotFirst => "dmarc_version_not_first", Spec, Error, "RFC 7489 §6.4";
    DmarcVersionNoncanonical => "dmarc_version_noncanonical", Spec, Error, "RFC 7489 §6.3";
    DmarcPolicyOutOfOrder => "dmarc_policy_out_of_order", Spec, Warning, "RFC 7489 §6.3";
    DmarcSyntax => "dmarc_syntax", Spec, Error, "RFC 7489 §6.4";
    DmarcPolicyMissing => "dmarc_policy_missing", Spec, Error, "RFC 7489 §6.6.3";
    DmarcPolicyInvalid => "dmarc_policy_invalid", Spec, Error, "RFC 7489 §6.6.3";
    DmarcTagValueInvalid => "dmarc_tag_value_invalid", Spec, Error, "RFC 7489 §6.3";
    DmarcTagDuplicate => "dmarc_tag_duplicate", Spec, Error, "RFC 7489 §6.4";
    DmarcTagUnknown => "dmarc_tag_unknown", Spec, Info, "RFC 7489 §6.3";
    DmarcReportUriInvalid => "dmarc_report_uri_invalid", Spec, Error, "RFC 7489 §6.2";
    DmarcExternalReportUnauthorised => "dmarc_external_report_unauthorised", Spec, Error, "RFC 7489 §7.1";
    DmarcExternalReportLookupFailed => "dmarc_external_report_lookup_failed", Spec, Warning, "RFC 7489 §7.1";
    DmarcPolicyInherited => "dmarc_policy_inherited", Observation, Info, "RFC 7489 §6.6.3";
    DmarcPctPartial => "dmarc_pct_partial", Practice, Warning, "RFC 7489 §6.3";
    DmarcSubdomainPolicyWeaker => "dmarc_subdomain_policy_weaker", Practice, Info, "RFC 7489 §6.3";
    DmarcNoAggregateReports => "dmarc_no_aggregate_reports", Practice, Warning, "RFC 7489 §6.3";
    DmarcPolicyNone => "dmarc_policy_none", Practice, Info, "RFC 7489 §6.3";
    DkimKeyMissing => "dkim_key_missing", Spec, Error, "RFC 6376 §6.1.2";
    DkimMultipleRecords => "dkim_multiple_records", Spec, Error, "RFC 6376 §3.6.2.2";
    DkimSyntax => "dkim_syntax", Spec, Error, "RFC 6376 §3.6.1";
    DkimKeyRevoked => "dkim_key_revoked", Spec, Info, "RFC 6376 §3.6.1";
    DkimTestingMode => "dkim_testing_mode", Practice, Warning, "RFC 6376 §3.6.1";
    DkimRsaKeyTooShort => "dkim_rsa_key_too_short", Spec, Error, "RFC 8301 §3.2";
    DkimRsaKeyWeak => "dkim_rsa_key_weak", Practice, Warning, "RFC 8301 §3.2";
    MxMissing => "mx_missing", Practice, Info, "RFC 5321 §5.1";
    MxNullWithOthers => "mx_null_with_others", Spec, Error, "RFC 7505 §3";
    MxExchangeIsCname => "mx_exchange_is_cname", Spec, Error, "RFC 2181 §10.3, RFC 5321 §5.1";
    MxExchangeIsIpLiteral => "mx_exchange_is_ip_literal", Spec, Error, "RFC 5321 §5.1";
    MxExchangeNoAddress => "mx_exchange_no_address", Spec, Error, "RFC 5321 §5.1";
    MxPtrMissing => "mx_ptr_missing", Practice, Warning, "RFC 1912 §2.1";
    MxFcrdnsMismatch => "mx_fcrdns_mismatch", Practice, Warning, "RFC 1912 §2.1";
    MxListed => "mx_listed", Practice, Warning, "RFC 5782";
    MxDnsblQueryBlocked => "mx_dnsbl_query_blocked", Observation, Info, "RFC 5782";
    BimiSyntax => "bimi_syntax", Spec, Error, "draft-brand-indicators-for-message-identification";
    BimiInsecureUri => "bimi_insecure_uri", Spec, Error, "draft-brand-indicators-for-message-identification";
    BimiDmarcNotEnforcing => "bimi_dmarc_not_enforcing", Spec, Error, "draft-brand-indicators-for-message-identification";
    MtaStsSyntax => "mta_sts_syntax", Spec, Error, "RFC 8461 §3";
    MtaStsMultipleRecords => "mta_sts_multiple_records", Spec, Error, "RFC 8461 §3.1";
    MtaStsPolicyUnreachable => "mta_sts_policy_unreachable", Spec, Error, "RFC 8461 §3.3";
    MtaStsMxNotCovered => "mta_sts_mx_not_covered", Spec, Error, "RFC 8461 §4.1";
    MtaStsMaxAgeOutOfRange => "mta_sts_max_age_out_of_range", Spec, Error, "RFC 8461 §3.2";
    MtaStsTesting => "mta_sts_testing", Practice, Info, "RFC 8461 §5";
    TlsRptSyntax => "tls_rpt_syntax", Spec, Error, "RFC 8460 §3";
    TlsRptMissingWithMtaSts => "tls_rpt_missing_with_mta_sts", Practice, Warning, "RFC 8461 §8";
    LookupFailed => "lookup_failed", Observation, Warning, "RFC 1035 §4.1.1";
    Incomplete => "incomplete", Observation, Warning, "";
}

impl fmt::Display for FindingCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The facts behind a finding, shaped by what it's about.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case", tag = "kind"))]
pub enum Detail {
    None,
    /// A syntax fault, with the text its span indexes.
    Fault {
        fault: SyntaxFault,
        text: String,
    },
    /// Every record found where one was allowed.
    Records {
        texts: Vec<String>,
    },
    Lookup {
        name: String,
        error: LookupError,
    },
    /// A §4.6.4 count and where it crossed the limit.
    Count {
        count: u32,
        limit: u32,
        crossed_at: Option<TermPath>,
        truncated: bool,
    },
    Names {
        at: TermPath,
        names: usize,
    },
    Term {
        at: TermPath,
    },
    Target {
        at: TermPath,
        target: String,
    },
    Length {
        bytes: usize,
        limit: usize,
    },
    /// A netblock and the flattened path to it.
    Netblock {
        source: Vec<String>,
        cidr: String,
    },
    /// A DMARC `p` or `sp` the receiver can't use, and whether `rua` saves it
    /// as `none` (§6.6.3).
    Policy {
        tag: String,
        treated_as_none: bool,
    },
    Percent {
        percent: u8,
    },
    Weaker {
        tag: String,
        policy: Policy,
        domain_policy: Policy,
    },
    Inherited {
        from: String,
    },
    Report {
        uri: String,
        name: Option<String>,
        error: Option<LookupError>,
    },
    KeySize {
        bits: u32,
    },
    Exchange {
        exchange: String,
        target: Option<String>,
    },
    Address {
        exchange: String,
        address: IpAddr,
        names: Vec<String>,
    },
    Listed {
        address: IpAddr,
        zone: String,
        codes: Vec<Ipv4Addr>,
        reason: Option<String>,
    },
    /// The DMARC policy BIMI needs to be enforcing, as found.
    Enforcement {
        domain: String,
        policy: Option<Policy>,
        percent: u8,
        subdomain_policy: Option<Policy>,
    },
    MaxAge {
        seconds: Option<u64>,
        limit: u32,
    },
    Unreachable {
        url: String,
        reason: String,
    },
    Uncovered {
        exchange: String,
    },
    /// The checks a deadline or query budget cut short.
    Incomplete {
        checks: Vec<String>,
    },
    /// Why a record is out of spec while receivers still use it.
    Risk {
        fault: SyntaxFault,
        text: String,
        risk: String,
    },
}

/// Neutral, RFC-style wording; consumers write their own.
impl fmt::Display for Finding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} ({:?}, {:?}): {}",
            self.code, self.kind, self.severity, self.subject
        )?;
        if !self.reference.is_empty() {
            write!(f, " [{}]", self.reference)?;
        }
        Ok(())
    }
}
