//! How a Windows account's name reaches a control pipe's audit actor, and
//! whether a group's SID lies one RID under an account domain, apart from the
//! pipe so that every platform tests them.

/// Whether `sid` is the domain SID `domain` and exactly one RID more.
pub(super) fn one_rid_under(domain: &str, sid: &str) -> bool {
    sid.strip_prefix(domain)
        .and_then(|rest| rest.strip_prefix('-'))
        .is_some_and(|rid| !rid.is_empty() && rid.bytes().all(|b| b.is_ascii_digit()))
}

/// What follows `control-socket:` for the account `domain\account` with SID
/// `sid`: `DOMAIN\account` when both parts are non-empty and each character is
/// ASCII alphanumeric or one of ` ._-$`, `sid=<SID>,non-ascii-name=DOMAIN\account`
/// when some are other alphanumerics, and otherwise `None`, which leaves the bare
/// SID form.
pub(super) fn named_actor(sid: &str, domain: &str, account: &str) -> Option<String> {
    let parts = [domain, account];
    let allowed = |c: char| c.is_alphanumeric() || " ._-$".contains(c);
    if parts
        .iter()
        .any(|part| part.is_empty() || !part.chars().all(allowed))
    {
        return None;
    }
    Some(if parts.iter().all(|part| part.is_ascii()) {
        format!(r"{domain}\{account}")
    } else {
        format!(r"sid={sid},non-ascii-name={domain}\{account}")
    })
}

#[cfg(test)]
mod tests {
    use super::{named_actor, one_rid_under};

    const DOMAIN: &str = "S-1-5-21-1-2-3";
    const SID: &str = "S-1-5-21-1-2-3-1001";

    #[test]
    fn a_group_one_rid_under_the_account_domain_is_granted() {
        assert!(one_rid_under(DOMAIN, SID));
    }

    #[test]
    fn any_other_sid_is_refused() {
        for (domain, sid) in [
            (DOMAIN, DOMAIN),
            (DOMAIN, "S-1-5-21-1-2-3-"),
            (DOMAIN, "S-1-5-21-1-2-3-1001-5"),
            (DOMAIN, "S-1-5-21-9-8-7-1001"),
            (DOMAIN, "S-1-5-32-544"),
            (DOMAIN, "S-1-1-0"),
            ("S-1-5-21-1-2-123", "S-1-5-21-1-2-1234-5"),
        ] {
            assert!(!one_rid_under(domain, sid), "{domain} {sid}");
        }
    }

    #[test]
    fn a_plain_ascii_name_is_the_actor() {
        for (domain, account) in [
            ("NT AUTHORITY", "SYSTEM"),
            ("DESKTOP-1", "first last"),
            ("CORP", "host01$"),
            ("CORP", "svc_backup.2"),
        ] {
            assert_eq!(
                named_actor(SID, domain, account).as_deref(),
                Some(format!(r"{domain}\{account}").as_str())
            );
        }
    }

    #[test]
    fn a_non_ascii_name_follows_the_sid() {
        for (domain, account) in [("BOX", "é"), ("BOX", "\u{430}dmin"), ("ДОМЕН", "operator")]
        {
            assert_eq!(
                named_actor(SID, domain, account).as_deref(),
                Some(format!(r"sid={SID},non-ascii-name={domain}\{account}").as_str())
            );
        }
    }

    #[test]
    fn any_other_name_leaves_only_the_sid() {
        for (domain, account) in [
            ("", "operator"),
            ("BOX", ""),
            ("BOX", r"a\b"),
            ("BOX", "a:b"),
            ("BOX", "a,b"),
            ("BOX", "a=b"),
            ("BOX", "a\nb"),
            ("BOX", "a\tb"),
            ("BOX", "a\u{7f}b"),
            ("BOX", "a\u{2028}b"),
            ("BOX", "a\u{202e}b"),
            ("BOX", "a\u{200b}b"),
            ("BOX", "a\u{200d}b"),
            ("BOX", "\u{feff}a"),
            ("BOX", "\u{430}dmin\u{202e}"),
        ] {
            assert_eq!(
                named_actor(SID, domain, account),
                None,
                "{domain:?} {account:?}"
            );
        }
    }
}
