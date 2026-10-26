//! The store's half of the ceremonies: accounts, passkeys kept and looked up,
//! names and the counter. Each check on a response itself is
//! `wslib_auth_passkey`'s, and tested there.

use std::cell::Cell;

use wslib_appliance_store::StoreError;
use wslib_appliance_types::{Role, User};
use wslib_auth_passkey::testing::SoftPasskey;

use super::*;
use crate::tests::{store, user};

thread_local! {
    pub(super) static LAST_REFUSAL: Cell<Option<&'static str>> = const { Cell::new(None) };
}

const HOST: &str = "box.local:8443";
const ORIGIN: &str = "https://box.local:8443";

fn rp() -> RelyingParty {
    RelyingParty::for_host(HOST).expect("a name")
}

/// Which check refused, by the reason it gave the journal.
fn reason<T: std::fmt::Debug>(result: Result<T, AuthError>, ceremony: Ceremony) -> &'static str {
    match result {
        Err(AuthError::PasskeyRefused(c)) if c == ceremony => {
            LAST_REFUSAL.take().expect("a refusal names its check")
        }
        other => panic!("{other:?}"),
    }
}

struct Appliance {
    store: Store,
    passkeys: Passkeys,
    admin: User,
}

impl Appliance {
    async fn new() -> Self {
        let store = store().await;
        let admin = user(&store, "admin", Role::Admin).await;
        Self {
            store,
            passkeys: Passkeys::default(),
            admin,
        }
    }

    async fn registration(
        &self,
        account: &User,
        passkey: &mut SoftPasskey,
    ) -> RegistrationCredential {
        self.registration_on(&rp(), account, passkey).await
    }

    async fn registration_on(
        &self,
        rp: &RelyingParty,
        account: &User,
        passkey: &mut SoftPasskey,
    ) -> RegistrationCredential {
        let options = self
            .passkeys
            .begin_registration(&self.store, rp, account, "Widget")
            .await
            .expect("options");
        passkey.register(&options, rp.origin())
    }

    async fn register(&self, account: &User, passkey: &mut SoftPasskey) -> PasskeyView {
        let credential = self.registration(account, passkey).await;
        self.passkeys
            .finish_registration(&self.store, &rp(), &account.id, "laptop", &credential)
            .await
            .expect("registered")
    }

    fn sign_in_answer(&self, passkey: &mut SoftPasskey) -> AssertionCredential {
        let options = self.passkeys.begin_sign_in(&rp()).expect("options");
        passkey.answer(&options, ORIGIN)
    }

    async fn sign_in(&self, credential: &AssertionCredential) -> Result<PasskeySignIn, AuthError> {
        self.passkeys
            .finish_sign_in(&self.store, &rp(), credential)
            .await
    }

    async fn reauthentication(
        &self,
        account: &User,
        passkey: &mut SoftPasskey,
    ) -> AssertionCredential {
        let options = self
            .passkeys
            .begin_reauthentication(&self.store, &rp(), &account.id)
            .await
            .expect("options");
        passkey.answer(&options, ORIGIN)
    }
}

#[tokio::test]
async fn a_passkey_registers_and_signs_in_without_a_username() {
    let ours = Appliance::new().await;
    let mut passkey = SoftPasskey::new();
    let view = ours.register(&ours.admin, &mut passkey).await;
    assert_eq!(
        (view.name.as_str(), view.host.as_str()),
        ("laptop", "box.local")
    );

    for _ in 0..2 {
        let answer = ours.sign_in_answer(&mut passkey);
        let signed_in = ours.sign_in(&answer).await.expect("signed in");
        assert_eq!(signed_in.account.user.id, ours.admin.id);
        assert_eq!(
            signed_in.passkey_id, view.id,
            "the uuid, not the credential id"
        );
    }
    let stored = ours
        .store
        .passkey_by_credential_id(passkey.credential_id())
        .await
        .unwrap()
        .expect("kept");
    assert_eq!(stored.sign_count, 2);
    assert!(stored.last_used_at.is_some());
    let account = ours
        .store
        .user_by_id(&ours.admin.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        account.user.last_login_at, None,
        "the session's issue stamps the sign-in"
    );
}

#[tokio::test]
async fn options_leave_out_or_offer_the_accounts_kept_passkeys() {
    let ours = Appliance::new().await;
    let mut passkey = SoftPasskey::new();
    ours.register(&ours.admin, &mut passkey).await;
    let ids = |descriptors: &[wslib_appliance_types::passkey::CredentialDescriptor]| {
        descriptors.iter().map(|d| d.id.clone()).collect::<Vec<_>>()
    };
    let expected = vec![ours.sign_in_answer(&mut passkey).raw_id];

    let registration = ours
        .passkeys
        .begin_registration(&ours.store, &rp(), &ours.admin, "Widget")
        .await
        .expect("options");
    assert_eq!(ids(&registration.exclude_credentials), expected);
    assert_eq!(registration.user.name, "admin");

    let reauthentication = ours
        .passkeys
        .begin_reauthentication(&ours.store, &rp(), &ours.admin.id)
        .await
        .expect("options");
    assert_eq!(ids(&reauthentication.allow_credentials), expected);
}

#[tokio::test]
async fn another_accounts_registration_challenge_or_a_known_credential_is_refused() {
    let ours = Appliance::new().await;
    let operator = user(&ours.store, "operator", Role::Operator).await;
    let mut passkey = SoftPasskey::new();
    let theirs = ours.registration(&operator, &mut passkey).await;
    let refused = ours
        .passkeys
        .finish_registration(&ours.store, &rp(), &ours.admin.id, "laptop", &theirs)
        .await;
    assert_eq!(
        reason(refused, Ceremony::Registration),
        "the challenge is unknown, spent, expired or someone else's"
    );

    ours.register(&ours.admin, &mut passkey).await;
    let again = ours.registration(&ours.admin, &mut passkey).await;
    let again = ours
        .passkeys
        .finish_registration(&ours.store, &rp(), &ours.admin.id, "again", &again)
        .await;
    assert!(
        matches!(again, Err(AuthError::Store(StoreError::PasskeyTaken))),
        "§7.1 step 26: {again:?}"
    );
}

#[tokio::test]
async fn a_passkeys_name_is_trimmed_and_bounded() {
    assert_eq!(passkey_name("  laptop ").unwrap(), "laptop");
    assert_eq!(
        passkey_name(&"é".repeat(MAX_PASSKEY_NAME_LEN))
            .unwrap()
            .chars()
            .count(),
        64
    );
    for bad in ["", "   ", "a\nb", &"x".repeat(MAX_PASSKEY_NAME_LEN + 1)] {
        assert!(
            matches!(passkey_name(bad), Err(AuthError::PasskeyName)),
            "{bad:?}"
        );
    }

    let ours = Appliance::new().await;
    let credential = ours
        .registration(&ours.admin, &mut SoftPasskey::new())
        .await;
    let rp = rp();
    let finish = |name| {
        ours.passkeys
            .finish_registration(&ours.store, &rp, &ours.admin.id, name, &credential)
    };
    let refused = finish(" ").await;
    assert!(
        matches!(refused, Err(AuthError::PasskeyName)),
        "{refused:?}"
    );
    finish("laptop")
        .await
        .expect("the challenge survives a refused name");
}

#[tokio::test]
async fn an_unknown_passkey_does_not_sign_in() {
    let ours = Appliance::new().await;
    let elsewhere = Appliance::new().await;
    let mut passkey = SoftPasskey::new();
    elsewhere.register(&elsewhere.admin, &mut passkey).await;
    let answer = ours.sign_in_answer(&mut passkey);
    assert_eq!(
        reason(ours.sign_in(&answer).await, Ceremony::SignIn),
        "no such passkey"
    );
}

#[tokio::test]
async fn a_counter_that_did_not_move_is_refused_as_a_possible_clone() {
    let ours = Appliance::new().await;
    let mut passkey = SoftPasskey::new();
    ours.register(&ours.admin, &mut passkey).await;
    let earlier = ours.sign_in_answer(&mut passkey);
    let later = ours.sign_in_answer(&mut passkey);
    ours.sign_in(&later).await.expect("signed in");

    let refused = ours.sign_in(&earlier).await;
    assert!(
        matches!(
            refused,
            Err(AuthError::PasskeyCounterDidNotMove(Ceremony::SignIn))
        ),
        "§7.2 step 22: {refused:?}"
    );

    let mut counterless = SoftPasskey::counterless();
    ours.register(&ours.admin, &mut counterless).await;
    for _ in 0..2 {
        let answer = ours.sign_in_answer(&mut counterless);
        ours.sign_in(&answer)
            .await
            .expect("an authenticator that keeps no count");
    }
}

#[tokio::test]
async fn a_passkey_made_on_another_name_does_not_sign_in_here() {
    let ours = Appliance::new().await;
    let mut passkey = SoftPasskey::new();
    let old_name = RelyingParty::for_host("widget-01.local").unwrap();
    let credential = ours
        .registration_on(&old_name, &ours.admin, &mut passkey)
        .await;
    ours.passkeys
        .finish_registration(&ours.store, &old_name, &ours.admin.id, "old", &credential)
        .await
        .expect("registered on the old name");

    let answer = ours.sign_in_answer(&mut passkey);
    assert_eq!(
        reason(ours.sign_in(&answer).await, Ceremony::SignIn),
        "the passkey was made on another host",
        "§7.2 step 15"
    );
}

#[tokio::test]
async fn a_disabled_accounts_passkey_does_not_sign_in() {
    let ours = Appliance::new().await;
    let mut passkey = SoftPasskey::new();
    ours.register(&ours.admin, &mut passkey).await;
    ours.store.set_enabled(&ours.admin.id, false).await.unwrap();
    let answer = ours.sign_in_answer(&mut passkey);
    assert_eq!(
        reason(ours.sign_in(&answer).await, Ceremony::SignIn),
        "the account is disabled"
    );
}

#[tokio::test]
async fn reauthentication_asks_for_this_accounts_passkeys_here_and_takes_no_other() {
    let ours = Appliance::new().await;
    let operator = user(&ours.store, "operator", Role::Operator).await;
    let mut mine = SoftPasskey::new();
    let view = ours.register(&ours.admin, &mut mine).await;

    let none = ours
        .passkeys
        .begin_reauthentication(&ours.store, &rp(), &operator.id)
        .await;
    assert!(
        matches!(&none, Err(AuthError::NoPasskeysHere(host)) if host == "box.local"),
        "{none:?}"
    );

    let answer = ours.reauthentication(&ours.admin, &mut mine).await;
    let proved = ours
        .passkeys
        .finish_reauthentication(&ours.store, &rp(), &ours.admin.id, &answer)
        .await
        .expect("proved");
    assert_eq!(proved, view.id);

    let answer = ours.reauthentication(&ours.admin, &mut mine).await;
    let as_operator = ours
        .passkeys
        .finish_reauthentication(&ours.store, &rp(), &operator.id, &answer)
        .await;
    assert_eq!(
        reason(as_operator, Ceremony::Reauthentication),
        "the challenge is unknown, spent, expired or someone else's",
        "the admin's challenge is not the operator's"
    );
}

#[tokio::test]
async fn reauthentication_refuses_another_accounts_passkey() {
    let ours = Appliance::new().await;
    let operator = user(&ours.store, "operator", Role::Operator).await;
    let mut admins = SoftPasskey::new();
    ours.register(&ours.admin, &mut admins).await;
    ours.register(&operator, &mut SoftPasskey::new()).await;

    let options = ours
        .passkeys
        .begin_reauthentication(&ours.store, &rp(), &operator.id)
        .await
        .unwrap();
    let answer = admins.answer(&options, ORIGIN);
    let refused = ours
        .passkeys
        .finish_reauthentication(&ours.store, &rp(), &operator.id, &answer)
        .await;
    assert_eq!(
        reason(refused, Ceremony::Reauthentication),
        "another account's passkey",
        "§7.2 step 5"
    );
}

#[test]
fn a_host_the_relying_party_refuses_maps_to_this_crates_errors() {
    assert!(matches!(
        RelyingParty::for_host("192.168.1.10").map_err(AuthError::from),
        Err(AuthError::NotOnAnIpAddress)
    ));
    assert!(matches!(
        RelyingParty::for_host("box_local").map_err(AuthError::from),
        Err(AuthError::BadHost)
    ));
}
