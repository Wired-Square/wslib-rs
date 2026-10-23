use std::io;

use wslib_1password::testing::FakeRunner;
use wslib_1password::{
    Assignment, Error, FieldType, ItemRef, Op, Output, Vault, VaultInfo, accounts, find_account,
};

fn op(fake: &FakeRunner) -> Op<FakeRunner> {
    Op::new(fake.clone(), "ops.1password.com")
}

fn vault(fake: &FakeRunner) -> Vault<FakeRunner> {
    op(fake).vault(VaultInfo {
        id: "v1".into(),
        name: "Deploy".into(),
    })
}

fn args(fake: &FakeRunner, call: usize) -> Vec<String> {
    fake.calls()[call].args().to_vec()
}

fn has(args: &[String], arg: &str) -> bool {
    args.iter().any(|a| a == arg)
}

const ID: &str = "4ld6tdxnvj5kgsbjbb4e3opyua";
const OTHER_ID: &str = "ubvcz6g3xb4bkmrkbs2xq6cfzi";
const ITEM: &str =
    r#"{"id":"4ld6tdxnvj5kgsbjbb4e3opyua","title":"CA","vault":{"id":"v1","name":"Deploy"}}"#;
const AMBIGUOUS: &str = "[ERROR] 2026/10/23 10:00:00 More than one item matches \"CA\". Try again and specify the item by its ID:\n\t* for the item \"CA\" in vault Deploy: 4ld6tdxnvj5kgsbjbb4e3opyua\n\t* for the item \"CA\" in vault Deploy: ubvcz6g3xb4bkmrkbs2xq6cfzi\n";

const ODD_BYTES: [&[u8]; 4] = [
    b"line one\nline two\n",
    b"windows\r\nline\r\n",
    &[0, 159, 146, 150, 255, 10, 13],
    b"",
];

#[test]
fn sign_in_signed_in_asks_once() {
    let fake = FakeRunner::new();
    fake.respond(Output::ok(
        r#"{"url":"https://ops.1password.com/","user_uuid":"U1"}"#,
    ));
    let who = op(&fake).sign_in().unwrap();
    assert_eq!(who.url, "ops.1password.com");
    assert_eq!(
        args(&fake, 0),
        ["whoami", "--format=json", "--account", "ops.1password.com"]
    );
}

#[test]
fn sign_in_signed_out_signs_in_then_asks_again() {
    let fake = FakeRunner::new();
    fake.respond(Output::fail("[ERROR] You are not currently signed in."))
        .respond(Output::ok(""))
        .respond(Output::ok(r#"{"user_uuid":"U1"}"#));
    assert_eq!(op(&fake).sign_in().unwrap().user_uuid, "U1");
    assert_eq!(args(&fake, 1), ["signin", "--account", "ops.1password.com"]);
    assert!(fake.is_done());
}

#[test]
fn sign_in_that_fails_is_not_signed_in() {
    let fake = FakeRunner::new();
    fake.respond(Output::fail("[ERROR] You are not currently signed in."))
        .respond(Output::fail("[ERROR] authorization prompt dismissed"));
    assert!(matches!(op(&fake).sign_in(), Err(Error::NotApproved(_))));
}

#[test]
fn sign_in_with_no_accounts_does_not_try_to_sign_in() {
    let fake = FakeRunner::new();
    fake.respond(Output::fail(
        "No accounts configured for use with 1Password CLI.",
    ));
    assert!(matches!(
        op(&fake).sign_in(),
        Err(Error::NoAccountsConfigured(_))
    ));
    assert_eq!(fake.calls().len(), 1);
}

#[test]
fn every_account_call_names_the_account() {
    let fake = FakeRunner::new();
    fake.respond(Output::ok("[]"))
        .respond(Output::ok(r#"{"id":"v9","name":"New"}"#))
        .respond(Output::ok("{}"))
        .respond(Output::ok("[]"))
        .respond(Output::ok("x"));
    let op = op(&fake);
    op.vaults().unwrap();
    op.create_vault("New").unwrap();
    op.current_user().unwrap();
    op.items(&[]).unwrap();
    op.read("op://Deploy/Key/field").unwrap();
    for call in fake.calls() {
        assert!(
            call.args()
                .ends_with(&["--account".into(), "ops.1password.com".into()]),
            "{call}"
        );
    }
}

#[test]
fn an_unscoped_client_names_no_account() {
    let fake = FakeRunner::new();
    fake.respond(Output::ok("{}"));
    Op::unscoped(fake.clone()).whoami().unwrap();
    assert_eq!(args(&fake, 0), ["whoami", "--format=json"]);
}

#[test]
fn a_raw_call_is_scoped_and_its_failure_mapped() {
    let fake = FakeRunner::new();
    fake.respond(Output::ok("raw\n"))
        .respond(Output::fail("[ERROR] You are not currently signed in."));
    let op = op(&fake);
    let out = op.call(["item", "template", "list"]).unwrap();
    assert_eq!(out.expose(), b"raw\n");
    assert_eq!(
        args(&fake, 0),
        ["item", "template", "list", "--account", "ops.1password.com"]
    );
    assert!(matches!(op.call(["whoami"]), Err(Error::NotSignedIn(_))));
}

#[test]
fn only_listings_and_gets_include_the_archive_when_asked() {
    let fake = FakeRunner::new();
    fake.respond(Output::ok("[]"))
        .respond(Output::ok(ITEM))
        .respond(Output::ok("[]"))
        .respond(Output::ok(""))
        .respond(Output::ok("[]"));
    vault(&fake).including_archive().items(&[]).unwrap();
    let vault = vault(&fake).including_archive();
    vault.item(&ItemRef::id(ID)).unwrap();
    op(&fake).including_archive().items(&[]).unwrap();
    vault.delete_item(&ItemRef::id(ID)).unwrap();
    op(&fake).items(&[]).unwrap();
    let archived: Vec<_> = (0..5)
        .map(|call| has(&args(&fake, call), "--include-archive"))
        .collect();
    assert_eq!(archived, [true, true, true, false, false]);
}

#[test]
fn accounts_are_listed_without_an_account_and_found_by_any_identifier() {
    let fake = FakeRunner::new();
    fake.respond(Output::ok(
        r#"[{"url":"ops.1password.com","email":"a@example.com","user_uuid":"U1","account_uuid":"A1"}]"#,
    ))
    .respond(Output::ok(r#"{"id":"A1","name":"Ops","domain":"ops"}"#));
    assert_eq!(accounts(&fake).unwrap()[0].user_uuid, "U1");
    assert_eq!(find_account(&fake, "ops").unwrap().id, "A1");
    assert_eq!(args(&fake, 0), ["account", "list", "--format=json"]);
    assert_eq!(
        args(&fake, 1),
        ["account", "get", "--account", "ops", "--format=json"]
    );
}

#[test]
fn an_opened_vault_scopes_items_by_its_id() {
    let fake = FakeRunner::new();
    fake.respond(Output::ok(r#"{"id":"v1","name":"Deploy","items":3}"#))
        .respond(Output::ok("[]"));
    let vault = op(&fake).open_vault("Deploy").unwrap();
    assert_eq!(vault.info().id, "v1");
    vault.items(&["Secure Note", "Login"]).unwrap();
    let list = args(&fake, 1);
    assert!(has(&list, "--vault=v1"));
    assert!(has(&list, "--categories=Secure Note,Login"));
}

#[test]
fn a_missing_vault_is_vault_not_found() {
    let fake = FakeRunner::new();
    fake.respond(Output::fail(
        "[ERROR] \"Gone\" isn't a vault in this account.",
    ));
    assert!(matches!(
        op(&fake).open_vault("Gone"),
        Err(Error::VaultNotFound(_))
    ));
}

#[test]
fn item_exists_is_false_only_when_not_found() {
    let fake = FakeRunner::new();
    fake.respond(Output::ok(ITEM))
        .respond(Output::fail(
            "[ERROR] \"CA\" isn't an item in the \"Deploy\" vault.",
        ))
        .respond(Output::fail("[ERROR] You are not currently signed in."));
    let vault = vault(&fake);
    assert!(vault.item_exists(&ItemRef::title("CA")).unwrap());
    assert!(!vault.item_exists(&ItemRef::title("CA")).unwrap());
    assert!(matches!(
        vault.item_exists(&ItemRef::title("CA")),
        Err(Error::NotSignedIn(_))
    ));
}

#[test]
fn an_item_is_typed_and_kept_whole_on_request() {
    let json = r#"{"id":"i1","title":"CA","category":"SECURE_NOTE","vault":{"id":"v1","name":"Deploy"},
        "fields":[{"id":"x","label":"key_size","type":"STRING","value":"4096",
                   "section":{"id":"dh","label":"diffie-hellman"}}]}"#;
    let fake = FakeRunner::new();
    fake.respond(Output::ok(json)).respond(Output::ok(json));
    let vault = vault(&fake);
    let item = vault.item(&ItemRef::title("CA")).unwrap();
    assert_eq!(
        item.field("key_size")
            .unwrap()
            .section
            .as_ref()
            .unwrap()
            .label
            .as_deref(),
        Some("diffie-hellman")
    );
    assert_eq!(item.value("key_size").unwrap().expose(), "4096");
    assert_eq!(
        vault.item_json(&ItemRef::title("CA")).unwrap().expose(),
        json
    );
    assert_eq!(
        args(&fake, 0),
        [
            "item",
            "get",
            "CA",
            "--vault=v1",
            "--format=json",
            "--account",
            "ops.1password.com"
        ]
    );
}

#[test]
fn unexpected_output_is_an_error_that_quotes_nothing() {
    let fake = FakeRunner::new();
    fake.respond(Output::ok(r#"{"id":"i1","vault":"hunter2"}"#));
    let error = vault(&fake).item(&ItemRef::title("CA")).unwrap_err();
    assert!(matches!(error, Error::Unexpected { .. }));
    assert!(!format!("{error} {error:?}").contains("hunter2"));
}

#[test]
fn item_count_counts_every_category() {
    let fake = FakeRunner::new();
    fake.respond(Output::ok(
        r#"[{"id":"a","vault":{"id":"v1"}},{"id":"b","vault":{"id":"v1"}}]"#,
    ));
    assert_eq!(vault(&fake).item_count().unwrap(), 2);
    assert!(!args(&fake, 0).iter().any(|a| a.starts_with("--categories")));
}

#[test]
fn a_listed_item_carries_its_timestamps_as_op_printed_them() {
    let fake = FakeRunner::new();
    fake.respond(Output::ok(format!(
        r#"[{{"id":"{ID}","title":"CA","version":2,"vault":{{"id":"v1","name":"Deploy"}},
             "category":"SECURE_NOTE","last_edited_by":"U1",
             "created_at":"2026-10-23T01:02:03Z","updated_at":"2026-10-23T04:05:06.789Z"}}]"#
    )));
    let item = &vault(&fake).items(&[]).unwrap()[0];
    assert_eq!(item.created_at, "2026-10-23T01:02:03Z");
    assert_eq!(item.updated_at, "2026-10-23T04:05:06.789Z");
}

#[test]
fn a_created_item_sends_its_values_on_stdin_not_in_argv() {
    let fake = FakeRunner::new();
    fake.respond(Output::ok(ITEM));
    let created = vault(&fake)
        .create_item(
            "Key",
            "Secure Note",
            &[Assignment::set(
                "private_key",
                FieldType::Password,
                "-----BEGIN PRIVATE KEY-----",
            )],
        )
        .unwrap();
    assert_eq!(created.id, ID);
    let call = &fake.calls()[0];
    assert_eq!(&call.args()[..3], ["item", "create", "-"]);
    assert!(has(call.args(), "--title=Key"));
    assert!(has(call.args(), "--category=Secure Note"));
    assert!(!call.args().iter().any(|a| a.contains("PRIVATE KEY")));
    let stdin = String::from_utf8(call.stdin().unwrap().to_vec()).unwrap();
    assert!(stdin.contains("-----BEGIN PRIVATE KEY-----"));
}

#[test]
fn a_refused_create_redacts_a_value_op_echoes() {
    let fake = FakeRunner::new();
    fake.respond(Output::fail("[ERROR] item already exists: hunter2"));
    let error = vault(&fake)
        .create_item(
            "Key",
            "Secure Note",
            &[Assignment::set("pw", FieldType::Password, "hunter2")],
        )
        .unwrap_err();
    assert!(
        matches!(&error, Error::ItemConflict(m) if m == "[ERROR] item already exists: <redacted>")
    );
}

#[test]
fn a_create_cannot_delete_a_field() {
    let fake = FakeRunner::new();
    let error = vault(&fake)
        .create_item("Key", "Secure Note", &[Assignment::delete("old")])
        .unwrap_err();
    assert!(matches!(error, Error::InvalidAssignment(_)));
    assert!(fake.calls().is_empty());
}

#[test]
fn an_edit_assigns_in_argv_and_shows_no_value() {
    let fake = FakeRunner::new();
    fake.respond(Output::ok("{}"));
    vault(&fake)
        .edit_item(
            &ItemRef::title("CA"),
            &[
                Assignment::parse("certificate=-----BEGIN CERTIFICATE-----").unwrap(),
                Assignment::parse("template.default[delete]").unwrap(),
            ],
        )
        .unwrap();
    let call = &fake.calls()[0];
    assert_eq!(
        call.args()[..5],
        [
            "item",
            "edit",
            "CA",
            "--vault=v1",
            "certificate=-----BEGIN CERTIFICATE-----"
        ]
    );
    assert!(has(call.args(), "template.default[delete]"));
    let shown = format!("{call} {call:?}");
    assert!(!shown.contains("BEGIN"), "{shown}");
    assert!(shown.contains("certificate=<redacted>"));
}

#[test]
fn an_edit_makes_no_other_call() {
    let fake = FakeRunner::new();
    fake.respond(Output::ok("{}"));
    vault(&fake)
        .edit_item(&ItemRef::title("CA"), &[Assignment::untyped("x", "y")])
        .unwrap();
    assert_eq!(fake.calls().len(), 1);
}

#[test]
fn a_rename_keeps_the_title_byte_for_byte() {
    let fake = FakeRunner::new();
    fake.respond(Output::ok("{}"));
    vault(&fake)
        .rename_item(&ItemRef::title("CA_Old"), "CA ✓ \"new\"")
        .unwrap();
    assert_eq!(
        args(&fake, 0)[..5],
        [
            "item",
            "edit",
            "CA_Old",
            "--vault=v1",
            "--title=CA ✓ \"new\""
        ]
    );
}

#[test]
fn delete_archives_and_the_hard_delete_does_not() {
    let fake = FakeRunner::new();
    fake.respond(Output::ok("")).respond(Output::ok(""));
    let vault = vault(&fake);
    vault.delete_item(&ItemRef::title("Old")).unwrap();
    vault
        .delete_item_permanently(&ItemRef::title("Old"))
        .unwrap();
    assert!(has(&args(&fake, 0), "--archive"));
    assert!(!has(&args(&fake, 1), "--archive"));
}

#[test]
fn a_vault_delete_is_permanent() {
    let fake = FakeRunner::new();
    fake.respond(Output::ok(""));
    op(&fake).delete_vault_permanently("v1").unwrap();
    assert_eq!(
        args(&fake, 0),
        ["vault", "delete", "v1", "--account", "ops.1password.com"]
    );
}

#[test]
fn a_document_is_read_byte_for_byte() {
    for bytes in ODD_BYTES {
        let fake = FakeRunner::new();
        fake.respond(Output::ok(bytes));
        assert_eq!(
            vault(&fake)
                .document(&ItemRef::title("CA_Database"))
                .unwrap()
                .expose(),
            bytes
        );
    }
}

#[test]
fn a_document_is_written_byte_for_byte_from_a_file() {
    let large = vec![b'x'; 200 * 1024];
    for bytes in ODD_BYTES.into_iter().chain([large.as_slice()]) {
        let fake = FakeRunner::new();
        fake.respond(Output::ok("")).respond(Output::ok(""));
        let vault = vault(&fake);
        vault
            .create_document("CA_Database", "ca.sql", bytes)
            .unwrap();
        vault
            .edit_document(&ItemRef::title("CA_Database"), "ca.sql", bytes)
            .unwrap();
        assert_eq!(fake.files(), [bytes, bytes]);
        for call in fake.calls() {
            assert!(call.stdin().is_none());
            assert!(has(call.args(), "--file-name=ca.sql"));
        }
        assert!(has(&args(&fake, 0), "--title=CA_Database"));
        assert_eq!(args(&fake, 1)[..3], ["document", "edit", "CA_Database"]);
    }
}

#[test]
fn a_reference_is_read_byte_for_byte() {
    for bytes in ODD_BYTES {
        let fake = FakeRunner::new();
        fake.respond(Output::ok(bytes));
        assert_eq!(
            op(&fake).read("op://Deploy/CA/key").unwrap().expose(),
            bytes
        );
        assert_eq!(
            args(&fake, 0)[..3],
            ["read", "--no-newline", "op://Deploy/CA/key"]
        );
    }
}

#[test]
fn inject_feeds_the_template_and_sets_the_environment() {
    let fake = FakeRunner::new();
    fake.respond(Output::ok("remote vpn.example.com\n"));
    let filled = op(&fake)
        .inject("remote {{ op://Deploy/VPN/host }}\n", &[("CN", "alice")])
        .unwrap();
    assert_eq!(filled.expose(), "remote vpn.example.com\n");
    let call = &fake.calls()[0];
    assert_eq!(
        call.stdin(),
        Some(&b"remote {{ op://Deploy/VPN/host }}\n"[..])
    );
    assert_eq!(call.env(), [("CN".to_owned(), "alice".to_owned())]);
}

#[test]
fn a_reference_drops_the_field_type() {
    let fake = FakeRunner::new();
    let vault = vault(&fake);
    assert_eq!(vault.reference("CA", None), "op://Deploy/CA");
    assert_eq!(
        vault.reference("VPN", Some("diffie-hellman/key_size[text]")),
        "op://Deploy/VPN/diffie-hellman/key_size"
    );
}

#[test]
fn a_timeout_or_a_missing_op_is_an_error_not_an_empty_answer() {
    let fake = FakeRunner::new();
    fake.fail_to_run(io::ErrorKind::TimedOut)
        .fail_to_run(io::ErrorKind::NotFound);
    let vault = vault(&fake);
    assert!(matches!(vault.item_count(), Err(Error::TimedOut)));
    assert!(matches!(vault.item_count(), Err(Error::CliNotFound)));
}

#[test]
fn an_unscripted_call_fails_naming_the_call() {
    let fake = FakeRunner::new();
    let error = op(&fake).vaults().unwrap_err();
    assert!(matches!(error, Error::Unscripted(_)));
    assert_eq!(
        error.to_string(),
        "nothing scripted for `op vault list --format=json --account ops.1password.com`"
    );
}

#[test]
fn a_fake_shows_its_calls_and_what_is_left_but_no_file() {
    let fake = FakeRunner::new();
    fake.respond(Output::ok("")).respond(Output::ok(""));
    vault(&fake)
        .create_document("Doc", "doc.bin", b"hunter2")
        .unwrap();
    let shown = format!("{fake:?}");
    assert!(shown.contains("unanswered: 1"), "{shown}");
    assert!(shown.contains("document create"), "{shown}");
    assert!(
        !shown.contains("hunter2") && !shown.contains("104, 117"),
        "{shown}"
    );
}

#[test]
fn a_title_two_items_share_is_ambiguous_and_each_is_reachable_by_id() {
    let fake = FakeRunner::new();
    fake.respond(Output::fail(AMBIGUOUS))
        .respond(Output::fail(AMBIGUOUS))
        .respond(Output::ok(""));
    let vault = vault(&fake);
    let error = vault.item_exists(&ItemRef::title("CA")).unwrap_err();
    assert!(
        matches!(&error, Error::Ambiguous { title, ids } if title == "CA" && ids == &[ID, OTHER_ID])
    );
    assert!(matches!(
        vault.delete_item(&ItemRef::title("CA")),
        Err(Error::Ambiguous { .. })
    ));
    vault
        .delete_item_permanently(&ItemRef::id(OTHER_ID))
        .unwrap();
    assert_eq!(
        args(&fake, 2)[..4],
        ["item", "delete", OTHER_ID, "--vault=v1"]
    );
}

#[test]
fn items_titled_lists_every_duplicate() {
    let fake = FakeRunner::new();
    fake.respond(Output::ok(format!(
        r#"[{{"id":"{ID}","title":"CA","vault":{{"id":"v1"}}}},
            {{"id":"{OTHER_ID}","title":"CA","vault":{{"id":"v1"}}}},
            {{"id":"x","title":"CA_Database","vault":{{"id":"v1"}}}}]"#
    )));
    let ids: Vec<_> = vault(&fake)
        .items_titled("CA")
        .unwrap()
        .into_iter()
        .map(|i| i.id)
        .collect();
    assert_eq!(ids, [ID, OTHER_ID]);
    assert_eq!(fake.calls().len(), 1);
}

#[test]
fn an_id_never_matches_a_title() {
    let fake = FakeRunner::new();
    fake.respond(Output::ok(ITEM));
    let error = vault(&fake).item(&ItemRef::id(OTHER_ID)).unwrap_err();
    assert!(matches!(error, Error::ItemNotFound(_)));
    let error = vault(&fake).delete_item(&ItemRef::id("CA")).unwrap_err();
    assert!(matches!(error, Error::InvalidItemId(_)));
    assert_eq!(fake.calls().len(), 1);
}

#[test]
fn an_item_by_id_is_got_by_id() {
    let fake = FakeRunner::new();
    fake.respond(Output::ok(ITEM));
    let item = vault(&fake).item(&ItemRef::id(ID)).unwrap();
    assert_eq!(ItemRef::from(&item), ItemRef::id(ID));
    assert_eq!(args(&fake, 0)[..3], ["item", "get", ID]);
}
