use std::fmt;
use std::io::Write;
use std::time::Instant;

use serde::de::DeserializeOwned;
use wslib_secret::Secret;

use crate::assignment::{self, Assignment};
use crate::error::map_cli_error;
use crate::runner::{Call, Output, Runner};
use crate::types::{
    Account, AccountInfo, Item, ItemRef, ItemSummary, SecretBytes, User, VaultInfo, WhoAmI,
};
use crate::{Error, ShellRunner};

/// The accounts `op` is set up for. Works signed out, and carries no `--account`.
pub fn accounts(runner: &impl Runner) -> Result<Vec<AccountInfo>, Error> {
    json(runner, Call::of(["account", "list", "--format=json"]))
}

/// The one account `identifier` names (a shorthand, sign-in address, or user or
/// account UUID), as `op` resolves it; an error when it names none, or several.
pub fn find_account(runner: &impl Runner, identifier: &str) -> Result<Account, Error> {
    let call = Call::of(["account", "get", "--account"])
        .arg(identifier)
        .arg("--format=json");
    json(runner, call)
}

/// A client for one account, which every call names with `--account`.
#[derive(Clone)]
pub struct Op<R = ShellRunner> {
    runner: R,
    account: Option<String>,
}

impl<R> fmt::Debug for Op<R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Op")
            .field("account", &self.account)
            .finish_non_exhaustive()
    }
}

impl<R: Runner> Op<R> {
    /// A client for `account`: a shorthand, sign-in address or UUID. It runs nothing yet.
    pub fn new(runner: R, account: impl Into<String>) -> Self {
        Self {
            runner,
            account: Some(account.into()),
        }
    }

    /// A client whose calls carry no `--account`, so `op` picks one: with several
    /// signed in it may prompt for one that is locked, or refuse.
    pub fn unscoped(runner: R) -> Self {
        Self {
            runner,
            account: None,
        }
    }

    /// The account every call names; `None` for [`Op::unscoped`].
    pub fn account(&self) -> Option<&str> {
        self.account.as_deref()
    }

    /// The runner calls go through.
    pub fn runner(&self) -> &R {
        &self.runner
    }

    /// `op whoami`, and when that fails `op signin` (which can ask for Touch ID
    /// or the desktop app's approval) then `op whoami` once more.
    pub fn sign_in(&self) -> Result<WhoAmI, Error> {
        match self.whoami() {
            Err(Error::NotSignedIn(_) | Error::Cli { .. }) => {}
            answer => return answer,
        }
        self.checked(Call::of(["signin"]), &[])?;
        self.whoami()
    }

    /// Who `op` is signed in as.
    pub fn whoami(&self) -> Result<WhoAmI, Error> {
        self.json(Call::of(["whoami", "--format=json"]))
    }

    /// The signed-in user's name and email.
    pub fn current_user(&self) -> Result<User, Error> {
        self.json(Call::of(["user", "get", "--me", "--format=json"]))
    }

    /// Every vault the account can see.
    pub fn vaults(&self) -> Result<Vec<VaultInfo>, Error> {
        self.json(Call::of(["vault", "list", "--format=json"]))
    }

    /// Creates a vault. `op` allows two vaults one name, so check
    /// [`VaultInfo::is_named`] against [`Op::vaults`] first if that matters.
    pub fn create_vault(&self, name: &str) -> Result<VaultInfo, Error> {
        self.json(Call::of(["vault", "create"]).arg(name).arg("--format=json"))
    }

    /// Deletes a vault and everything in it: `op` has no vault archive.
    pub fn delete_vault_permanently(&self, vault: &str) -> Result<(), Error> {
        self.checked(Call::of(["vault", "delete"]).arg(vault), &[])
            .map(drop)
    }

    /// The vault `name` (or id), looked up with one `op vault get`.
    pub fn open_vault(&self, name: &str) -> Result<Vault<R>, Error>
    where
        R: Clone,
    {
        let info = self.json(Call::of(["vault", "get"]).arg(name).arg("--format=json"))?;
        Ok(self.vault(info))
    }

    /// The vault `info` describes, without asking `op`.
    pub fn vault(&self, info: VaultInfo) -> Vault<R>
    where
        R: Clone,
    {
        Vault {
            op: self.clone(),
            info,
        }
    }

    /// Items in every vault, of these `--categories` names (`Secure Note`,
    /// `API Credential`); all of them when `categories` is empty.
    pub fn items(&self, categories: &[&str]) -> Result<Vec<ItemSummary>, Error> {
        self.list_items(None, categories)
    }

    /// The item, in whichever vault holds it.
    pub fn item(&self, item: &ItemRef) -> Result<Item, Error> {
        self.get_item(None, item)
    }

    /// The value an `op://vault/item/field` reference names, byte for byte.
    pub fn read(&self, reference: &str) -> Result<SecretBytes, Error> {
        let out = self.checked(Call::of(["read", "--no-newline"]).arg(reference), &[])?;
        Ok(SecretBytes::new(out.stdout))
    }

    /// `template` with its references filled by `op inject`; `env` is set for `op`
    /// to expand `$VAR`s from.
    pub fn inject(&self, template: &str, env: &[(&str, &str)]) -> Result<Secret, Error> {
        let mut call = Call::of(["inject"]);
        call.stdin = Some(template.as_bytes().to_vec());
        call.env = env
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        let out = self.checked(call, &[])?;
        SecretBytes::new(out.stdout).into_text()
    }

    fn list_items(
        &self,
        vault: Option<&str>,
        categories: &[&str],
    ) -> Result<Vec<ItemSummary>, Error> {
        let mut call = Call::of(["item", "list"]);
        if let Some(vault) = vault {
            call = call.arg(format!("--vault={vault}"));
        }
        if !categories.is_empty() {
            call = call.arg(format!("--categories={}", categories.join(",")));
        }
        self.json(call.arg("--format=json"))
    }

    fn get_item_json(&self, vault: Option<&str>, item: &ItemRef) -> Result<Output, Error> {
        let mut call = Call::of(["item", "get"]).arg(item.arg()?);
        if let Some(vault) = vault {
            call = call.arg(format!("--vault={vault}"));
        }
        let out = self.checked(call.arg("--format=json"), &[])?;
        if let ItemRef::Id(id) = item {
            #[derive(serde::Deserialize)]
            struct Found {
                id: String,
            }
            if parse::<Found>(&out.stdout, "item get")?.id != *id {
                return Err(Error::ItemNotFound(format!("no item has the id {id}")));
            }
        }
        Ok(out)
    }

    fn get_item(&self, vault: Option<&str>, item: &ItemRef) -> Result<Item, Error> {
        let out = self.get_item_json(vault, item)?;
        parse(&out.stdout, "item get")
    }

    fn json<T: DeserializeOwned>(&self, call: Call) -> Result<T, Error> {
        json(&self.runner, self.scoped(call))
    }

    fn checked(&self, call: Call, secrets: &[&str]) -> Result<Output, Error> {
        checked(&self.runner, self.scoped(call), secrets)
    }

    fn scoped(&self, call: Call) -> Call {
        match &self.account {
            Some(account) => call.arg("--account").arg(account),
            None => call,
        }
    }
}

/// One vault of an [`Op`]'s account; every item call names it with `--vault=<id>`.
#[derive(Clone, Debug)]
pub struct Vault<R = ShellRunner> {
    op: Op<R>,
    info: VaultInfo,
}

impl<R: Runner> Vault<R> {
    /// The vault's id and name.
    pub fn info(&self) -> &VaultInfo {
        &self.info
    }

    /// The account's client.
    pub fn op(&self) -> &Op<R> {
        &self.op
    }

    /// Whether `item` is here: one `op item get`, `false` only for
    /// [`Error::ItemNotFound`]; a title two items share is [`Error::Ambiguous`].
    pub fn item_exists(&self, item: &ItemRef) -> Result<bool, Error> {
        match self.item(item) {
            Ok(_) => Ok(true),
            Err(Error::ItemNotFound(_)) => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// The item, with its fields.
    pub fn item(&self, item: &ItemRef) -> Result<Item, Error> {
        self.op.get_item(Some(self.id()), item)
    }

    /// The item as `op item get --format=json` prints it, for keeping whole.
    pub fn item_json(&self, item: &ItemRef) -> Result<Secret, Error> {
        let out = self.op.get_item_json(Some(self.id()), item)?;
        SecretBytes::new(out.stdout).into_text()
    }

    /// Items here, of these `--categories` names; all of them when `categories` is empty.
    pub fn items(&self, categories: &[&str]) -> Result<Vec<ItemSummary>, Error> {
        self.op.list_items(Some(self.id()), categories)
    }

    /// Every item titled exactly `title`, from one `op item list`: more than one
    /// when creates made duplicates, each addressable by [`ItemRef::Id`].
    pub fn items_titled(&self, title: &str) -> Result<Vec<ItemSummary>, Error> {
        let mut items = self.items(&[])?;
        items.retain(|item| item.title == title);
        Ok(items)
    }

    /// How many items the vault holds, of any category.
    pub fn item_count(&self) -> Result<usize, Error> {
        self.items(&[]).map(|items| items.len())
    }

    /// Creates an item of `category` (`Secure Note`, …), its fields sent as a
    /// JSON template on stdin so no value is in `op`'s argv.
    ///
    /// `op` never refuses a title in use: a second create makes a second item
    /// of the same title, and that title then addresses neither.
    pub fn create_item(
        &self,
        title: &str,
        category: &str,
        fields: &[Assignment],
    ) -> Result<ItemSummary, Error> {
        let mut call = self
            .vault_call(["item", "create", "-"])
            .arg(format!("--title={title}"))
            .arg(format!("--category={category}"))
            .arg("--format=json");
        call.stdin = Some(assignment::template(fields)?);
        let out = self.op.checked(call, &values(fields))?;
        parse(&out.stdout, "item create")
    }

    /// Sets and deletes fields of the item, leaving the rest.
    ///
    /// The values go in `op`'s argv, where other local processes can see them,
    /// since `op item edit` takes a template only as the whole item.
    pub fn edit_item(&self, item: &ItemRef, fields: &[Assignment]) -> Result<(), Error> {
        let call = fields
            .iter()
            .fold(self.item_call(["item", "edit"], item)?, |call, a| {
                call.secret_arg(a.token(), a.shown())
            });
        self.op.checked(call, &values(fields)).map(drop)
    }

    /// Retitles the item.
    pub fn rename_item(&self, item: &ItemRef, to: &str) -> Result<(), Error> {
        let call = self
            .item_call(["item", "edit"], item)?
            .arg(format!("--title={to}"));
        self.op.checked(call, &[]).map(drop)
    }

    /// Moves the item to the Archive, from which it can be restored.
    pub fn delete_item(&self, item: &ItemRef) -> Result<(), Error> {
        let call = self.item_call(["item", "delete"], item)?.arg("--archive");
        self.op.checked(call, &[]).map(drop)
    }

    /// Deletes the item for good.
    pub fn delete_item_permanently(&self, item: &ItemRef) -> Result<(), Error> {
        let call = self.item_call(["item", "delete"], item)?;
        self.op.checked(call, &[]).map(drop)
    }

    /// The document's file, byte for byte.
    pub fn document(&self, item: &ItemRef) -> Result<SecretBytes, Error> {
        let out = self
            .op
            .checked(self.item_call(["document", "get"], item)?, &[])?;
        Ok(SecretBytes::new(out.stdout))
    }

    /// Creates a document holding `content` as `file_name`; like
    /// [`Vault::create_item`], it never refuses a title in use.
    pub fn create_document(
        &self,
        title: &str,
        file_name: &str,
        content: &[u8],
    ) -> Result<(), Error> {
        let call = self
            .vault_call(["document", "create"])
            .arg(format!("--title={title}"));
        self.store_document(call, file_name, content)
    }

    /// Replaces the document's file with `content`, as `file_name`.
    pub fn edit_document(
        &self,
        item: &ItemRef,
        file_name: &str,
        content: &[u8],
    ) -> Result<(), Error> {
        self.store_document(
            self.item_call(["document", "edit"], item)?,
            file_name,
            content,
        )
    }

    /// The `op://` reference to `item` (a title or id), or to its `field`
    /// (`section.label`); any `[type]` suffix is dropped, as `op` refuses one.
    pub fn reference(&self, item: &str, field: Option<&str>) -> String {
        match field {
            Some(field) => {
                let field = field.split_once('[').map_or(field, |(field, _)| field);
                format!("op://{}/{item}/{field}", self.info.name)
            }
            None => format!("op://{}/{item}", self.info.name),
        }
    }

    // A file, not stdin: piped without a `-`, op kept only the first 64 KiB.
    fn store_document(&self, call: Call, file_name: &str, content: &[u8]) -> Result<(), Error> {
        let mut file = tempfile::NamedTempFile::new()?;
        file.write_all(content)?;
        file.flush()?;
        let call = call
            .arg(file.path().to_string_lossy())
            .arg(format!("--file-name={file_name}"));
        self.op.checked(call, &[]).map(drop)
    }

    fn vault_call<const N: usize>(&self, args: [&str; N]) -> Call {
        Call::of(args).arg(format!("--vault={}", self.id()))
    }

    fn item_call(&self, verb: [&str; 2], item: &ItemRef) -> Result<Call, Error> {
        let call = Call::of(verb).arg(item.arg()?);
        Ok(call.arg(format!("--vault={}", self.id())))
    }

    fn id(&self) -> &str {
        &self.info.id
    }
}

fn values(fields: &[Assignment]) -> Vec<&str> {
    fields.iter().filter_map(Assignment::value).collect()
}

fn checked(runner: &impl Runner, call: Call, secrets: &[&str]) -> Result<Output, Error> {
    let start = Instant::now();
    let out = runner.run(&call);
    let elapsed = start.elapsed();
    match &out {
        Ok(out) => tracing::debug!(command = %call, code = ?out.code, ?elapsed, "op"),
        Err(e) => tracing::debug!(command = %call, error = %e, ?elapsed, "op"),
    }
    let mut out = out?;
    if out.success() {
        return Ok(out);
    }
    if !secrets.is_empty() {
        out.stdout.clear();
        for secret in secrets.iter().filter(|s| !s.is_empty()) {
            out.stderr = out.stderr.replace(secret, "<redacted>");
        }
    }
    Err(map_cli_error(&out))
}

fn json<T: DeserializeOwned>(runner: &impl Runner, call: Call) -> Result<T, Error> {
    let command = call
        .args()
        .iter()
        .take(2)
        .cloned()
        .collect::<Vec<_>>()
        .join(" ");
    let out = checked(runner, call, &[])?;
    parse(&out.stdout, &command)
}

fn parse<T: DeserializeOwned>(stdout: &[u8], command: &str) -> Result<T, Error> {
    serde_json::from_slice(stdout).map_err(|e| Error::Unexpected {
        command: command.to_owned(),
        line: e.line(),
        column: e.column(),
    })
}
