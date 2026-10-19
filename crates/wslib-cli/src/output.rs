use comfy_table::{Table, presets};
use serde::Serialize;
use serde_json::Value;

/// Whether a command prints for a person or for a program.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Output {
    /// Tables and prose.
    #[default]
    Human,
    /// Pretty-printed JSON.
    Json,
}

impl Output {
    /// The mode a `--json` flag asks for.
    pub fn from_json_flag(json: bool) -> Self {
        if json { Self::Json } else { Self::Human }
    }

    /// `rows` as JSON, or as a table of `columns`, each a `(header, field)`;
    /// no columns means every field, in the order they first appear.
    pub fn rows<T: Serialize>(
        self,
        rows: &[T],
        columns: &[(&str, &str)],
    ) -> serde_json::Result<String> {
        match self {
            Self::Json => serde_json::to_string_pretty(rows),
            Self::Human => {
                let rows = rows
                    .iter()
                    .map(serde_json::to_value)
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(if rows.is_empty() {
                    "(no rows)".to_owned()
                } else {
                    table(&rows, columns).to_string()
                })
            }
        }
    }

    /// `value` as JSON, or as `human` renders it.
    pub fn value<T: Serialize>(
        self,
        value: &T,
        human: impl FnOnce(&T) -> String,
    ) -> serde_json::Result<String> {
        match self {
            Self::Json => serde_json::to_string_pretty(value),
            Self::Human => Ok(human(value)),
        }
    }
}

/// The global `--json` flag, to `#[command(flatten)]` into a parser.
#[cfg(feature = "clap")]
#[derive(clap::Args, Clone, Copy, Debug, Default)]
pub struct OutputArgs {
    /// Print JSON instead of tables.
    #[arg(long, global = true)]
    pub json: bool,
}

#[cfg(feature = "clap")]
impl From<OutputArgs> for Output {
    fn from(args: OutputArgs) -> Self {
        Self::from_json_flag(args.json)
    }
}

/// An empty table in the house style, for rows that aren't serialisable.
pub fn new_table() -> Table {
    let mut table = Table::new();
    table.load_style(presets::UTF8_FULL_CONDENSED);
    table
}

/// A table of `columns` over JSON rows, as [`Output::rows`] draws it.
pub fn table(rows: &[Value], columns: &[(&str, &str)]) -> Table {
    let all_fields;
    let columns = if columns.is_empty() {
        all_fields = field_names(rows);
        &all_fields
    } else {
        columns
    };
    let mut table = new_table();
    table.set_header(columns.iter().map(|(header, _)| *header));
    for row in rows {
        table.add_row(
            columns
                .iter()
                .map(|(_, field)| row.get(field).map(cell).unwrap_or_default()),
        );
    }
    table
}

fn field_names(rows: &[Value]) -> Vec<(&str, &str)> {
    let mut names: Vec<(&str, &str)> = Vec::new();
    for key in rows
        .iter()
        .filter_map(Value::as_object)
        .flat_map(|row| row.keys())
    {
        if !names.iter().any(|(name, _)| name == key) {
            names.push((key, key));
        }
    }
    names
}

fn cell(value: &Value) -> String {
    match value {
        Value::Null => "—".to_owned(),
        Value::String(s) => s.clone(),
        Value::Array(items) if items.iter().all(Value::is_string) => items
            .iter()
            .filter_map(Value::as_str)
            .collect::<Vec<_>>()
            .join(","),
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn boards() -> Vec<Value> {
        vec![
            json!({ "name": "dev-mac", "targets": ["os", "wfl"], "board": null }),
            json!({ "name": "rack-2", "targets": [], "board": "r7", "slots": 4 }),
        ]
    }

    #[test]
    fn json_is_the_rows_serialised() {
        let out = Output::Json.rows(&boards(), &[("name", "name")]).unwrap();
        assert_eq!(
            serde_json::from_str::<Value>(&out).unwrap(),
            json!(boards())
        );
    }

    #[test]
    fn a_table_keeps_the_given_columns_in_order() {
        let out = Output::Human
            .rows(
                &boards(),
                &[("NAME", "name"), ("TARGETS", "targets"), ("BOARD", "board")],
            )
            .unwrap();
        assert_eq!(
            out,
            "\
┌─────────┬─────────┬───────┐
│ NAME    ┆ TARGETS ┆ BOARD │
╞═════════╪═════════╪═══════╡
│ dev-mac ┆ os,wfl  ┆ —     │
│ rack-2  ┆         ┆ r7    │
└─────────┴─────────┴───────┘"
        );
    }

    #[test]
    fn no_columns_means_every_field_of_every_row() {
        let headers: Vec<String> = table(&boards(), &[])
            .header()
            .unwrap()
            .cell_iter()
            .map(|c| c.content())
            .collect();
        assert_eq!(headers, ["board", "name", "targets", "slots"]);
    }

    #[test]
    fn no_rows_says_so_for_a_person_and_is_an_empty_array_for_a_program() {
        let none: [Value; 0] = [];
        assert_eq!(Output::Human.rows(&none, &[]).unwrap(), "(no rows)");
        assert_eq!(Output::Json.rows(&none, &[]).unwrap(), "[]");
    }

    #[test]
    fn a_single_value_is_rendered_by_the_caller_for_a_person() {
        let version = json!({ "version": "1.2.3" });
        let human = |v: &Value| format!("v{}", v["version"].as_str().unwrap());
        assert_eq!(Output::Human.value(&version, human).unwrap(), "v1.2.3");
        assert_eq!(
            Output::Json.value(&version, human).unwrap(),
            "{\n  \"version\": \"1.2.3\"\n}"
        );
    }

    #[cfg(feature = "clap")]
    #[test]
    fn the_json_flag_is_global() {
        use clap::Parser;

        #[derive(Parser)]
        struct Cli {
            #[command(flatten)]
            output: OutputArgs,
            #[command(subcommand)]
            command: Command,
        }
        #[derive(clap::Subcommand)]
        enum Command {
            List,
        }

        let cli = Cli::try_parse_from(["tool", "list", "--json"]).unwrap();
        assert_eq!(Output::from(cli.output), Output::Json);
        let cli = Cli::try_parse_from(["tool", "list"]).unwrap();
        assert_eq!(Output::from(cli.output), Output::Human);
    }
}
