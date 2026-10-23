# wslib-cli

The conventions a Wired Square command line shares, so each tool doesn't
restate them.

```rust
use wslib_cli::{Exit, Output, config::Discovery, exit};

fn main() -> ExitCode {
    let cli = Cli::parse();
    let output = Output::from(cli.output);
    match run(&cli, output) {
        Ok(()) => Exit::SUCCESS.into(),
        Err(error) => exit::fail(output, &*error, Exit::of(&*error, |_| None)),
    }
}

fn run(cli: &Cli, output: Output) -> anyhow::Result<()> {
    let config: Settings = Discovery::new("bench-tool").load(cli.config.as_deref())?;
    let boards = fetch_boards(&config)?;
    println!("{}", output.rows(&boards, &[("NAME", "name"), ("BOARD", "board")])?);
    Ok(())
}
```

## What's here

- **`Output`**: `--json` prints pretty JSON; without it, rows are a
  comfy-table and a single value is whatever the caller renders.
  `OutputArgs` (feature `clap`) is the global flag, to `#[command(flatten)]`.
- **`Exit`**: 0 success, 1 failure, 2 usage, 3–123 the tool's own, 124 gave up
  waiting, 130 interrupted. `Exit::of` finds the code in an error's source
  chain; `exit::fail` prints the error, as `{"error", "exit"}` JSON in JSON
  mode.
- **`config::Discovery`**: the config file is `--config`, else
  `<PREFIX>_CONFIG`, else `<app>/config.toml` under `$XDG_CONFIG_HOME` or
  `~/.config`, macOS included. `var("URL")` reads `<PREFIX>_URL`, and a flag
  beats it, which beats the file. `read` hands back the text in any format;
  `load` (feature `toml`) parses TOML.

`op://` references moved to `wslib-1password` in 0.2.0: `resolve` and
`ReadReference` are there, and `Op` reads with `op read`.
