//! `mezha`: a boundary, not a matcher.

mod approve;

use std::io::{IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::LazyLock;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use mezha_render::{Action, Mode, Plan};
use mezha_spec::{SPEC_FILE, Spec};

static VERSION: LazyLock<String> = LazyLock::new(|| {
    format!(
        "{} (hook protocol {})",
        env!("CARGO_PKG_VERSION"),
        mezha_hooks::PROTOCOL
    )
});

#[derive(Parser)]
#[command(
    name = "mezha",
    version = VERSION.as_str(),
    about = "A boundary, not a matcher: governance for Claude Code projects.",
    after_help = "Start with `mezha init`, edit mezha.toml, then `mezha compile`."
)]
struct Cli {
    /// Project root (where mezha.toml lives).
    #[arg(short = 'p', long, global = true, default_value = ".")]
    path: PathBuf,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Create mezha.toml in the project root.
    Init,
    /// Render mezha.toml into .claude/. Stops without writing if a generated
    /// file was written or edited by someone else.
    Compile,
    /// Show what `compile` or `apply` would change.
    Diff,
    /// Like `compile`, but back up conflicting files and overwrite them.
    Apply {
        /// Don't ask for confirmation.
        #[arg(long)]
        yes: bool,
    },
    /// Approve gated commands (such as `git push`) for a while. Run it
    /// yourself, in your own terminal: it refuses to run inside Claude Code.
    Approve {
        /// How long the approval lasts.
        #[arg(long, default_value_t = 30, value_parser = clap::value_parser!(u32).range(1..=1440))]
        minutes: u32,
        /// Show the current approval instead.
        #[arg(long, conflicts_with_all = ["revoke", "minutes"])]
        status: bool,
        /// End the current approval now.
        #[arg(long, conflicts_with = "minutes")]
        revoke: bool,
    },
    /// Check that the boundary holds: the sandbox is in effect, an agent
    /// can't push, and nothing switched the gate off. Exit 0 = pass (maybe
    /// with warnings), 1 = a check failed, 2 = verify couldn't run.
    Verify {
        /// Print the report as JSON.
        #[arg(long)]
        json: bool,
        /// Look only at committed project files (for CI).
        #[arg(long)]
        project_only: bool,
        /// Also run side-effect-free probes inside Anthropic's sandbox
        /// runtime (srt 0.0.79 or later, macOS and Linux).
        #[arg(long, conflicts_with = "project_only")]
        probe: bool,
        /// Look from inside Claude Code's sandbox. Ask Claude to run it
        /// with its Bash tool; read its output in the tool result.
        #[arg(long, conflicts_with_all = ["project_only", "probe"])]
        inside: bool,
    },
    /// Run a hook (Claude Code calls this; see .claude/settings.json).
    #[command(hide = true)]
    Hook {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match &cli.command {
        Command::Hook { args } => return hook(args),
        Command::Verify {
            json,
            project_only,
            probe,
            inside,
        } => {
            let opts = mezha_verify::Options {
                project_only: *project_only,
                probe: *probe,
                inside: *inside,
            };
            return verify(&cli.path, *json, &opts);
        }
        _ => {}
    }
    match run(cli) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::FAILURE
        }
    }
}

/// Hooks answer only 0 or 2; an unreadable stdin blocks.
fn hook(args: &[String]) -> ExitCode {
    let mut input = Vec::new();
    let limit = mezha_hooks::MAX_INPUT as u64 + 1;
    let outcome = match std::io::stdin().take(limit).read_to_end(&mut input) {
        Ok(_) => mezha_hooks::run(args, &input, &mezha_hooks::Env::from_process()),
        Err(e) => mezha_hooks::Outcome::block(format!("mezha: can't read hook input: {e}")),
    };
    eprint!("{}", outcome.stderr);
    ExitCode::from(outcome.code as u8)
}

/// verify keeps its own exit codes: 0 pass, 1 a check failed, 2 couldn't run.
fn verify(root: &Path, json: bool, opts: &mezha_verify::Options) -> ExitCode {
    let root = std::fs::canonicalize(root).unwrap_or_else(|_| root.to_path_buf());
    let ctx = mezha_verify::Ctx::from_process(&root);
    match mezha_verify::verify(&ctx, opts) {
        Ok(report) => {
            if json {
                print!("{}", report.to_json());
            } else {
                print!("{}", report.to_human(&root.display().to_string()));
            }
            ExitCode::from(report.exit_code() as u8)
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(2)
        }
    }
}

fn run(cli: Cli) -> Result<ExitCode> {
    let root = cli.path;
    match cli.command {
        Command::Init => init(&root),
        Command::Compile => compile(&root, Mode::Compile, false),
        Command::Apply { yes } => compile(&root, Mode::Apply, yes),
        Command::Diff => diff(&root),
        Command::Approve {
            minutes,
            status,
            revoke,
        } => approve::run(&root, minutes, status, revoke),
        Command::Hook { .. } | Command::Verify { .. } => unreachable!("handled in main"),
    }
}

fn init(root: &Path) -> Result<ExitCode> {
    let path = root.join(SPEC_FILE);
    if path.exists() {
        bail!("{} already exists; edit it instead", path.display());
    }
    let dir = std::fs::canonicalize(root).with_context(|| root.display().to_string())?;
    let name = dir
        .file_name()
        .map(|n| project_name(&n.to_string_lossy()))
        .filter(|n| !n.is_empty())
        .unwrap_or_else(|| "project".to_string());
    let os_mode = if cfg!(windows) {
        "native-windows"
    } else {
        "full"
    };
    let text = include_str!("init_template.toml")
        .replace("{{name}}", &name)
        .replace("{{os_mode}}", os_mode);
    std::fs::write(&path, text).with_context(|| path.display().to_string())?;
    println!(
        "Created {}. Edit it, then run `mezha compile`.",
        path.display()
    );
    if cfg!(windows) {
        println!(
            "Native Windows has no sandbox, so gates are advisory; use WSL2 and os_mode = \"full\"."
        );
    }
    Ok(ExitCode::SUCCESS)
}

/// A directory name as a project name: lowercase, `-` for anything else.
fn project_name(dir: &str) -> String {
    let mapped: String = dir
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect();
    mapped.trim_matches('-').to_string()
}

/// Loads and validates the spec, printing every diagnostic. `None` means
/// the spec has errors.
fn load(root: &Path) -> Result<Option<(Spec, String)>> {
    let path = root.join(SPEC_FILE);
    let text = std::fs::read_to_string(&path)
        .with_context(|| format!("{} (run `mezha init` first?)", path.display()))?;
    let spec = mezha_spec::parse(&text)?;
    let diagnostics = mezha_spec::validate(&spec);
    for d in diagnostics.warnings().chain(diagnostics.errors()) {
        eprintln!("{d}");
    }
    if diagnostics.has_errors() {
        eprintln!("{SPEC_FILE} has errors; nothing was written.");
        return Ok(None);
    }
    Ok(Some((spec, text)))
}

fn prepare(root: &Path) -> Result<Option<Plan>> {
    let Some((spec, text)) = load(root)? else {
        return Ok(None);
    };
    let rendered = mezha_render::render(&spec, &text, root)?;
    for warning in &rendered.warnings {
        eprintln!("warning: {warning}");
    }
    if !rendered.problems.is_empty() {
        for problem in &rendered.problems {
            eprintln!("error: {problem}");
        }
        eprintln!("nothing was written.");
        return Ok(None);
    }
    let plan = mezha_render::plan(root, &rendered)?;
    for note in &plan.notes {
        eprintln!("note: {note}");
    }
    Ok(Some(plan))
}

fn print_plan(plan: &Plan) {
    for change in &plan.changes {
        let line = match &change.action {
            Action::Unchanged => format!("  unchanged  {}", change.path),
            Action::Create => format!("  create     {}", change.path),
            Action::Update => format!("  update     {}", change.path),
            Action::Remove => format!("  remove     {}", change.path),
            Action::Conflict(why) => format!("  CONFLICT   {} ({why})", change.path),
            Action::KeepRemoved(why) => format!("  keep       {} ({why})", change.path),
        };
        println!("{line}");
    }
}

fn compile(root: &Path, mode: Mode, yes: bool) -> Result<ExitCode> {
    let Some(plan) = prepare(root)? else {
        return Ok(ExitCode::FAILURE);
    };
    print_plan(&plan);
    if plan.is_noop() {
        println!("Everything is up to date.");
        return Ok(ExitCode::SUCCESS);
    }
    let conflicts = plan.conflicts().count();
    if conflicts > 0 {
        if mode == Mode::Compile {
            eprintln!(
                "{conflicts} file(s) were written or edited by someone else, so nothing was \
                 written. See `mezha diff`; `mezha apply` backs them up and overwrites them."
            );
            return Ok(ExitCode::FAILURE);
        }
        if !yes && !confirm(&format!("Back up and overwrite {conflicts} file(s)?"))? {
            eprintln!("Nothing was written.");
            return Ok(ExitCode::FAILURE);
        }
    }
    let report = mezha_render::write(root, &plan, mode, &mezha_render::utc_stamp(now()))?;
    if let Some(dir) = &report.backup {
        println!(
            "Backed up the replaced files to {}. Add `{}/` to .gitignore if it isn't there.",
            dir.display(),
            mezha_render::BACKUP_DIR
        );
    }
    println!(
        "Wrote {} file(s), removed {}.",
        report.written.len(),
        report.removed.len()
    );
    Ok(ExitCode::SUCCESS)
}

fn diff(root: &Path) -> Result<ExitCode> {
    let Some(plan) = prepare(root)? else {
        return Ok(ExitCode::FAILURE);
    };
    print_plan(&plan);
    for change in &plan.changes {
        if !matches!(change.action, Action::Unchanged | Action::KeepRemoved(_)) {
            print!("{}", mezha_render::unified_diff(change));
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn confirm(question: &str) -> Result<bool> {
    if !std::io::stdin().is_terminal() {
        bail!("{question} Needs a terminal to ask; pass --yes to proceed without asking.");
    }
    print!("{question} [y/N] ");
    std::io::stdout().flush()?;
    let mut answer = String::new();
    std::io::stdin().read_line(&mut answer)?;
    Ok(matches!(answer.trim(), "y" | "Y" | "yes"))
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

#[cfg(test)]
mod tests {
    use super::project_name;

    #[test]
    fn project_names_from_directories() {
        assert_eq!(project_name("Client X"), "client-x");
        assert_eq!(project_name("my_repo.git"), "my-repo-git");
        assert_eq!(project_name("--"), "");
    }
}
