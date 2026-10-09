//! `mezha metrics --ab tasks.toml`: each task runs as its agent with the
//! project's agent memory and with that memory emptied, in identical
//! worktrees, and a sandboxed check says which runs passed. It spends real
//! money, so it says how much at most and asks first.

use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use mezha_memory::claude::{self, ENV_REMOVE, MIN_CLAUDE_CODE};
use mezha_memory::review;
use mezha_memory::scan::escape;
use mezha_metrics::ab::{self, AbRow, Task, TaskFile, Variant};
use mezha_metrics::store::{self, Store};
use mezha_spec::{Scope, Spec};
use mezha_verify::Ctx;
use mezha_verify::runner::{self, Next, Run};
use mezha_verify::scratch::{Scratch, nonce};
use serde_json::Value;

use crate::files::{create_private_dir, shell_word};
use crate::git::{Git, resolve_base};
use crate::metrics::Options;

/// A run's diff kept for the report, at most.
const MAX_DIFF: usize = 64 * 1024;
/// Keeps sessions from writing auto memory, which all worktrees share.
/// Turning auto memory off instead would turn agent memory off too.
const NO_AUTO_MEMORY_WRITES: &str = r#"{"permissions":{"deny":["Edit(~/.claude/projects/**)"]}}"#;
/// Commits that make both variants look the same to the model.
const PREPARE: &str = "ab: prepare run";
const IDENTITY: [&str; 4] = ["-c", "user.name=mezha", "-c", "user.email=mezha@localhost"];

/// What the runs share.
struct Setup<'a> {
    ctx: &'a Ctx,
    layers: &'a mezha_verify::layers::Layers,
    spec: &'a Spec,
    root: &'a Path,
    git: &'a Git<'a>,
    claude: &'a Path,
    srt: Option<mezha_verify::probe::srt::Srt>,
    file: &'a TaskFile,
    base: String,
    prefix: String,
    scratch: Scratch,
    report: PathBuf,
    stamp: String,
}

pub fn run(root: &Path, tasks_path: &Path, opts: &Options) -> Result<ExitCode> {
    if crate::approve::inside_claude_code(&|k: &str| std::env::var(k).ok()) {
        bail!(
            "mezha metrics --ab refuses to run inside Claude Code: it starts Claude Code sessions and spends money. Run it in your own terminal."
        );
    }
    if cfg!(windows) {
        bail!("the A/B runner runs on macOS, Linux and WSL2");
    }
    let root = std::fs::canonicalize(root).with_context(|| root.display().to_string())?;
    let Some((spec, _)) = super::load(&root)? else {
        return Ok(ExitCode::FAILURE);
    };
    let text =
        std::fs::read_to_string(tasks_path).with_context(|| tasks_path.display().to_string())?;
    let file = ab::parse(&text).map_err(|e| anyhow::anyhow!("{}: {e}", tasks_path.display()))?;
    let errors = ab::validate(&file, &spec);
    if !errors.is_empty() {
        for e in &errors {
            eprintln!("error: {}: {e}", tasks_path.display());
        }
        return Ok(ExitCode::FAILURE);
    }
    let repeat = opts.repeat.max(1);

    let mut ctx = Ctx::from_process(&root);
    let layers = mezha_verify::layers::Layers::load(&ctx, false);
    ctx.agent_writable = layers.agent_writable(&ctx);
    let git = Git::new(&ctx)?;
    let claude = ctx
        .which_trusted("claude")
        .path
        .context("claude is not on PATH (or only in a directory an agent could write)")?;
    let version = claude_version(&ctx, &claude)?;
    if ctx.which_trusted("mezha").path.is_none() {
        bail!(
            "mezha isn't on PATH where agents can't write; the project's hooks call it and block every tool call without it"
        );
    }
    let checks: Vec<&Task> = file.task.iter().filter(|t| t.check.is_some()).collect();
    let srt = if checks.is_empty() || opts.unsandboxed_check {
        None
    } else {
        Some(mezha_verify::probe::srt::find(&ctx).map_err(|e| {
            anyhow::anyhow!("{e}\nChecks run code the agent just wrote, so they run in srt. Install it, or pass --unsandboxed-check to run them unsandboxed in your own process.")
        })?)
    };

    // What it will do and cost, before anything runs.
    let runs = file.task.len() as u32 * 2 * repeat;
    let ceiling = f64::from(runs) * file.ab.budget_usd();
    println!(
        "{} task(s) × 2 variants × {repeat} repeat(s) = {runs} Claude Code session(s), up to ${:.2} each: at most ${ceiling:.2}.",
        file.task.len(),
        file.ab.budget_usd()
    );
    for task in &checks {
        println!(
            "  check for {}{}: {}",
            task.name,
            if opts.unsandboxed_check {
                " (UNSANDBOXED)"
            } else {
                " (in srt)"
            },
            escape(task.check.as_deref().unwrap_or(""))
        );
    }
    if !opts.yes {
        if !std::io::stdin().is_terminal() {
            bail!(
                "the A/B run spends up to ${ceiling:.2}; pass --yes to start it without a terminal"
            );
        }
        if !super::confirm("Start?")? {
            println!("Nothing ran.");
            return Ok(ExitCode::FAILURE);
        }
    }

    let (base, base_name) = resolve_base(&git, &root, None)?;
    let prefix = git
        .out(&root, &["rev-parse", "--show-prefix"])?
        .trim()
        .to_string();
    let home = ctx.home.clone().context("can't find the home directory")?;
    let stamp = mezha_render::utc_stamp(super::now());
    let report = mezha_memory::metrics_dir(&home, &root).join(format!("ab-{stamp}"));
    create_private_dir(&report)?;
    let setup = Setup {
        ctx: &ctx,
        layers: &layers,
        spec: &spec,
        root: &root,
        git: &git,
        claude: &claude,
        srt,
        file: &file,
        base,
        prefix,
        // Outside ~/.mezha, where the project's own rules refuse writes.
        scratch: Scratch::new("mezha-ab").context("can't create a scratch directory")?,
        report: report.clone(),
        stamp: stamp.clone(),
    };
    let store = Store::new(&mezha_memory::metrics_dir(&home, &root));
    println!(
        "From {base_name}, with Claude Code {version}. Results: {}",
        report.display()
    );

    let order = ab::run_order(file.task.len(), repeat);
    let mut rows = Vec::new();
    for (i, (t, r, variant)) in order.iter().enumerate() {
        let task = &file.task[*t];
        let row = match setup.one(task, *r, *variant, &version) {
            Ok(row) => row,
            Err(e) => {
                eprintln!("The A/B run stopped: {e:#}");
                let _ = git.out(&root, &["worktree", "prune"]);
                return Ok(ExitCode::FAILURE);
            }
        };
        println!(
            "[{}/{}] {} {}: {}, ${:.2}, {} turns{}",
            i + 1,
            order.len(),
            task.name,
            if *variant == Variant::Memory {
                "with memory"
            } else {
                "without"
            },
            if row.passed { "passed" } else { "failed" },
            row.cost_usd,
            row.turns,
            row.failure
                .as_deref()
                .map_or(String::new(), |f| format!(" ({})", escape(f)))
        );
        if let Ok(value) = serde_json::to_value(&row)
            && let Err(e) = store.upsert(store::AB, "id", &[value])
        {
            eprintln!("note: couldn't record the run: {e}");
        }
        rows.push(row);
    }
    let _ = git.out(&root, &["worktree", "prune"]);
    let summary = ab::summarize(&rows);
    let markdown = ab::markdown(&summary);
    mezha_memory::write_private(&report.join("report.md"), markdown.as_bytes())?;
    let json = serde_json::json!({ "version": 1, "summary": summary, "runs": rows });
    mezha_memory::write_private(
        &report.join("report.json"),
        format!("{json:#}\n").as_bytes(),
    )?;
    println!("\n{markdown}");
    Ok(ExitCode::SUCCESS)
}

impl Setup<'_> {
    /// One session in a fresh worktree, its check, and its row.
    fn one(&self, task: &Task, repeat: u32, variant: Variant, version: &str) -> Result<AbRow> {
        let git = self.git;
        // A neutral name: the cwd is in the model's prompt.
        let wt = self.scratch.path().join(format!("run-{}", &nonce()?[..12]));
        let wt_text = wt.to_string_lossy().into_owned();
        git.out(
            self.root,
            &[
                "worktree", "add", "--quiet", "--detach", &wt_text, &self.base,
            ],
        )?;
        // The real path: srt and the session compare paths as the kernel
        // sees them (`/tmp` is `/private/tmp` on macOS).
        let wt = std::fs::canonicalize(&wt)?;
        let result = self.in_worktree(&wt, task, repeat, variant, version);
        let _ = git.out(self.root, &["worktree", "remove", "--force", &wt_text]);
        result
    }

    fn in_worktree(
        &self,
        wt: &Path,
        task: &Task,
        repeat: u32,
        variant: Variant,
        version: &str,
    ) -> Result<AbRow> {
        let git = self.git;
        let project = match self.prefix.trim_end_matches('/') {
            "" => wt.to_path_buf(),
            prefix => wt.join(prefix),
        };
        match variant {
            Variant::Memory => {
                // Local memory isn't in git: copy it in, never PHI.
                for (name, agent) in &self.spec.agent {
                    if self.spec.memory_scope(agent) != Some(Scope::Local)
                        || self.spec.is_phi(agent)
                    {
                        continue;
                    }
                    let from = self.root.join(".claude/agent-memory-local").join(name);
                    let files = review::snapshot(&from).map_err(anyhow::Error::msg)?;
                    let to = project.join(".claude/agent-memory-local").join(name);
                    create_private_dir(&to)?;
                    for (file, bytes) in files {
                        std::fs::write(to.join(file), bytes)?;
                    }
                }
            }
            Variant::Empty => {
                let dir = format!("{}.claude/agent-memory", self.prefix);
                git.out(wt, &["rm", "-r", "-q", "--ignore-unmatch", "--", &dir])?;
            }
        }
        let mut commit = IDENTITY.to_vec();
        commit.extend([
            "commit",
            "--quiet",
            "--no-verify",
            "--allow-empty",
            "-m",
            PREPARE,
        ]);
        git.out(wt, &commit)?;

        let started = Instant::now();
        let (outcome, init_version) = self.session(&project, task)?;
        if init_version.as_deref().is_some_and(|v| v != version) {
            bail!(
                "Claude Code changed from {version} to {} during the run; start again",
                init_version.unwrap_or_default()
            );
        }
        let duration_ms = started.elapsed().as_millis() as u64;
        let passed = match &task.check {
            Some(check) => self.check(&project, check)?,
            None => outcome.failure.is_none(),
        };
        self.save_diff(wt, task, repeat, variant);
        Ok(AbRow {
            v: store::VERSION,
            id: format!("{}/{}/{}/{repeat}", self.stamp, task.name, variant.as_str()),
            stamp: self.stamp.clone(),
            task: task.name.clone(),
            variant,
            repeat,
            passed,
            is_error: outcome.failure.is_some(),
            subtype: outcome.subtype.clone(),
            cost_usd: outcome.cost_usd,
            turns: outcome.turns,
            duration_ms,
            claude_code: version.to_string(),
            failure: outcome.failure,
        })
    }

    /// The session: the project's own settings, sandbox and hooks, as in
    /// real use. Auto memory stays readable (Claude Code turns agent memory
    /// off with it) but can't be written: every worktree of the repository
    /// shares it, so one run's notes would reach the next.
    fn session(&self, cwd: &Path, task: &Task) -> Result<(claude::Outcome, Option<String>)> {
        let ab = &self.file.ab;
        let turns = ab.max_turns().to_string();
        let budget = format!("{:.2}", ab.budget_usd());
        let mut args = vec![
            "-p",
            "--agent",
            &task.agent,
            "--output-format",
            "stream-json",
            "--verbose",
            "--permission-mode",
            "acceptEdits",
            "--permission-prompts",
            "none",
            "--strict-mcp-config",
            "--max-turns",
            &turns,
            "--max-budget-usd",
            &budget,
            "--no-session-persistence",
            "--settings",
            NO_AUTO_MEMORY_WRITES,
        ];
        if let Some(model) = &ab.model {
            args.extend(["--model", model.as_str()]);
        }
        let mut init: Option<Result<Option<String>, String>> = None;
        let mut result: Option<Value> = None;
        let out = runner::run_lines(
            self.ctx,
            &Run {
                program: self.claude,
                args: &args,
                cwd,
                env: &[("DISABLE_AUTOUPDATER", "1")],
                remove: &ENV_REMOVE,
                stdin: task.prompt.as_bytes(),
                timeout: Duration::from_secs(u64::from(ab.timeout_minutes()) * 60),
            },
            |line| {
                let Ok(event) = serde_json::from_str::<Value>(line) else {
                    return Next::Continue;
                };
                match (
                    event.get("type").and_then(Value::as_str),
                    event.get("subtype").and_then(Value::as_str),
                ) {
                    (Some("system"), Some("init")) => {
                        let checked = check_init(&event, &task.agent);
                        let stop = checked.is_err();
                        init = Some(checked);
                        if stop {
                            return Next::Stop;
                        }
                    }
                    (Some("result"), _) => result = Some(event),
                    _ => {}
                }
                Next::Continue
            },
        )?;
        let version = match init {
            Some(Ok(v)) => v,
            Some(Err(why)) => bail!("{why}"),
            None => bail!(
                "claude didn't report how it started (exit {:?}): {}",
                out.code,
                escape(out.stderr.trim())
            ),
        };
        let outcome = match result {
            Some(event) => claude::read_outcome(&event),
            None if out.timed_out => claude::Outcome {
                failure: Some(format!(
                    "it ran longer than {} minutes",
                    ab.timeout_minutes()
                )),
                subtype: "timeout".into(),
                ..claude::Outcome::default()
            },
            None => claude::Outcome {
                failure: Some(format!("it ended without a result (exit {:?})", out.code)),
                subtype: "no-result".into(),
                ..claude::Outcome::default()
            },
        };
        Ok((outcome, version))
    }

    /// Runs the task's check in the worktree: in srt with the project's
    /// sandbox, unless you passed --unsandboxed-check.
    fn check(&self, cwd: &Path, check: &str) -> Result<bool> {
        let timeout = Duration::from_secs(u64::from(self.file.ab.timeout_minutes()) * 60);
        let path = self.ctx.trusted_path();
        let out = match &self.srt {
            Some(srt) => {
                let settings =
                    mezha_verify::probe::srt::command_settings(self.ctx, self.layers, cwd);
                let file = self.scratch.write_new(
                    &format!("srt-{}.json", &nonce()?[..12]),
                    settings.to_string().as_bytes(),
                )?;
                let file = file.to_string_lossy().into_owned();
                runner::run(
                    self.ctx,
                    &Run {
                        program: &srt.program,
                        args: &["--settings", &file, "-c", check],
                        cwd,
                        env: &[("PATH", &path)],
                        remove: &mezha_verify::probe::srt::NODE_ENV,
                        stdin: b"",
                        timeout,
                    },
                )?
            }
            None => runner::run(
                self.ctx,
                &Run {
                    program: Path::new("/bin/sh"),
                    args: &["-c", check],
                    cwd,
                    env: &[("PATH", &path)],
                    remove: &[],
                    stdin: b"",
                    timeout,
                },
            )?,
        };
        Ok(out.success())
    }

    /// The run's changes outside agent memory, for reading afterwards.
    fn save_diff(&self, wt: &Path, task: &Task, repeat: u32, variant: Variant) {
        let git = self.git;
        let _ = git.out(wt, &["add", "-A"]);
        let diff = git
            .out(
                wt,
                &[
                    "diff",
                    "--cached",
                    "--no-color",
                    "--no-ext-diff",
                    "HEAD",
                    "--",
                    ".",
                    ":(exclude).claude/agent-memory",
                    ":(exclude).claude/agent-memory-local",
                ],
            )
            .unwrap_or_default();
        let diff = mezha_memory::inbox::cut(&diff, MAX_DIFF);
        let name = format!("{}-{}-{repeat}.diff", task.name, variant.as_str());
        let _ = mezha_memory::write_private(&self.report.join(name), diff.as_bytes());
    }
}

/// The session must run as the task's agent, in acceptEdits; returns the
/// Claude Code version it reports.
fn check_init(event: &Value, agent: &str) -> Result<Option<String>, String> {
    let mode = event.get("permissionMode").and_then(Value::as_str);
    if mode != Some("acceptEdits") {
        return Err(format!(
            "the session runs in permission mode {}, not acceptEdits",
            mode.unwrap_or("(none)")
        ));
    }
    let agents = event.get("agents").and_then(Value::as_array);
    if agents.is_some_and(|a| !a.iter().any(|n| n.as_str() == Some(agent))) {
        return Err(format!(
            "Claude Code doesn't know agent `{agent}` in the worktree; is .claude/agents/{agent}.md committed? (`mezha compile`)"
        ));
    }
    Ok(event
        .get("claude_code_version")
        .and_then(Value::as_str)
        .map(str::to_string))
}

fn claude_version(ctx: &Ctx, claude: &Path) -> Result<String> {
    let out = runner::run(
        ctx,
        &Run {
            program: claude,
            args: &["--version"],
            cwd: &ctx.root,
            env: &[("DISABLE_AUTOUPDATER", "1")],
            remove: &ENV_REMOVE,
            stdin: b"",
            timeout: Duration::from_secs(30),
        },
    )?;
    let text = out.stdout.trim();
    let Some(v) = claude::parse_version(text) else {
        bail!(
            "`claude --version` said {}, not a version",
            shell_word(text)
        );
    };
    if v < MIN_CLAUDE_CODE {
        bail!("Claude Code {text} is too old; update it");
    }
    Ok(text.split_whitespace().next().unwrap_or("").to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn init_must_show_the_agent_and_mode() {
        let ok = json!({"permissionMode": "acceptEdits", "agents": ["implementer"], "claude_code_version": "2.1.285"});
        assert_eq!(check_init(&ok, "implementer"), Ok(Some("2.1.285".into())));
        assert!(check_init(&ok, "explorer").is_err());
        assert!(check_init(&json!({"permissionMode": "default"}), "implementer").is_err());
    }
}
