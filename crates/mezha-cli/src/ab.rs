//! `mezha metrics --ab tasks.toml`: each task runs as its agent with the
//! project's agent memory and with that memory emptied, in identical
//! worktrees, and a sandboxed check says which runs passed. It spends real
//! money, so it says how much at most and asks first.

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use mezha_memory::review;
use mezha_memory::scan::escape;
use mezha_metrics::ab::{self, AbRow, Task, TaskFile, Variant};
use mezha_metrics::store::{self, Store};
use mezha_spec::{Scope, Spec};
use mezha_verify::Ctx;
use mezha_verify::scratch::Scratch;

use crate::bench::{self, Bench, Session};
use crate::files::create_private_dir;
use crate::git::{Git, resolve_base};
use crate::metrics::Options;

/// The commit that makes both variants look the same to the model.
const PREPARE: &str = "ab: prepare run";
/// Agent memory is what differs, so diffs leave it out.
const MEMORY_DIRS: [&str; 2] = [".claude/agent-memory", ".claude/agent-memory-local"];

/// What the runs share.
struct Setup<'a> {
    bench: Bench<'a>,
    spec: &'a Spec,
    file: &'a TaskFile,
    report: PathBuf,
    stamp: String,
}

pub fn run(root: &Path, tasks_path: &Path, opts: &Options) -> Result<ExitCode> {
    bench::refuse_here("mezha metrics --ab")?;
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
    let (claude, version) = bench::find_claude(&ctx)?;
    let checks: Vec<&Task> = file.task.iter().filter(|t| t.check.is_some()).collect();
    let srt = bench::find_srt(&ctx, !checks.is_empty(), opts.unsandboxed_check)?;

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
    if !bench::confirm_spend(opts.yes, "A/B run", ceiling)? {
        return Ok(ExitCode::FAILURE);
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
        bench: Bench {
            ctx: &ctx,
            layers: &layers,
            root: &root,
            git: &git,
            claude,
            version: version.clone(),
            srt,
            base,
            prefix,
            scratch: Scratch::new("mezha-ab").context("can't create a scratch directory")?,
        },
        spec: &spec,
        file: &file,
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
        let row = match setup.one(task, *r, *variant) {
            Ok(row) => row,
            Err(e) => {
                eprintln!("The A/B run stopped: {e:#}");
                setup.bench.prune();
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
    setup.bench.prune();
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
    fn one(&self, task: &Task, repeat: u32, variant: Variant) -> Result<AbRow> {
        let bench = &self.bench;
        bench.in_worktree(
            PREPARE,
            |wt, project| self.prepare(wt, project, variant),
            |wt, project| {
                let ab = &self.file.ab;
                let timeout = Duration::from_secs(u64::from(ab.timeout_minutes()) * 60);
                let started = Instant::now();
                let outcome = bench.session(
                    project,
                    &Session {
                        agent: Some(&task.agent),
                        prompt: &task.prompt,
                        model: ab.model.as_deref(),
                        max_turns: ab.max_turns(),
                        budget_usd: ab.budget_usd(),
                        timeout,
                    },
                    |_| {},
                )?;
                let duration_ms = started.elapsed().as_millis() as u64;
                let passed = match &task.check {
                    Some(check) => bench.check(project, check, timeout)?,
                    None => outcome.failure.is_none(),
                };
                let name = format!("{}-{}-{repeat}.diff", task.name, variant.as_str());
                bench.save_diff(wt, &MEMORY_DIRS, &self.report.join(name));
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
                    claude_code: bench.version.clone(),
                    failure: outcome.failure,
                })
            },
        )
    }

    /// With memory: local memory, which isn't in git, copied in (never
    /// PHI). Emptied: the committed memory removed.
    fn prepare(&self, wt: &Path, project: &Path, variant: Variant) -> Result<()> {
        match variant {
            Variant::Memory => {
                for (name, agent) in &self.spec.agent {
                    if self.spec.memory_scope(agent) != Some(Scope::Local)
                        || self.spec.is_phi(agent)
                    {
                        continue;
                    }
                    let from = self
                        .bench
                        .root
                        .join(".claude/agent-memory-local")
                        .join(name);
                    let files = review::snapshot(&from).map_err(anyhow::Error::msg)?;
                    let to = project.join(".claude/agent-memory-local").join(name);
                    create_private_dir(&to)?;
                    for (file, bytes) in files {
                        std::fs::write(to.join(file), bytes)?;
                    }
                }
            }
            Variant::Empty => {
                let dir = format!("{}.claude/agent-memory", self.bench.prefix);
                self.bench
                    .git
                    .out(wt, &["rm", "-r", "-q", "--ignore-unmatch", "--", &dir])?;
            }
        }
        Ok(())
    }
}
