//! `mezha skill eval <name>`: does Claude load the skill when it should,
//! and only then, and do tasks go better with it? Trigger prompts run with
//! the skill; tasks run with it and without it, in otherwise identical
//! clones of the project. It spends real money, so it says how much at most
//! and asks first.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use clap::ValueEnum;
use mezha_memory::claude::Outcome;
use mezha_memory::scan::escape;
use mezha_metrics::skill_eval::{self, Arm, CaseFile, EvalRow, Kind, Run};
use mezha_metrics::store::{self, Store};
use mezha_spec::Spec;
use mezha_verify::Ctx;
use mezha_verify::scratch::Scratch;
use serde_json::Value;

use crate::bench::{self, Bench, Session};
use crate::files::create_private_dir;
use crate::git::{Git, resolve_base};

/// Where case files live by default: `mezha/evals/<skill>.toml`.
pub const EVALS_DIR: &str = "mezha/evals";
/// The commit that makes both arms look the same to the model.
const PREPARE: &str = "eval: prepare run";
/// A task's final message kept for the report, at most.
const MAX_MESSAGE: usize = 16 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Only {
    Triggers,
    Tasks,
}

pub struct Options {
    pub name: String,
    pub cases: Option<PathBuf>,
    pub repeat: u32,
    pub base: Option<String>,
    pub only: Option<Only>,
    pub yes: bool,
    pub unsandboxed_check: bool,
}

/// What the runs share.
struct Setup<'a> {
    bench: Bench<'a>,
    name: &'a str,
    file: &'a CaseFile,
    /// The skill's SKILL.md as mezha.toml renders it now.
    skill_md: String,
    /// Paths, relative to the project, that the arm without the skill
    /// loses: the skill's directory and its body file.
    skill_paths: Vec<String>,
    /// Paths both arms lose: the case files, which hold the answers.
    case_paths: Vec<String>,
    report: PathBuf,
    stamp: String,
}

pub fn run(root: &Path, opts: &Options) -> Result<ExitCode> {
    bench::refuse_here("mezha skill eval")?;
    let root = std::fs::canonicalize(root).with_context(|| root.display().to_string())?;
    let Some((spec, _)) = super::load(&root)? else {
        return Ok(ExitCode::FAILURE);
    };
    let name = opts.name.as_str();
    let cases = match &opts.cases {
        Some(path) => path.clone(),
        None => root.join(EVALS_DIR).join(format!("{name}.toml")),
    };
    let text = std::fs::read_to_string(&cases).with_context(|| {
        format!(
            "{} (write the skill's cases there, or pass --cases)",
            cases.display()
        )
    })?;
    let mut file =
        skill_eval::parse(&text).map_err(|e| anyhow::anyhow!("{}: {e}", cases.display()))?;
    let mut errors = skill_eval::validate(&file, &spec, name);
    match opts.only {
        Some(Only::Triggers) if file.trigger.is_empty() => {
            errors.push("--only triggers, but there are no [[trigger]] entries".into());
        }
        Some(Only::Tasks) if file.task.is_empty() => {
            errors.push("--only tasks, but there are no [[task]] entries".into());
        }
        Some(Only::Triggers) => file.task.clear(),
        Some(Only::Tasks) => file.trigger.clear(),
        None => {}
    }
    if !errors.is_empty() {
        for e in &errors {
            eprintln!("error: {}: {e}", cases.display());
        }
        return Ok(ExitCode::FAILURE);
    }
    let skill_md = render_skill(&spec, &root, name)?;
    let repeat = opts.repeat.max(1);

    let mut ctx = Ctx::from_process(&root);
    let layers = mezha_verify::layers::Layers::load(&ctx, false);
    ctx.agent_writable = layers.agent_writable(&ctx);
    let git = Git::new(&ctx)?;
    let (claude, version) = bench::find_claude(&ctx)?;
    let checks: Vec<_> = file.task.iter().filter(|t| t.check.is_some()).collect();
    let srt = bench::find_srt(&ctx, !checks.is_empty(), opts.unsandboxed_check)?;

    // What it will do and cost, before anything runs.
    let eval = &file.eval;
    let triggers = file.trigger.len() as u32 * repeat;
    let tasks = file.task.len() as u32 * 2 * repeat;
    let ceiling = f64::from(triggers + tasks) * eval.budget_usd();
    println!(
        "{} trigger prompt(s) × {repeat} + {} task(s) × 2 variants × {repeat} = {} Claude Code session(s), up to ${:.2} each: at most ${ceiling:.2}.",
        file.trigger.len(),
        file.task.len(),
        triggers + tasks,
        eval.budget_usd()
    );
    if triggers > 0 {
        println!("  trigger runs stop after {} turn(s)", eval.trigger_turns());
    }
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
    if !bench::confirm_spend(opts.yes, "skill eval", ceiling)? {
        return Ok(ExitCode::FAILURE);
    }

    let (base, base_name) = resolve_base(&git, &root, opts.base.as_deref())?;
    let prefix = git
        .out(&root, &["rev-parse", "--show-prefix"])?
        .trim()
        .to_string();
    let home = ctx.home.clone().context("can't find the home directory")?;
    let stamp = mezha_render::utc_stamp(super::now());
    let metrics = mezha_memory::metrics_dir(&home, &root);
    let report = metrics.join(format!("skill-{name}-{stamp}"));
    create_private_dir(&report)?;
    let skill = &spec.skill[name];
    let mut case_paths = vec![EVALS_DIR.to_string()];
    if let Some(rel) = std::fs::canonicalize(&cases)
        .ok()
        .and_then(|c| c.strip_prefix(&root).ok().map(Path::to_path_buf))
    {
        case_paths.push(rel.to_string_lossy().replace('\\', "/"));
    }
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
            scratch: Scratch::new("mezha-eval").context("can't create a scratch directory")?,
        },
        name,
        file: &file,
        skill_md,
        skill_paths: vec![format!(".claude/skills/{name}"), skill.body_path(name)],
        case_paths,
        report: report.clone(),
        stamp: stamp.clone(),
    };
    let store = Store::new(&metrics);
    println!(
        "From {base_name} with skill.{name} as mezha.toml says now, with Claude Code {version}. Results: {}",
        report.display()
    );

    let order = skill_eval::run_order(file.trigger.len(), file.task.len(), repeat);
    let mut rows = Vec::new();
    for (i, run) in order.iter().enumerate() {
        let row = match setup.one(*run) {
            Ok(row) => row,
            Err(e) => {
                eprintln!("The skill eval stopped: {e:#}");
                return Ok(ExitCode::FAILURE);
            }
        };
        println!("[{}/{}] {}", i + 1, order.len(), progress(&row));
        if let Ok(value) = serde_json::to_value(&row)
            && let Err(e) = store.upsert(store::SKILL_EVALS, "id", &[value])
        {
            eprintln!("note: couldn't record the run: {e}");
        }
        rows.push(row);
    }
    let summary = skill_eval::summarize(&rows);
    let prompts: Vec<String> = file.trigger.iter().map(|t| t.prompt.clone()).collect();
    let markdown = skill_eval::markdown(&summary, &prompts, eval.trigger_turns());
    mezha_memory::write_private(&report.join("report.md"), markdown.as_bytes())?;
    let json = serde_json::json!({ "version": 1, "summary": summary, "runs": rows });
    mezha_memory::write_private(
        &report.join("report.json"),
        format!("{json:#}\n").as_bytes(),
    )?;
    println!("\n{markdown}");
    Ok(ExitCode::SUCCESS)
}

/// The skill's SKILL.md as the spec and its body file say now, with a note
/// when the compiled file differs from it.
fn render_skill(spec: &Spec, root: &Path, name: &str) -> Result<String> {
    let rel = format!(".claude/skills/{name}/SKILL.md");
    let mut rendered = mezha_render::components::render(spec, root);
    let Some(text) = rendered.files.remove(&rel) else {
        let problems: Vec<String> = rendered
            .problems
            .into_iter()
            .filter(|p| p.starts_with(&rel))
            .collect();
        bail!("can't render skill.{name}: {}", problems.join("; "));
    };
    let compiled = std::fs::read_to_string(root.join(&rel)).ok();
    if compiled.as_deref().map(|c| c.replace("\r\n", "\n")) != Some(text.clone()) {
        eprintln!(
            "note: {rel} isn't what mezha.toml renders now; the eval uses mezha.toml (`mezha compile` writes it)"
        );
    }
    Ok(text)
}

/// A run's line on the terminal.
fn progress(row: &EvalRow) -> String {
    let what = match row.kind {
        Kind::Trigger => format!(
            "{} ({}): ",
            row.case.replace('-', " "),
            if row.should_trigger == Some(true) {
                "should load"
            } else {
                "shouldn't load"
            }
        ),
        Kind::Task => format!(
            "{} {}: {}, ",
            row.case,
            if row.arm == Arm::With {
                "with the skill"
            } else {
                "without"
            },
            if row.passed == Some(true) {
                "passed"
            } else {
                "failed"
            }
        ),
    };
    let loaded = match (row.arm, row.load_turn) {
        (Arm::Without, _) => String::new(),
        (Arm::With, Some(turn)) => format!("loaded at turn {turn}, "),
        (Arm::With, None) => "not loaded, ".into(),
    };
    // A trigger run that ran out of turns ended as it should.
    let failure = match (&row.failure, row.kind, row.is_error) {
        (Some(f), Kind::Trigger, true) => format!(" (didn't count: {})", escape(f)),
        (Some(f), Kind::Task, _) => format!(" ({})", escape(f)),
        _ => String::new(),
    };
    format!(
        "{what}{loaded}${:.2}, {} turns{failure}",
        row.cost_usd, row.turns
    )
}

impl Setup<'_> {
    /// One session in a fresh clone, and its row.
    fn one(&self, run: Run) -> Result<EvalRow> {
        let arm = match run {
            Run::Trigger { .. } => Arm::With,
            Run::Task { arm, .. } => arm,
        };
        self.bench.in_clone(
            PREPARE,
            |clone, project| self.prepare(clone, project, arm),
            |clone, project| match run {
                Run::Trigger { index, repeat } => self.trigger(project, index, repeat),
                Run::Task { index, repeat, arm } => self.task(clone, project, index, repeat, arm),
            },
        )
    }

    /// With the skill: its SKILL.md as rendered now. Without: its directory
    /// and body file removed. Both: the case files removed.
    fn prepare(&self, clone: &Path, project: &Path, arm: Arm) -> Result<()> {
        let git = self.bench.git;
        let prefix = &self.bench.prefix;
        let literal = |rel: &str| format!(":(literal){prefix}{rel}");
        let mut gone: Vec<String> = self.case_paths.iter().map(|p| literal(p)).collect();
        match arm {
            Arm::With => {
                let rel = format!(".claude/skills/{}/SKILL.md", self.name);
                let path = project.join(&rel);
                std::fs::create_dir_all(path.parent().expect("a skill directory"))?;
                std::fs::write(&path, &self.skill_md)?;
                git.out(clone, &["add", "-f", "--", &literal(&rel)])?;
            }
            Arm::Without => gone.extend(self.skill_paths.iter().map(|p| literal(p))),
        }
        let mut args = vec!["rm", "-r", "-q", "--ignore-unmatch", "--"];
        args.extend(gone.iter().map(String::as_str));
        git.out(clone, &args)?;
        Ok(())
    }

    fn trigger(&self, project: &Path, index: usize, repeat: u32) -> Result<EvalRow> {
        let eval = &self.file.eval;
        let case = &self.file.trigger[index];
        let (outcome, loads, duration_ms) =
            self.session(project, &case.prompt, eval.trigger_turns(), Arm::With)?;
        // Running out of turns is how a trigger run ends.
        let is_error = outcome.failure.is_some()
            && !matches!(
                outcome.subtype.as_str(),
                "error_max_turns" | "error_max_budget_usd"
            );
        let case_name = format!("trigger-{}", index + 1);
        Ok(EvalRow {
            should_trigger: Some(case.should_trigger),
            is_error,
            ..self
                .row(
                    Kind::Trigger,
                    &case_name,
                    &case.prompt,
                    Arm::With,
                    repeat,
                    &loads,
                )
                .finish(outcome, duration_ms)
        })
    }

    fn task(
        &self,
        clone: &Path,
        project: &Path,
        index: usize,
        repeat: u32,
        arm: Arm,
    ) -> Result<EvalRow> {
        let eval = &self.file.eval;
        let task = &self.file.task[index];
        let (outcome, loads, duration_ms) =
            self.session(project, &task.prompt, eval.max_turns(), arm)?;
        let timeout = Duration::from_secs(u64::from(eval.timeout_minutes()) * 60);
        let check = match &task.check {
            Some(check) => Some(self.bench.check(project, check, timeout)?),
            None => None,
        };
        // A run without a final message passes no pattern, not even a
        // `reject` one.
        let message = task
            .judge_message(&outcome.summary)
            .map(|ok| ok && !outcome.summary.trim().is_empty());
        let passed = match (check, message) {
            (None, None) => outcome.failure.is_none(),
            (check, message) => check.unwrap_or(true) && message.unwrap_or(true),
        };
        let stem = format!("{}-{}-{repeat}", task.name, arm.as_str());
        self.bench
            .save_diff(clone, &[], &self.report.join(format!("{stem}.diff")));
        let _ = mezha_memory::write_private(
            &self.report.join(format!("{stem}.md")),
            mezha_memory::inbox::cut(&outcome.summary, MAX_MESSAGE).as_bytes(),
        );
        Ok(EvalRow {
            passed: Some(passed),
            ..self
                .row(Kind::Task, &task.name, &task.prompt, arm, repeat, &loads)
                .finish(outcome, duration_ms)
        })
    }

    /// A session and the skill loads seen in it. A load in the arm without
    /// the skill means another skill has its name, and stops the eval.
    fn session(
        &self,
        project: &Path,
        prompt: &str,
        max_turns: u32,
        arm: Arm,
    ) -> Result<(Outcome, Loads, u64)> {
        let eval = &self.file.eval;
        let mut loads = Loads::new(self.name);
        let started = Instant::now();
        let outcome = self.bench.session(
            project,
            &Session {
                agent: None,
                prompt,
                model: eval.model.as_deref(),
                max_turns,
                budget_usd: eval.budget_usd(),
                timeout: Duration::from_secs(u64::from(eval.timeout_minutes()) * 60),
            },
            |event| loads.see(event),
        )?;
        let duration_ms = started.elapsed().as_millis() as u64;
        if arm == Arm::Without && loads.loaded_at.is_some() {
            bail!(
                "Claude loaded a skill named `{}` in a run without the project's: a user or plugin skill has the same name, so the comparison would mean nothing. Rename one of them.",
                self.name
            );
        }
        Ok((outcome, loads, duration_ms))
    }

    /// A row with what every run has; [`Started::finish`] adds the outcome.
    fn row(
        &self,
        kind: Kind,
        case: &str,
        prompt: &str,
        arm: Arm,
        repeat: u32,
        loads: &Loads,
    ) -> Started {
        Started(EvalRow {
            v: store::VERSION,
            id: format!(
                "{}/{}/{case}/{}/{repeat}",
                self.stamp,
                self.name,
                arm.as_str()
            ),
            stamp: self.stamp.clone(),
            skill: self.name.to_string(),
            kind,
            case: case.to_string(),
            prompt_sha: mezha_broker::sha256_hex(prompt.as_bytes())[..16].to_string(),
            arm,
            repeat,
            should_trigger: None,
            loaded: loads.loaded_at.is_some(),
            load_turn: loads.loaded_at,
            passed: None,
            is_error: false,
            subtype: String::new(),
            cost_usd: 0.0,
            turns: 0,
            duration_ms: 0,
            claude_code: self.bench.version.clone(),
            failure: None,
        })
    }
}

struct Started(EvalRow);

impl Started {
    /// The row with the session's outcome; a failed session is an error.
    fn finish(self, outcome: Outcome, duration_ms: u64) -> EvalRow {
        EvalRow {
            is_error: outcome.failure.is_some(),
            subtype: outcome.subtype,
            cost_usd: outcome.cost_usd,
            turns: outcome.turns,
            duration_ms,
            failure: outcome.failure,
            ..self.0
        }
    }
}

/// Watches a session's events for the skill being loaded: a Skill tool
/// call naming it, or a Read of its SKILL.md, whose result isn't an error.
/// Claude Code's own skill listing can't tell: it leaves out skills with
/// `user-invocable: false`, which knowledge skills are by default.
struct Loads {
    /// `.claude/skills/<name>/SKILL.md`.
    skill_md: String,
    name: String,
    /// The main thread's assistant messages so far, by id: its turns.
    turns: Vec<String>,
    /// Load attempts waiting for their result, by tool use id, with the
    /// turn they were made in.
    pending: BTreeMap<String, u64>,
    loaded_at: Option<u64>,
}

impl Loads {
    fn new(name: &str) -> Loads {
        Loads {
            skill_md: format!(".claude/skills/{name}/SKILL.md"),
            name: name.to_string(),
            turns: Vec::new(),
            pending: BTreeMap::new(),
            loaded_at: None,
        }
    }

    fn see(&mut self, event: &Value) {
        let Some(message) = event.get("message") else {
            return;
        };
        let content = message
            .get("content")
            .and_then(Value::as_array)
            .map(Vec::as_slice)
            .unwrap_or_default();
        match event.get("type").and_then(Value::as_str) {
            Some("assistant") => {
                let main = event.get("parent_tool_use_id").is_none_or(Value::is_null);
                if let Some(id) = message.get("id").and_then(Value::as_str)
                    && main
                    && !self.turns.iter().any(|t| t == id)
                {
                    self.turns.push(id.to_string());
                }
                for block in content {
                    if block.get("type").and_then(Value::as_str) == Some("tool_use")
                        && self.is_load(block)
                        && let Some(id) = block.get("id").and_then(Value::as_str)
                    {
                        self.pending
                            .insert(id.to_string(), self.turns.len().max(1) as u64);
                    }
                }
            }
            Some("user") => {
                for block in content {
                    if block.get("type").and_then(Value::as_str) != Some("tool_result") {
                        continue;
                    }
                    let Some(turn) = block
                        .get("tool_use_id")
                        .and_then(Value::as_str)
                        .and_then(|id| self.pending.remove(id))
                    else {
                        continue;
                    };
                    let failed = block.get("is_error").and_then(Value::as_bool) == Some(true);
                    if !failed && self.loaded_at.is_none() {
                        self.loaded_at = Some(turn);
                    }
                }
            }
            _ => {}
        }
    }

    fn is_load(&self, block: &Value) -> bool {
        let input = block.get("input");
        let field = |k: &str| input.and_then(|i| i.get(k)).and_then(Value::as_str);
        match block.get("name").and_then(Value::as_str) {
            Some("Skill") => field("skill") == Some(self.name.as_str()),
            Some("Read") => field("file_path").is_some_and(|p| {
                p.strip_suffix(self.skill_md.as_str())
                    .is_some_and(|dir| dir.is_empty() || dir.ends_with('/'))
            }),
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn assistant(id: &str, parent: Option<&str>, tools: &[(&str, &str, Value)]) -> Value {
        let content: Vec<Value> = tools
            .iter()
            .map(|(use_id, name, input)| {
                json!({"type": "tool_use", "id": use_id, "name": name, "input": input})
            })
            .collect();
        json!({"type": "assistant", "parent_tool_use_id": parent,
            "message": {"id": id, "content": content}})
    }

    fn result(use_id: &str, error: Option<bool>) -> Value {
        json!({"type": "user", "message": {"content": [
            {"type": "tool_result", "tool_use_id": use_id, "is_error": error, "content": "x"}]}})
    }

    #[test]
    fn loads_by_skill_tool() {
        let mut l = Loads::new("probe");
        // A message split over two events counts as one turn.
        l.see(&assistant("m1", None, &[]));
        l.see(&assistant(
            "m1",
            None,
            &[("t1", "Bash", json!({"command": "ls"}))],
        ));
        l.see(&result("t1", None));
        l.see(&assistant(
            "m2",
            None,
            &[("t2", "Skill", json!({"skill": "other"}))],
        ));
        l.see(&result("t2", None));
        assert_eq!(l.loaded_at, None);
        l.see(&assistant(
            "m3",
            None,
            &[("t3", "Skill", json!({"skill": "probe"}))],
        ));
        assert_eq!(l.loaded_at, None, "not before its result");
        l.see(&result("t3", None));
        assert_eq!(l.loaded_at, Some(3));
    }

    #[test]
    fn loads_by_reading_skill_md() {
        let mut l = Loads::new("probe");
        let read = |p: &str| json!({"file_path": p});
        l.see(&assistant(
            "m1",
            None,
            &[
                ("t1", "Read", read("/w/.claude/skills/probe/other.md")),
                ("t2", "Read", read("/w/.claude/skills/probe-2/SKILL.md")),
            ],
        ));
        l.see(&result("t1", None));
        l.see(&result("t2", None));
        l.see(&assistant(
            "m1",
            None,
            &[("t5", "Read", read("x.claude/skills/probe/SKILL.md"))],
        ));
        l.see(&result("t5", None));
        assert_eq!(l.loaded_at, None);
        // A failed attempt (the arm without the skill) isn't a load.
        l.see(&assistant(
            "m2",
            None,
            &[("t3", "Read", read("/w/.claude/skills/probe/SKILL.md"))],
        ));
        l.see(&result("t3", Some(true)));
        assert_eq!(l.loaded_at, None);
        // A subagent's load counts, at the main thread's turn.
        l.see(&assistant(
            "s1",
            Some("t9"),
            &[("t4", "Skill", json!({"skill": "probe"}))],
        ));
        l.see(&result("t4", Some(false)));
        assert_eq!(l.loaded_at, Some(2));

        let mut relative = Loads::new("probe");
        relative.see(&assistant(
            "m1",
            None,
            &[("t1", "Read", read(".claude/skills/probe/SKILL.md"))],
        ));
        relative.see(&result("t1", None));
        assert_eq!(relative.loaded_at, Some(1));
    }
}
