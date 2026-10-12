//! `mezha skill eval`: a skill's case file, run order and report.
//!
//! Trigger cases run with the skill only and record whether Claude loaded
//! it within the first few turns: precision and recall over prompts that
//! should and shouldn't load it. Tasks run with the skill and without it,
//! in otherwise identical worktrees, and a check or the final message says
//! which runs passed.

use std::collections::{BTreeMap, BTreeSet};

use mezha_spec::{Preset, Spec, check_name};
use regex::Regex;
use serde::{Deserialize, Serialize};

pub const DEFAULT_BUDGET_USD: f64 = 1.0;
pub const DEFAULT_MAX_TURNS: u32 = 30;
pub const DEFAULT_TRIGGER_TURNS: u32 = 4;
pub const DEFAULT_TIMEOUT_MINUTES: u32 = 15;
/// Section 7 of the plan: a skill's trigger precision should reach this.
pub const PRECISION_TARGET: f64 = 0.8;
/// Below this many repeats the report claims no difference between arms.
pub const MIN_REPEAT_FOR_CLAIMS: u32 = crate::ab::MIN_REPEAT_FOR_CLAIMS;
/// Prompts are cut to this many characters in the report.
const PROMPT_IN_REPORT: usize = 80;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaseFile {
    #[serde(default)]
    pub eval: Settings,
    #[serde(default)]
    pub trigger: Vec<Trigger>,
    #[serde(default)]
    pub task: Vec<Task>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Settings {
    pub model: Option<String>,
    /// The most one session may cost, in US dollars.
    pub budget_usd: Option<f64>,
    /// Turns a task session may take.
    pub max_turns: Option<u32>,
    /// Turns a trigger session gets: the skill must load within them.
    pub trigger_turns: Option<u32>,
    pub timeout_minutes: Option<u32>,
}

impl Settings {
    pub fn budget_usd(&self) -> f64 {
        self.budget_usd.unwrap_or(DEFAULT_BUDGET_USD)
    }

    pub fn max_turns(&self) -> u32 {
        self.max_turns.unwrap_or(DEFAULT_MAX_TURNS)
    }

    pub fn trigger_turns(&self) -> u32 {
        self.trigger_turns.unwrap_or(DEFAULT_TRIGGER_TURNS)
    }

    pub fn timeout_minutes(&self) -> u32 {
        self.timeout_minutes.unwrap_or(DEFAULT_TIMEOUT_MINUTES)
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Trigger {
    pub prompt: String,
    /// Whether Claude should load the skill for this prompt.
    pub should_trigger: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Task {
    pub name: String,
    pub prompt: String,
    /// A command whose exit 0 means the run passed.
    pub check: Option<String>,
    /// Regular expressions the final message must match, every one.
    #[serde(default)]
    pub expect: Vec<String>,
    /// Regular expressions the final message must not match.
    #[serde(default)]
    pub reject: Vec<String>,
}

impl Task {
    /// The task's verdict on a final message; `None` when it has no
    /// `expect` or `reject` patterns. Patterns are checked by [`validate`].
    pub fn judge_message(&self, message: &str) -> Option<bool> {
        if self.expect.is_empty() && self.reject.is_empty() {
            return None;
        }
        let matches = |p: &String| Regex::new(p).is_ok_and(|r| r.is_match(message));
        Some(self.expect.iter().all(matches) && !self.reject.iter().any(matches))
    }
}

pub fn parse(text: &str) -> Result<CaseFile, String> {
    toml::from_str(text).map_err(|e| e.to_string())
}

/// Everything wrong with the case file for this spec's skill `skill`.
pub fn validate(file: &CaseFile, spec: &Spec, skill: &str) -> Vec<String> {
    let mut errors = Vec::new();
    match spec.skill.get(skill) {
        None => errors.push(format!("there is no skill.{skill} in mezha.toml")),
        Some(s) if s.preset == Preset::Command => errors.push(format!(
            "skill.{skill} is a command skill: Claude never loads it on its own, so there is \
             nothing to compare. Run /{skill} yourself to try it."
        )),
        Some(_) => {}
    }
    let eval = &file.eval;
    if let Some(model) = &eval.model
        && (model.is_empty()
            || model.starts_with('-')
            || model.chars().any(|c| c.is_whitespace() || c.is_control()))
    {
        errors.push(format!(
            "eval.model `{}` is not a model name",
            model.escape_debug()
        ));
    }
    if let Some(b) = eval.budget_usd
        && !(b.is_finite() && b > 0.0 && b <= 50.0)
    {
        errors.push("eval.budget_usd must be more than 0 and at most 50".into());
    }
    if eval.max_turns.is_some_and(|t| !(1..=200).contains(&t)) {
        errors.push("eval.max_turns must be between 1 and 200".into());
    }
    if eval.trigger_turns.is_some_and(|t| !(1..=20).contains(&t)) {
        errors.push("eval.trigger_turns must be between 1 and 20".into());
    }
    if eval
        .timeout_minutes
        .is_some_and(|t| !(1..=240).contains(&t))
    {
        errors.push("eval.timeout_minutes must be between 1 and 240".into());
    }
    if file.trigger.is_empty() && file.task.is_empty() {
        errors.push("there are no [[trigger]] or [[task]] entries".into());
    }

    let mut prompts = BTreeSet::new();
    for (i, trigger) in file.trigger.iter().enumerate() {
        let at = format!("trigger {}", i + 1);
        if trigger.prompt.trim().is_empty() {
            errors.push(format!("{at}: the prompt is empty"));
        }
        if !prompts.insert(trigger.prompt.trim()) {
            errors.push(format!("{at}: the same prompt is listed twice"));
        }
    }
    if !file.trigger.is_empty() {
        let wanted = file.trigger.iter().filter(|t| t.should_trigger).count();
        if wanted == 0 || wanted == file.trigger.len() {
            errors.push(
                "triggers need prompts with should_trigger = true and with false: one kind alone \
                 measures recall or false loads, not both"
                    .into(),
            );
        }
    }

    let mut names = BTreeSet::new();
    for task in &file.task {
        let at = format!("task {}", task.name);
        if let Err(e) = check_name(&task.name) {
            errors.push(format!("{at}: {e}"));
        }
        if !names.insert(task.name.as_str()) {
            errors.push(format!("{at}: the name is used twice"));
        }
        if task.prompt.trim().is_empty() {
            errors.push(format!("{at}: the prompt is empty"));
        }
        if task.check.as_deref().is_some_and(|c| c.trim().is_empty()) {
            errors.push(format!("{at}: the check is empty"));
        }
        for (field, list) in [("expect", &task.expect), ("reject", &task.reject)] {
            for pattern in list {
                if let Err(e) = Regex::new(pattern) {
                    errors.push(format!("{at}: {field} `{}`: {e}", pattern.escape_debug()));
                }
            }
        }
    }
    errors
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Arm {
    /// The skill as `mezha.toml` renders it now.
    With,
    /// The skill, its body file and its directory removed.
    Without,
}

impl Arm {
    pub fn as_str(self) -> &'static str {
        match self {
            Arm::With => "with",
            Arm::Without => "without",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Run {
    /// Trigger case `index` (from 0), with the skill.
    Trigger { index: usize, repeat: u32 },
    /// Task `index` (from 0), in one arm.
    Task { index: usize, repeat: u32, arm: Arm },
}

/// The runs in order: every trigger and repeat, then every task and repeat
/// in both arms, the order of the two alternating so neither always goes
/// first (warm caches, a changing service).
pub fn run_order(triggers: usize, tasks: usize, repeat: u32) -> Vec<Run> {
    let mut order = Vec::new();
    for r in 0..repeat {
        for index in 0..triggers {
            order.push(Run::Trigger { index, repeat: r });
        }
    }
    for r in 0..repeat {
        for index in 0..tasks {
            let pair = if (index + r as usize).is_multiple_of(2) {
                [Arm::With, Arm::Without]
            } else {
                [Arm::Without, Arm::With]
            };
            order.extend(pair.map(|arm| Run::Task {
                index,
                repeat: r,
                arm,
            }));
        }
    }
    order
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Kind {
    Trigger,
    Task,
}

/// One run's result, as stored in `skill-evals.jsonl`: counts and hashes,
/// never prompt or message text.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EvalRow {
    pub v: u64,
    /// `<stamp>/<skill>/<case>/<arm>/<repeat>`.
    pub id: String,
    pub stamp: String,
    pub skill: String,
    pub kind: Kind,
    /// `trigger-<n>` (from 1), or the task's name.
    pub case: String,
    /// The first 16 hex digits of the prompt's SHA-256.
    pub prompt_sha: String,
    pub arm: Arm,
    pub repeat: u32,
    /// Trigger cases: whether the skill should have loaded.
    pub should_trigger: Option<bool>,
    /// Whether Claude loaded the skill (the Skill tool, or a read of its
    /// SKILL.md).
    pub loaded: bool,
    /// The assistant turn it loaded in, from 1.
    pub load_turn: Option<u64>,
    /// Tasks: the check's and patterns' verdict; without either, whether
    /// the session succeeded.
    pub passed: Option<bool>,
    /// The run didn't count: no result, a failed login, a timeout. A
    /// trigger run that ran out of turns counts.
    pub is_error: bool,
    pub subtype: String,
    pub cost_usd: f64,
    pub turns: u64,
    pub duration_ms: u64,
    pub claude_code: String,
    pub failure: Option<String>,
    /// Fingerprint (`sha256:...`) of the SKILL.md the run had, so a result
    /// is tied to the skill it measured; absent in older rows.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub skill_sha: Option<String>,
    /// The model the eval asked for; absent means Claude Code's default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    /// Tools Claude called while the skill was loaded, by name (`Bash` for
    /// any command), first use first.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tools_used: Vec<String>,
    /// Those the skill's `allowed_tools` doesn't declare; `Bash outside
    /// its scopes` for a command no `Bash(...)` entry matches.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub undeclared_tools: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct TriggerStats {
    pub case: String,
    pub should_trigger: bool,
    /// Runs that counted.
    pub runs: u32,
    pub loaded: u32,
    pub errors: u32,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct Confusion {
    /// Loaded when it should have.
    pub hits: u32,
    /// Loaded when it shouldn't have.
    pub false_loads: u32,
    /// Didn't load when it should have.
    pub misses: u32,
    /// Stayed out when it should have.
    pub quiet: u32,
}

impl Confusion {
    pub fn precision(&self) -> Option<f64> {
        ratio(self.hits, self.hits + self.false_loads)
    }

    pub fn recall(&self) -> Option<f64> {
        ratio(self.hits, self.hits + self.misses)
    }
}

fn ratio(a: u32, b: u32) -> Option<f64> {
    (b > 0).then(|| f64::from(a) / f64::from(b))
}

#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct ArmStats {
    pub runs: u32,
    pub passed: u32,
    /// Runs in which Claude loaded the skill.
    pub loaded: u32,
    pub errors: u32,
    pub cost_usd: f64,
    pub turns: u64,
}

impl ArmStats {
    fn add(&mut self, row: &EvalRow) {
        self.runs += 1;
        self.passed += u32::from(row.passed == Some(true));
        self.loaded += u32::from(row.loaded);
        self.errors += u32::from(row.is_error);
        self.cost_usd += row.cost_usd;
        self.turns += row.turns;
    }
}

#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct TaskStats {
    pub with: ArmStats,
    pub without: ArmStats,
    /// Repeats that passed with the skill only, and without it only.
    pub with_only: u32,
    pub without_only: u32,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct Summary {
    pub stamp: String,
    pub skill: String,
    pub repeat: u32,
    pub triggers: Vec<TriggerStats>,
    pub confusion: Confusion,
    pub precision: Option<f64>,
    pub recall: Option<f64>,
    pub tasks: BTreeMap<String, TaskStats>,
    pub with: ArmStats,
    pub without: ArmStats,
    pub cost_usd: f64,
    /// Fewer repeats than [`MIN_REPEAT_FOR_CLAIMS`].
    pub too_few: bool,
    /// Tools used while the skill was loaded that its `allowed_tools`
    /// doesn't declare, with the number of runs that used each.
    pub undeclared: BTreeMap<String, u32>,
    /// Runs in which the skill was loaded, and so could be compared.
    pub loaded_runs: u32,
}

/// The summary of one eval (rows with the same stamp and skill).
pub fn summarize(rows: &[EvalRow]) -> Summary {
    let mut s = Summary {
        stamp: rows.first().map(|r| r.stamp.clone()).unwrap_or_default(),
        skill: rows.first().map(|r| r.skill.clone()).unwrap_or_default(),
        ..Summary::default()
    };
    let mut triggers: BTreeMap<u32, TriggerStats> = BTreeMap::new();
    let mut pairs: BTreeMap<(String, u32), [Option<bool>; 2]> = BTreeMap::new();
    for row in rows {
        s.cost_usd += row.cost_usd;
        s.repeat = s.repeat.max(row.repeat + 1);
        s.loaded_runs += u32::from(row.loaded);
        for tool in &row.undeclared_tools {
            *s.undeclared.entry(tool.clone()).or_default() += 1;
        }
        match row.kind {
            Kind::Trigger => {
                let n = trigger_number(&row.case);
                let should = row.should_trigger.unwrap_or(false);
                let t = triggers.entry(n).or_insert_with(|| TriggerStats {
                    case: row.case.clone(),
                    should_trigger: should,
                    ..TriggerStats::default()
                });
                if row.is_error {
                    t.errors += 1;
                    continue;
                }
                t.runs += 1;
                t.loaded += u32::from(row.loaded);
                let c = &mut s.confusion;
                match (should, row.loaded) {
                    (true, true) => c.hits += 1,
                    (false, true) => c.false_loads += 1,
                    (true, false) => c.misses += 1,
                    (false, false) => c.quiet += 1,
                }
            }
            Kind::Task => {
                let task = s.tasks.entry(row.case.clone()).or_default();
                let slot = match row.arm {
                    Arm::With => {
                        task.with.add(row);
                        s.with.add(row);
                        0
                    }
                    Arm::Without => {
                        task.without.add(row);
                        s.without.add(row);
                        1
                    }
                };
                pairs.entry((row.case.clone(), row.repeat)).or_default()[slot] =
                    Some(row.passed == Some(true));
            }
        }
    }
    for ((task, _), pair) in pairs {
        let stats = s.tasks.entry(task).or_default();
        match pair {
            [Some(true), Some(false)] => stats.with_only += 1,
            [Some(false), Some(true)] => stats.without_only += 1,
            _ => {}
        }
    }
    s.triggers = triggers.into_values().collect();
    s.precision = s.confusion.precision();
    s.recall = s.confusion.recall();
    s.too_few = s.repeat < MIN_REPEAT_FOR_CLAIMS;
    s
}

/// `trigger-12` → 12, so the report lists triggers in file order.
fn trigger_number(case: &str) -> u32 {
    case.strip_prefix("trigger-")
        .and_then(|n| n.parse().ok())
        .unwrap_or(u32::MAX)
}

/// The summary as Markdown, for `report.md`. `prompts` are the trigger
/// prompts in file order, which the store doesn't keep.
pub fn markdown(s: &Summary, prompts: &[String], trigger_turns: u32) -> String {
    let mut out = format!("# Skill eval: {}, {}\n\n", s.skill, s.stamp);
    if !s.triggers.is_empty() {
        out.push_str(&format!(
            "## Triggers\n\n{} prompt(s) × {} run(s), with the skill. Loaded means Claude called the Skill tool for it, or read its SKILL.md, within {trigger_turns} turn(s).\n\n",
            s.triggers.len(),
            s.repeat
        ));
        out.push_str("| # | Should load | Loaded | Prompt |\n|---|---|---|---|\n");
        for t in &s.triggers {
            let n = trigger_number(&t.case);
            let prompt = prompts
                .get((n as usize).wrapping_sub(1))
                .map_or(String::new(), |p| cell(p, PROMPT_IN_REPORT));
            let mut loaded = format!("{}/{}", t.loaded, t.runs);
            if t.errors > 0 {
                loaded.push_str(&format!(" ({} failed)", t.errors));
            }
            let mark = if t.runs > 0 && (t.loaded * 2 > t.runs) != t.should_trigger {
                " ✗"
            } else {
                ""
            };
            out.push_str(&format!(
                "| {n} | {} | {loaded}{mark} | {prompt} |\n",
                if t.should_trigger { "yes" } else { "no" }
            ));
        }
        let c = &s.confusion;
        out.push_str(&format!(
            "\nPrecision {}: {} of {} loads were wanted. Recall {}: {} of {} wanted loads happened.\n",
            percent(s.precision),
            c.hits,
            c.hits + c.false_loads,
            percent(s.recall),
            c.hits,
            c.hits + c.misses
        ));
        match s.precision {
            Some(p) if p < PRECISION_TARGET => out.push_str(&format!(
                "Precision is below the {:.0}% target (mezha-plan.md section 7): the description pulls the skill into prompts it doesn't fit.\n",
                PRECISION_TARGET * 100.0
            )),
            None if c.hits + c.misses > 0 => out.push_str(
                "The skill never loaded, so precision can't be measured: it is listed, but its description doesn't match these prompts.\n",
            ),
            _ => {}
        }
        out.push('\n');
    }
    if !s.tasks.is_empty() {
        out.push_str(&format!(
            "## Tasks\n\n{} task(s) × {} repeat(s), each run with the skill and without it.\n\n",
            s.tasks.len(),
            s.repeat
        ));
        out.push_str("| Task | With the skill | Without | Passed only with | Passed only without |\n|---|---|---|---|---|\n");
        let arm = |a: &ArmStats| {
            format!(
                "{}/{} passed, ${:.2}, {:.1} turns",
                a.passed,
                a.runs,
                a.cost_usd,
                a.turns as f64 / f64::from(a.runs.max(1))
            )
        };
        for (name, t) in &s.tasks {
            out.push_str(&format!(
                "| {name} | {}, loaded {}/{} | {} | {} | {} |\n",
                arm(&t.with),
                t.with.loaded,
                t.with.runs,
                arm(&t.without),
                t.with_only,
                t.without_only
            ));
        }
        out.push_str(&format!(
            "| **All** | {}, loaded {}/{} | {} | | |\n\n",
            arm(&s.with),
            s.with.loaded,
            s.with.runs,
            arm(&s.without)
        ));
        if s.with.runs > 0 && s.with.loaded < s.with.runs {
            out.push_str(&format!(
                "Claude didn't load the skill in {} of {} runs that had it; those runs say nothing about the skill's content.\n",
                s.with.runs - s.with.loaded,
                s.with.runs
            ));
        }
        if s.too_few {
            out.push_str(&format!(
                "Not enough runs to claim a difference: use `--repeat {MIN_REPEAT_FOR_CLAIMS}` or more.\n"
            ));
        } else {
            out.push_str("Small samples are noisy: a difference of one or two passes may be chance. The columns of passes in only one arm are the ones to read.\n");
        }
        out.push('\n');
    }
    if s.loaded_runs > 0 {
        out.push_str("## Manifest\n\n");
        if s.undeclared.is_empty() {
            out.push_str("While the skill was loaded, Claude called only tools its `allowed_tools` declares.\n\n");
        } else {
            let list: Vec<String> = s
                .undeclared
                .iter()
                .map(|(tool, runs)| {
                    let outside = if reaches_outside(tool) { " ✗" } else { "" };
                    format!("{tool}{outside} ({runs} of {} runs)", s.loaded_runs)
                })
                .collect();
            out.push_str(&format!(
                "While the skill was loaded, Claude called tools its `allowed_tools` doesn't declare: {}. Declare what the skill needs, or find out why it reached for the rest; ✗ marks tools that reach outside the sandbox (OWASP AST03, AST04).\n\n",
                list.join(", ")
            ));
        }
    }
    out.push_str(&format!("Cost: ${:.2}.\n", s.cost_usd));
    out
}

/// Tools that reach outside the sandbox.
pub fn reaches_outside(tool: &str) -> bool {
    matches!(tool, "WebFetch" | "WebSearch") || tool.starts_with("mcp__")
}

/// A percentage, or "n/a".
pub fn percent(v: Option<f64>) -> String {
    v.map_or("n/a".into(), |v| format!("{:.0}%", v * 100.0))
}

/// Text for one Markdown table cell: one line, no pipes, cut to `max`
/// characters.
fn cell(text: &str, max: usize) -> String {
    let flat: String = text
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .chars()
        .filter(|c| !c.is_control())
        .collect();
    let mut out: String = flat.chars().take(max).collect();
    if flat.chars().count() > max {
        out.push('…');
    }
    out.replace('|', "\\|")
}

#[cfg(test)]
mod tests {
    use super::*;

    const SPEC: &str = r#"
[project]
name = "evals"
[policy]
permissions_ask = ["git push"]
[skill.rust-conventions]
preset = "knowledge"
description = "Error handling and test conventions for this workspace. Use when writing Rust."
[skill.release]
preset = "command"
description = "Cut a release."
"#;

    const GOOD: &str = r#"
[[trigger]]
prompt = "Add an error variant"
should_trigger = true
[[trigger]]
prompt = "What's in the README?"
should_trigger = false
[[task]]
name = "timeout"
prompt = "Add a timeout error."
expect = ["Timeout"]
"#;

    fn errors(text: &str, skill: &str) -> Vec<String> {
        let spec = mezha_spec::parse(SPEC).unwrap();
        validate(&parse(text).unwrap(), &spec, skill)
    }

    #[test]
    fn case_files() {
        assert!(errors(GOOD, "rust-conventions").is_empty());
        let all = errors(
            r#"
[eval]
budget_usd = 0
model = "--x"
trigger_turns = 0
[[trigger]]
prompt = "a"
should_trigger = true
[[trigger]]
prompt = " a"
should_trigger = true
[[task]]
name = "Bad Name"
prompt = " "
check = ""
expect = ["("]
[[task]]
name = "t"
prompt = "p"
[[task]]
name = "t"
prompt = "p"
"#,
            "rust-conventions",
        )
        .join("\n");
        for want in [
            "eval.model",
            "eval.budget_usd",
            "eval.trigger_turns",
            "listed twice",
            "with false",
            "task Bad Name:",
            "prompt is empty",
            "check is empty",
            "expect `(`",
            "used twice",
        ] {
            assert!(all.contains(want), "{want}: {all}");
        }
        assert!(errors(GOOD, "release")[0].contains("command skill"));
        assert!(errors(GOOD, "nobody")[0].contains("no skill.nobody"));
        assert!(errors("", "rust-conventions")[0].contains("no [[trigger]] or [[task]]"));
        assert!(parse("[eval]\npermission_mode = \"bypassPermissions\"\n").is_err());
    }

    #[test]
    fn settings_fall_back_to_the_defaults() {
        let s = Settings::default();
        assert_eq!(
            (
                s.budget_usd(),
                s.max_turns(),
                s.trigger_turns(),
                s.timeout_minutes()
            ),
            (
                DEFAULT_BUDGET_USD,
                DEFAULT_MAX_TURNS,
                DEFAULT_TRIGGER_TURNS,
                DEFAULT_TIMEOUT_MINUTES
            )
        );
        let s = parse(
            "[eval]\nbudget_usd = 2.5\nmax_turns = 12\ntrigger_turns = 2\ntimeout_minutes = 9\n",
        )
        .unwrap()
        .eval;
        assert_eq!(
            (
                s.budget_usd(),
                s.max_turns(),
                s.trigger_turns(),
                s.timeout_minutes()
            ),
            (2.5, 12, 2, 9)
        );
    }

    #[test]
    fn limits_on_turns_timeouts_and_empty_prompts() {
        let all = errors(
            "[eval]\nmodel = \"a b\"\nmax_turns = 201\ntimeout_minutes = 0\n\
             [[trigger]]\nprompt = \" \"\nshould_trigger = true\n\
             [[trigger]]\nprompt = \"b\"\nshould_trigger = false\n",
            "rust-conventions",
        );
        assert_eq!(
            all,
            [
                "eval.model `a b` is not a model name",
                "eval.max_turns must be between 1 and 200",
                "eval.timeout_minutes must be between 1 and 240",
                "trigger 1: the prompt is empty"
            ]
        );
    }

    #[test]
    fn messages_against_patterns() {
        let file = parse(
            "[[task]]\nname = \"t\"\nprompt = \"p\"\nexpect = [\"(?i)timeout\", \"test\"]\nreject = [\"unwrap\\\\(\\\\)\"]\n",
        )
        .unwrap();
        let task = &file.task[0];
        assert_eq!(task.judge_message("Added Timeout and a test."), Some(true));
        assert_eq!(task.judge_message("Added Timeout."), Some(false));
        assert_eq!(
            task.judge_message("Timeout, test, and x.unwrap() here"),
            Some(false)
        );
        let plain = parse("[[task]]\nname = \"t\"\nprompt = \"p\"\n").unwrap();
        assert_eq!(plain.task[0].judge_message("anything"), None);
    }

    #[test]
    fn order() {
        let order = run_order(2, 2, 2);
        assert_eq!(order.len(), 2 * 2 + 2 * 2 * 2);
        assert_eq!(
            order[0],
            Run::Trigger {
                index: 0,
                repeat: 0
            }
        );
        assert_eq!(
            order[3],
            Run::Trigger {
                index: 1,
                repeat: 1
            }
        );
        let first: Vec<Arm> = order[4..]
            .chunks(2)
            .map(|p| match p[0] {
                Run::Task { arm, .. } => arm,
                Run::Trigger { .. } => unreachable!(),
            })
            .collect();
        assert_eq!(first, [Arm::With, Arm::Without, Arm::Without, Arm::With]);
    }

    fn row(kind: Kind, case: &str, arm: Arm, repeat: u32) -> EvalRow {
        EvalRow {
            v: 1,
            id: format!("s/x/{case}/{}/{repeat}", arm.as_str()),
            stamp: "s".into(),
            skill: "x".into(),
            kind,
            case: case.into(),
            prompt_sha: "0".repeat(16),
            arm,
            repeat,
            should_trigger: None,
            loaded: false,
            load_turn: None,
            passed: None,
            is_error: false,
            subtype: "success".into(),
            cost_usd: 0.25,
            turns: 2,
            duration_ms: 1000,
            claude_code: "2.1.285".into(),
            failure: None,
            skill_sha: None,
            model: None,
            tools_used: Vec::new(),
            undeclared_tools: Vec::new(),
        }
    }

    fn trigger(n: u32, should: bool, loaded: bool) -> EvalRow {
        EvalRow {
            should_trigger: Some(should),
            loaded,
            ..row(Kind::Trigger, &format!("trigger-{n}"), Arm::With, 0)
        }
    }

    #[test]
    fn precision_and_recall() {
        let mut failed = trigger(4, true, false);
        failed.is_error = true;
        let rows = [
            trigger(1, true, true),
            trigger(2, true, false),
            trigger(3, false, true),
            trigger(10, false, false),
            failed,
        ];
        let s = summarize(&rows);
        assert_eq!(
            s.confusion,
            Confusion {
                hits: 1,
                false_loads: 1,
                misses: 1,
                quiet: 1
            }
        );
        assert_eq!((s.precision, s.recall), (Some(0.5), Some(0.5)));
        let cases: Vec<&str> = s.triggers.iter().map(|t| t.case.as_str()).collect();
        assert_eq!(
            cases,
            [
                "trigger-1",
                "trigger-2",
                "trigger-3",
                "trigger-4",
                "trigger-10"
            ]
        );
        assert_eq!(s.triggers[3].errors, 1);
        assert_eq!(s.triggers[3].runs, 0);

        let prompts: Vec<String> = (1..=10).map(|n| format!("prompt | {n}")).collect();
        let md = markdown(&s, &prompts, 4);
        assert!(md.contains("| 3 | no | 1/1 ✗ | prompt \\| 3 |"), "{md}");
        assert!(md.contains("| 4 | yes | 0/0 (1 failed) |"), "{md}");
        assert!(
            md.contains("Precision 50%: 1 of 2 loads were wanted"),
            "{md}"
        );
        assert!(md.contains("below the 80% target"), "{md}");
        assert!(!md.contains("## Tasks"), "{md}");

        let never = summarize(&[trigger(1, true, false), trigger(2, false, false)]);
        assert_eq!(never.precision, None);
        assert!(markdown(&never, &prompts, 4).contains("never loaded"));
    }

    #[test]
    fn arms() {
        let pass = |mut r: EvalRow, passed: bool, loaded: bool| {
            r.passed = Some(passed);
            r.loaded = loaded;
            r
        };
        let rows = [
            pass(row(Kind::Task, "a", Arm::With, 0), true, true),
            pass(row(Kind::Task, "a", Arm::Without, 0), false, false),
            pass(row(Kind::Task, "a", Arm::With, 1), true, false),
            pass(row(Kind::Task, "a", Arm::Without, 1), true, false),
        ];
        let s = summarize(&rows);
        assert_eq!((s.with.passed, s.without.passed), (2, 1));
        assert_eq!((s.tasks["a"].with_only, s.tasks["a"].without_only), (1, 0));
        assert_eq!(s.with.loaded, 1);
        assert!(s.too_few);
        assert_eq!(s.cost_usd, 1.0);
        let md = markdown(&s, &[], 4);
        assert!(
            md.contains("| a | 2/2 passed, $0.50, 2.0 turns, loaded 1/2 | 1/2 passed"),
            "{md}"
        );
        assert!(md.contains("didn't load the skill in 1 of 2 runs"), "{md}");
        assert!(md.contains("Not enough runs"), "{md}");
        assert!(!md.contains("## Triggers"), "{md}");
    }

    #[test]
    fn undeclared_tools_and_enough_repeats() {
        let rows: Vec<EvalRow> = (0..MIN_REPEAT_FOR_CLAIMS)
            .flat_map(|r| {
                let mut with = row(Kind::Task, "a", Arm::With, r);
                with.passed = Some(false);
                with.loaded = true;
                with.undeclared_tools = vec!["WebFetch".into(), "Bash outside its scopes".into()];
                let mut without = row(Kind::Task, "a", Arm::Without, r);
                without.passed = Some(true);
                [with, without]
            })
            .collect();
        let s = summarize(&rows);
        assert!(!s.too_few);
        assert_eq!(
            (s.tasks["a"].with_only, s.tasks["a"].without_only),
            (0, MIN_REPEAT_FOR_CLAIMS)
        );
        assert_eq!(s.loaded_runs, MIN_REPEAT_FOR_CLAIMS);
        assert_eq!(
            s.undeclared,
            BTreeMap::from([
                ("Bash outside its scopes".to_string(), 3),
                ("WebFetch".to_string(), 3)
            ])
        );
        let md = markdown(&s, &[], 4);
        assert!(md.contains("Small samples are noisy"), "{md}");
        assert!(!md.contains("Not enough runs"), "{md}");
        assert!(
            md.contains(
                "doesn't declare: Bash outside its scopes (3 of 3 runs), WebFetch ✗ (3 of 3 runs). "
            ),
            "{md}"
        );
        assert!(md.ends_with("Cost: $1.50.\n"), "{md}");
    }

    #[test]
    fn precision_at_the_target_needs_no_remark() {
        let s = summarize(&[trigger(1, true, true), trigger(2, false, false)]);
        assert_eq!((s.precision, s.recall), (Some(1.0), Some(1.0)));
        let md = markdown(&s, &["a".into(), "b".into()], 4);
        assert!(
            md.contains(
                "Precision 100%: 1 of 1 loads were wanted. Recall 100%: 1 of 1 wanted loads happened.\n\n"
            ),
            "{md}"
        );
        assert!(!md.contains("below the"), "{md}");
        assert!(!md.contains("never loaded"), "{md}");
        assert!(
            md.contains("called only tools its `allowed_tools` declares"),
            "{md}"
        );
    }

    #[test]
    fn tools_that_reach_outside_the_sandbox() {
        assert!(reaches_outside("WebFetch"));
        assert!(reaches_outside("WebSearch"));
        assert!(reaches_outside("mcp__github__create_issue"));
        assert!(!reaches_outside("Bash"));
        assert!(!reaches_outside("Read"));
    }

    #[test]
    fn cells() {
        assert_eq!(cell("a\n|b\tc", 10), "a \\|b c");
        assert_eq!(cell("abcdef", 3), "abc…");
    }
}
