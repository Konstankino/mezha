//! The A/B runner's task file, run order and report. Each task runs as its
//! agent twice per repeat: once with the project's agent memory and once
//! with that memory emptied, in otherwise identical worktrees. A `check`
//! command decides whether a run passed.

use std::collections::{BTreeMap, BTreeSet};

use mezha_spec::{Scope, Spec, check_name};
use serde::{Deserialize, Serialize};

pub const DEFAULT_BUDGET_USD: f64 = 2.0;
pub const DEFAULT_MAX_TURNS: u32 = 40;
pub const DEFAULT_TIMEOUT_MINUTES: u32 = 20;
/// Below this many repeats the report claims no difference.
pub const MIN_REPEAT_FOR_CLAIMS: u32 = 3;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskFile {
    #[serde(default)]
    pub ab: Settings,
    #[serde(default)]
    pub task: Vec<Task>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Settings {
    pub model: Option<String>,
    pub budget_usd: Option<f64>,
    pub max_turns: Option<u32>,
    pub timeout_minutes: Option<u32>,
}

impl Settings {
    pub fn budget_usd(&self) -> f64 {
        self.budget_usd.unwrap_or(DEFAULT_BUDGET_USD)
    }

    pub fn max_turns(&self) -> u32 {
        self.max_turns.unwrap_or(DEFAULT_MAX_TURNS)
    }

    pub fn timeout_minutes(&self) -> u32 {
        self.timeout_minutes.unwrap_or(DEFAULT_TIMEOUT_MINUTES)
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Task {
    pub name: String,
    pub prompt: String,
    /// The spec agent the task runs as.
    pub agent: String,
    /// A command whose exit 0 means the run passed.
    pub check: Option<String>,
}

pub fn parse(text: &str) -> Result<TaskFile, String> {
    toml::from_str(text).map_err(|e| e.to_string())
}

/// Everything wrong with the task file for this spec.
pub fn validate(file: &TaskFile, spec: &Spec) -> Vec<String> {
    let mut errors = Vec::new();
    let ab = &file.ab;
    if let Some(model) = &ab.model
        && (model.is_empty()
            || model.starts_with('-')
            || model.chars().any(|c| c.is_whitespace() || c.is_control()))
    {
        errors.push(format!(
            "ab.model `{}` is not a model name",
            model.escape_debug()
        ));
    }
    if let Some(b) = ab.budget_usd
        && !(b.is_finite() && b > 0.0 && b <= 50.0)
    {
        errors.push("ab.budget_usd must be more than 0 and at most 50".into());
    }
    if ab.max_turns.is_some_and(|t| !(1..=200).contains(&t)) {
        errors.push("ab.max_turns must be between 1 and 200".into());
    }
    if ab.timeout_minutes.is_some_and(|t| !(1..=240).contains(&t)) {
        errors.push("ab.timeout_minutes must be between 1 and 240".into());
    }
    if file.task.is_empty() {
        errors.push("there are no [[task]] entries".into());
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
        let Some(agent) = spec.agent.get(&task.agent) else {
            errors.push(format!(
                "{at}: there is no agent.{} in mezha.toml",
                task.agent
            ));
            continue;
        };
        let phi = spec.is_phi(agent);
        match spec.memory_scope(agent) {
            None => errors.push(format!(
                "{at}: agent.{} has no memory, so there is nothing to compare",
                task.agent
            )),
            Some(Scope::User) => errors.push(format!(
                "{at}: agent.{} has user memory, which every project shares and a run can't empty",
                task.agent
            )),
            Some(_) if phi => errors.push(format!(
                "{at}: agent.{} keeps PHI, and mezha never copies PHI memory into a test run",
                task.agent
            )),
            Some(_) => {}
        }
    }
    errors
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Variant {
    Memory,
    Empty,
}

impl Variant {
    pub fn as_str(self) -> &'static str {
        match self {
            Variant::Memory => "memory",
            Variant::Empty => "empty",
        }
    }
}

/// The runs in order: every task and repeat, both variants, with the order
/// of the two alternating so neither always goes first (warm caches, a
/// changing service).
pub fn run_order(tasks: usize, repeat: u32) -> Vec<(usize, u32, Variant)> {
    let mut order = Vec::new();
    for r in 0..repeat {
        for t in 0..tasks {
            let pair = if (t + r as usize).is_multiple_of(2) {
                [Variant::Memory, Variant::Empty]
            } else {
                [Variant::Empty, Variant::Memory]
            };
            order.extend(pair.map(|v| (t, r, v)));
        }
    }
    order
}

/// One run's result, as stored in `ab.jsonl`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AbRow {
    pub v: u64,
    /// `<stamp>/<task>/<variant>/<repeat>`.
    pub id: String,
    pub stamp: String,
    pub task: String,
    pub variant: Variant,
    pub repeat: u32,
    /// The check's verdict; without a check, whether the session succeeded.
    pub passed: bool,
    pub is_error: bool,
    pub subtype: String,
    pub cost_usd: f64,
    pub turns: u64,
    pub duration_ms: u64,
    pub claude_code: String,
    pub failure: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct VariantStats {
    pub runs: u32,
    pub passed: u32,
    pub cost_usd: f64,
    pub turns: u64,
}

impl VariantStats {
    fn add(&mut self, row: &AbRow) {
        self.runs += 1;
        self.passed += u32::from(row.passed);
        self.cost_usd += row.cost_usd;
        self.turns += row.turns;
    }
}

#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct TaskStats {
    pub memory: VariantStats,
    pub empty: VariantStats,
    /// Repeats that passed with memory only, and without memory only.
    pub memory_only: u32,
    pub empty_only: u32,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct Summary {
    pub stamp: String,
    pub tasks: BTreeMap<String, TaskStats>,
    pub memory: VariantStats,
    pub empty: VariantStats,
    pub repeat: u32,
    /// Fewer repeats than [`MIN_REPEAT_FOR_CLAIMS`].
    pub too_few: bool,
}

/// The summary of one A/B run (rows with the same stamp).
pub fn summarize(rows: &[AbRow]) -> Summary {
    let mut s = Summary {
        stamp: rows.first().map(|r| r.stamp.clone()).unwrap_or_default(),
        ..Summary::default()
    };
    let mut pairs: BTreeMap<(String, u32), [Option<bool>; 2]> = BTreeMap::new();
    for row in rows {
        let task = s.tasks.entry(row.task.clone()).or_default();
        let slot = match row.variant {
            Variant::Memory => {
                task.memory.add(row);
                s.memory.add(row);
                0
            }
            Variant::Empty => {
                task.empty.add(row);
                s.empty.add(row);
                1
            }
        };
        pairs.entry((row.task.clone(), row.repeat)).or_default()[slot] = Some(row.passed);
        s.repeat = s.repeat.max(row.repeat + 1);
    }
    for ((task, _), pair) in pairs {
        let stats = s.tasks.entry(task).or_default();
        match pair {
            [Some(true), Some(false)] => stats.memory_only += 1,
            [Some(false), Some(true)] => stats.empty_only += 1,
            _ => {}
        }
    }
    s.too_few = s.repeat < MIN_REPEAT_FOR_CLAIMS;
    s
}

/// The summary as Markdown, for `report.md`.
pub fn markdown(s: &Summary) -> String {
    let mut out = format!(
        "# A/B {}\n\n{} task(s) × {} repeat(s), each run with the agent's memory and with it emptied.\n\n",
        s.stamp,
        s.tasks.len(),
        s.repeat
    );
    out.push_str("| Task | With memory | Without | Passed only with | Passed only without |\n|---|---|---|---|---|\n");
    let cell = |v: &VariantStats| {
        format!(
            "{}/{} passed, ${:.2}, {:.1} turns",
            v.passed,
            v.runs,
            v.cost_usd,
            v.turns as f64 / f64::from(v.runs.max(1))
        )
    };
    for (name, t) in &s.tasks {
        out.push_str(&format!(
            "| {name} | {} | {} | {} | {} |\n",
            cell(&t.memory),
            cell(&t.empty),
            t.memory_only,
            t.empty_only
        ));
    }
    out.push_str(&format!(
        "| **All** | {} | {} | | |\n\n",
        cell(&s.memory),
        cell(&s.empty)
    ));
    if s.too_few {
        out.push_str(&format!(
            "Not enough runs to claim a difference: use `--repeat {MIN_REPEAT_FOR_CLAIMS}` or more.\n"
        ));
    } else {
        out.push_str("Small samples are noisy: a difference of one or two passes may be chance. The columns of passes in only one variant are the ones to read.\n");
    }
    out.push_str("\nBoth variants share user-scope memory, CLAUDE.md and the model; auto memory is off in both.\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const SPEC: &str = r#"
[project]
name = "ab"
[policy]
permissions_ask = ["git push"]
[agent.implementer]
description = "x"
tools = ["Read"]
rule_of_two = []
memory = {}
[agent.global]
description = "x"
tools = ["Read"]
rule_of_two = []
memory = { scope = "user" }
[agent.clinician]
description = "x"
tools = ["Read"]
rule_of_two = []
memory = { class = "phi" }
[agent.plain]
description = "x"
tools = ["Read"]
rule_of_two = []
"#;

    fn errors(text: &str) -> Vec<String> {
        let spec = mezha_spec::parse(SPEC).unwrap();
        validate(&parse(text).unwrap(), &spec)
    }

    #[test]
    fn task_files() {
        assert!(
            errors("[[task]]\nname = \"t\"\nprompt = \"p\"\nagent = \"implementer\"\n").is_empty()
        );
        let all = errors(
            r#"
[ab]
budget_usd = 0
model = "--x"
[[task]]
name = "Bad Name"
prompt = " "
agent = "global"
[[task]]
name = "t"
prompt = "p"
agent = "clinician"
[[task]]
name = "t"
prompt = "p"
agent = "plain"
check = ""
[[task]]
name = "u"
prompt = "p"
agent = "nobody"
"#,
        )
        .join("\n");
        for want in [
            "ab.model",
            "ab.budget_usd",
            "task Bad Name:",
            "prompt is empty",
            "user memory",
            "keeps PHI",
            "used twice",
            "has no memory",
            "check is empty",
            "no agent.nobody",
        ] {
            assert!(all.contains(want), "{want}: {all}");
        }
        assert!(parse("[ab]\npermission_mode = \"bypassPermissions\"\n").is_err());
        assert!(errors("").iter().any(|e| e.contains("no [[task]]")));
    }

    #[test]
    fn order_alternates() {
        let order = run_order(2, 2);
        let first: Vec<Variant> = order.chunks(2).map(|p| p[0].2).collect();
        assert_eq!(
            first,
            [
                Variant::Memory,
                Variant::Empty,
                Variant::Empty,
                Variant::Memory
            ]
        );
        assert_eq!(order.len(), 8);
    }

    fn row(task: &str, variant: Variant, repeat: u32, passed: bool) -> AbRow {
        AbRow {
            v: 1,
            id: format!("s/{task}/{}/{repeat}", variant.as_str()),
            stamp: "s".into(),
            task: task.into(),
            variant,
            repeat,
            passed,
            is_error: false,
            subtype: "success".into(),
            cost_usd: 0.5,
            turns: 4,
            duration_ms: 1000,
            claude_code: "2.1.285".into(),
            failure: None,
        }
    }

    #[test]
    fn summaries() {
        let rows = [
            row("a", Variant::Memory, 0, true),
            row("a", Variant::Empty, 0, false),
            row("a", Variant::Memory, 1, true),
            row("a", Variant::Empty, 1, true),
        ];
        let s = summarize(&rows);
        assert_eq!((s.memory.passed, s.empty.passed), (2, 1));
        assert_eq!(s.tasks["a"].memory_only, 1);
        assert_eq!(s.tasks["a"].empty_only, 0);
        assert!(s.too_few);
        let md = markdown(&s);
        assert!(
            md.contains("| a | 2/2 passed, $1.00, 4.0 turns | 1/2 passed"),
            "{md}"
        );
        assert!(md.contains("Not enough runs"), "{md}");
    }
}
