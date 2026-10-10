//! The typed spec. Every table rejects unknown keys: in a governance file a
//! typo such as `rule_of_tow` must fail, not silently drop a property.

use std::collections::BTreeMap;

use serde::Deserialize;

use crate::{CommandPrefix, HostPattern};

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Spec {
    /// Schema version; absent means 1.
    pub schema: Option<u32>,
    pub project: Project,
    #[serde(default)]
    pub policy: Policy,
    #[serde(default)]
    pub memory: Memory,
    #[serde(default)]
    pub agent: BTreeMap<String, Agent>,
    #[serde(default)]
    pub skill: BTreeMap<String, Skill>,
    #[serde(default)]
    pub rule: BTreeMap<String, Rule>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Project {
    pub name: String,
    #[serde(default)]
    pub os_mode: OsMode,
    /// The project's check command, such as `cargo test --workspace`.
    pub check: Option<String>,
    pub languages: Option<Languages>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum OsMode {
    /// macOS, Linux and WSL2: the sandbox is available.
    #[default]
    Full,
    /// Native Windows: no sandbox, so every gate is advisory.
    NativeWindows,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Languages {
    /// Language of agent instructions and briefs.
    pub instructions: String,
    /// Language Claude answers the user in.
    pub answers: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Policy {
    pub sandbox: bool,
    /// Hosts sandboxed commands may reach.
    pub egress_allow: Vec<String>,
    /// Command prefixes that need a permission prompt and an active
    /// `mezha approve`, such as `git push`.
    pub permissions_ask: Vec<String>,
    /// Paths agents may not read (gitignore patterns, as in `Read(...)` rules).
    pub deny_reads: Vec<String>,
    /// Skills from outside the repository a person has reviewed: personal
    /// skills by name, plugin skills as `plugin:skill`, each optionally
    /// pinned to the fingerprint verify reports (`name@sha256:<hex>`). An
    /// agent may preload only these and the spec's own; verify warns about
    /// any other that loads, and fails when a pinned one changes (OWASP
    /// AST01, AST07, AST09).
    pub external_skills: Vec<String>,
    /// Hosts the WebFetch tool may reach, as patterns like `egress_allow`'s;
    /// `[]` for none. Absent leaves WebFetch unrestricted (OWASP AST05).
    pub fetch_allow: Option<Vec<String>>,
}

impl Policy {
    /// The reviewed external skills, as (name, pinned fingerprint).
    pub fn external(&self) -> impl Iterator<Item = (&str, Option<&str>)> {
        self.external_skills
            .iter()
            .map(|entry| match entry.split_once('@') {
                Some((name, pin)) => (name, Some(pin)),
                None => (entry.as_str(), None),
            })
    }

    /// Whether `name` is a reviewed external skill.
    pub fn lists_external(&self, name: &str) -> bool {
        self.external().any(|(n, _)| n == name)
    }
}

impl Default for Policy {
    fn default() -> Self {
        Policy {
            sandbox: true,
            egress_allow: Vec::new(),
            permissions_ask: Vec::new(),
            deny_reads: Vec::new(),
            external_skills: Vec::new(),
            fetch_allow: None,
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Memory {
    pub dream_schedule: DreamSchedule,
    pub default_scope: Scope,
    /// Repositories that hold PHI: their agent memory is local only.
    pub phi_repos: Vec<String>,
    /// The model `mezha dream` runs the dreamer on.
    pub dream_model: Option<String>,
    /// The most one role's dream may cost, in US dollars.
    pub dream_budget_usd: Option<f64>,
    /// The most turns one role's dream may take.
    pub dream_max_turns: Option<u32>,
    /// `HH:MM` local time for `dream_schedule = "nightly"`.
    pub dream_at: Option<String>,
    /// A five-field cron expression for `dream_schedule = "cron"`.
    pub dream_cron: Option<String>,
    /// Whether sessions may write Claude Code's auto memory.
    pub auto_memory: AutoMemory,
}

/// Claude Code's auto memory (`~/.claude/projects/<project>/memory/`) loads
/// into every session of the project and its worktrees, so a write to it
/// persists like an instruction (OWASP AST01, "memory poisoning").
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AutoMemory {
    /// Sessions read it but may not write it.
    #[default]
    ReadOnly,
    /// Sessions write it without review, as Claude Code does by default.
    Writable,
}

pub const DEFAULT_DREAM_MODEL: &str = "sonnet";
pub const DEFAULT_DREAM_BUDGET_USD: f64 = 1.0;
pub const DEFAULT_DREAM_MAX_TURNS: u32 = 40;

impl Memory {
    pub fn dream_model(&self) -> &str {
        self.dream_model.as_deref().unwrap_or(DEFAULT_DREAM_MODEL)
    }

    pub fn dream_budget_usd(&self) -> f64 {
        self.dream_budget_usd.unwrap_or(DEFAULT_DREAM_BUDGET_USD)
    }

    pub fn dream_max_turns(&self) -> u32 {
        self.dream_max_turns.unwrap_or(DEFAULT_DREAM_MAX_TURNS)
    }

    /// When a nightly dream runs: `dream_at`, else 03:00. An invalid
    /// `dream_at` is a validation error, so this falls back quietly.
    pub fn dream_at(&self) -> (u8, u8) {
        self.dream_at
            .as_deref()
            .and_then(|t| crate::cron::parse_time(t).ok())
            .unwrap_or((3, 0))
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DreamSchedule {
    Nightly,
    #[default]
    Manual,
    Cron,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Scope {
    /// Committed with the project.
    #[default]
    Project,
    /// This machine and project only, never committed.
    Local,
    /// Shared by every project of this user.
    User,
}

impl Scope {
    /// The value Claude Code's agent `memory` field takes.
    pub fn as_str(self) -> &'static str {
        match self {
            Scope::Project => "project",
            Scope::Local => "local",
            Scope::User => "user",
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Agent {
    /// When Claude should delegate to the agent. Required for rendering.
    pub description: Option<String>,
    /// The Markdown body, relative to the project; absent means
    /// `mezha/agents/<name>.md`.
    pub prompt_file: Option<String>,
    pub model: Option<String>,
    pub effort: Option<Effort>,
    /// Absent: the agent inherits every tool. `[]`: no tools at all.
    pub tools: Option<Vec<String>>,
    #[serde(default)]
    pub disallowed_tools: Vec<String>,
    #[serde(default)]
    pub skills: Vec<String>,
    /// Which of the three Rule of Two properties the agent has. Required, so
    /// nobody gets all three by forgetting to say; `[]` is allowed.
    pub rule_of_two: Option<Vec<Capability>>,
    pub human_gate: Option<HumanGate>,
    pub memory: Option<AgentMemory>,
    pub max_turns: Option<u32>,
}

/// The properties of the Agents Rule of Two: an agent should have at most two.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    /// Processes input an attacker can influence (web pages, issues, email).
    UntrustedInput,
    /// Can read private data or sensitive systems.
    PrivateData,
    /// Can change state or communicate outside (push, publish, send).
    ExternalAction,
}

impl Capability {
    pub const ALL: [Capability; 3] = [
        Capability::UntrustedInput,
        Capability::PrivateData,
        Capability::ExternalAction,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Capability::UntrustedInput => "untrusted_input",
            Capability::PrivateData => "private_data",
            Capability::ExternalAction => "external_action",
        }
    }
}

/// The only accepted gate for an agent with all three properties, and its
/// name says what it is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HumanGate {
    Advisory,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Effort {
    Low,
    Medium,
    High,
    Xhigh,
    Max,
}

impl Effort {
    pub fn as_str(self) -> &'static str {
        match self {
            Effort::Low => "low",
            Effort::Medium => "medium",
            Effort::High => "high",
            Effort::Xhigh => "xhigh",
            Effort::Max => "max",
        }
    }
}

/// Where the bodies of agents, skills and rules live by default.
pub const BODY_DIR: &str = "mezha";

impl Agent {
    /// The agent's prompt file, relative to the project.
    pub fn prompt_path(&self, name: &str) -> String {
        self.prompt_file
            .clone()
            .unwrap_or_else(|| format!("{BODY_DIR}/agents/{name}.md"))
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentMemory {
    /// Absent means `[memory] default_scope` (or `local` for PHI).
    pub scope: Option<Scope>,
    pub class: Option<MemoryClass>,
    /// What the dreamer keeps in this role's memory; absent means `lessons`.
    pub dream_policy: Option<DreamPolicy>,
}

/// What the dreamer keeps in a role's memory (`mezha-plan.md` section 3.6).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DreamPolicy {
    /// "Avoid X because Y (seen N times)": lessons from what went wrong.
    #[default]
    Lessons,
    /// Only facts checked against the code, with `file:line`.
    VerifiedFacts,
    /// Only attack patterns that found real bugs; never "this can be skipped".
    AttackPatternsOnly,
}

impl DreamPolicy {
    pub fn as_str(self) -> &'static str {
        match self {
            DreamPolicy::Lessons => "lessons",
            DreamPolicy::VerifiedFacts => "verified-facts",
            DreamPolicy::AttackPatternsOnly => "attack-patterns-only",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MemoryClass {
    Phi,
    NoPhi,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Skill {
    pub preset: Preset,
    pub description: String,
    pub when_to_use: Option<String>,
    #[serde(default)]
    pub paths: Vec<String>,
    pub user_invocable: Option<bool>,
    #[serde(default)]
    pub arguments: Vec<String>,
    #[serde(default)]
    pub allowed_tools: Vec<String>,
    /// The Markdown body; absent means `mezha/skills/<name>.md`.
    pub body_file: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Preset {
    /// Background knowledge Claude loads when relevant.
    Knowledge,
    /// A command the user runs with `/name`.
    Command,
}

impl Skill {
    /// Command skills run only when the user asks for them.
    pub fn disable_model_invocation(&self) -> bool {
        self.preset == Preset::Command
    }

    /// Knowledge skills stay out of the `/` menu unless the spec says otherwise.
    pub fn user_invocable(&self) -> bool {
        self.user_invocable
            .unwrap_or(self.preset == Preset::Command)
    }

    /// The skill's body file, relative to the project.
    pub fn body_path(&self, name: &str) -> String {
        self.body_file
            .clone()
            .unwrap_or_else(|| format!("{BODY_DIR}/skills/{name}.md"))
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    #[serde(default)]
    pub paths: Vec<String>,
    pub max_lines: Option<u32>,
    /// The Markdown body; absent means `mezha/rules/<name>.md`.
    pub body_file: Option<String>,
}

impl Rule {
    /// The rule's body file, relative to the project.
    pub fn body_path(&self, name: &str) -> String {
        self.body_file
            .clone()
            .unwrap_or_else(|| format!("{BODY_DIR}/rules/{name}.md"))
    }
}

impl Spec {
    /// True when this repository is listed in `[memory] phi_repos`.
    pub fn is_phi_repo(&self) -> bool {
        self.memory
            .phi_repos
            .iter()
            .any(|r| r.trim().eq_ignore_ascii_case(self.project.name.trim()))
    }

    /// True when the agent's memory holds PHI, by its class or by the repo.
    pub fn is_phi(&self, agent: &Agent) -> bool {
        self.is_phi_repo()
            || agent
                .memory
                .as_ref()
                .is_some_and(|m| m.class == Some(MemoryClass::Phi))
    }

    /// The agent's effective memory scope: PHI memory is always local.
    pub fn memory_scope(&self, agent: &Agent) -> Option<Scope> {
        let memory = agent.memory.as_ref()?;
        if self.is_phi(agent) {
            return Some(Scope::Local);
        }
        Some(memory.scope.unwrap_or(self.memory.default_scope))
    }

    /// True when any memory in this spec holds PHI.
    pub fn has_phi(&self) -> bool {
        self.is_phi_repo()
            || self.agent.values().any(|a| {
                a.memory
                    .as_ref()
                    .is_some_and(|m| m.class == Some(MemoryClass::Phi))
            })
    }

    /// The gated command prefixes from `[policy] permissions_ask`.
    pub fn gates(&self) -> Result<Vec<CommandPrefix>, String> {
        self.policy
            .permissions_ask
            .iter()
            .map(|p| CommandPrefix::parse(p))
            .collect()
    }

    /// The hosts WebFetch may reach, when `[policy] fetch_allow` limits it.
    pub fn fetch_allow(&self) -> Result<Option<Vec<HostPattern>>, String> {
        self.policy
            .fetch_allow
            .as_ref()
            .map(|hosts| hosts.iter().map(|h| HostPattern::parse(h)).collect())
            .transpose()
    }
}
