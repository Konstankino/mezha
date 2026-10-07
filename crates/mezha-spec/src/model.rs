//! The typed spec. Every table rejects unknown keys: in a governance file a
//! typo such as `rule_of_tow` must fail, not silently drop a property.

use std::collections::BTreeMap;

use serde::Deserialize;

use crate::CommandPrefix;

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
}

impl Default for Policy {
    fn default() -> Self {
        Policy {
            sandbox: true,
            egress_allow: Vec::new(),
            permissions_ask: Vec::new(),
            deny_reads: Vec::new(),
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

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Agent {
    pub model: Option<String>,
    pub effort: Option<Effort>,
    #[serde(default)]
    pub tools: Vec<String>,
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

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentMemory {
    /// Absent means `[memory] default_scope` (or `local` for PHI).
    pub scope: Option<Scope>,
    pub class: Option<MemoryClass>,
    /// How the dreamer filters this role's memory. Checked in phase 2.
    pub dream_policy: Option<String>,
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
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    #[serde(default)]
    pub paths: Vec<String>,
    pub max_lines: Option<u32>,
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

    /// The gated command prefixes from `[policy] permissions_ask`.
    pub fn gates(&self) -> Result<Vec<CommandPrefix>, String> {
        self.policy
            .permissions_ask
            .iter()
            .map(|p| CommandPrefix::parse(p))
            .collect()
    }
}
