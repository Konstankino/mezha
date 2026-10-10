//! The `mezha.toml` schema and its validation.
//!
//! [`parse`] turns the text into a [`Spec`] (rejecting unknown keys and newer
//! schemas); [`validate`] runs the compiler rules from `mezha-plan.md`
//! section 4 and returns every error and warning at once.

mod bash_pattern;
pub mod cron;
mod host;
mod model;
mod names;
mod prefix;
mod tools;
mod validate;

pub use bash_pattern::BashPattern;
pub use host::{HostPattern, host_matches, url_host};
pub use model::{
    Agent, AgentMemory, AutoMemory, BODY_DIR, Capability, DEFAULT_DREAM_BUDGET_USD,
    DEFAULT_DREAM_MAX_TURNS, DEFAULT_DREAM_MODEL, DreamPolicy, DreamSchedule, Effort, HumanGate,
    Languages, Memory, MemoryClass, OsMode, Policy, Preset, Project, Rule, Scope, Skill, Spec,
};
pub use names::check_name;
pub use prefix::CommandPrefix;
pub use tools::{
    KNOWN_TOOLS, ToolEntry, frontmatter_problem, hidden_char, is_emoji, is_hidden, parse_tool,
};
pub use validate::{
    Diagnostic, Diagnostics, Severity, body_path_problem, is_unscoped_bash, validate,
};

/// The newest `schema` this mezha understands.
pub const SCHEMA_VERSION: u32 = 1;

/// The spec's file name at the project root.
pub const SPEC_FILE: &str = "mezha.toml";

/// Why a spec could not be read at all (as opposed to a [`Diagnostic`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoadError {
    /// Not valid TOML, or a key or value the schema doesn't know.
    Syntax(String),
    /// `schema` is newer than this mezha.
    NewerSchema { found: i64 },
}

impl std::fmt::Display for LoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LoadError::Syntax(msg) => write!(f, "{SPEC_FILE}: {}", msg.trim_end()),
            LoadError::NewerSchema { found } => write!(
                f,
                "{SPEC_FILE}: schema {found} needs a newer mezha (this one reads schema {SCHEMA_VERSION})"
            ),
        }
    }
}

impl std::error::Error for LoadError {}

/// Parses a spec. The `schema` key is read first, so a newer spec fails with
/// "needs a newer mezha" rather than with whatever key it added.
pub fn parse(text: &str) -> Result<Spec, LoadError> {
    let raw: toml::Table = toml::from_str(text).map_err(|e| LoadError::Syntax(e.to_string()))?;
    if let Some(found) = raw.get("schema").and_then(toml::Value::as_integer)
        && found > i64::from(SCHEMA_VERSION)
    {
        return Err(LoadError::NewerSchema { found });
    }
    toml::from_str(text).map_err(|e| LoadError::Syntax(e.to_string()))
}
