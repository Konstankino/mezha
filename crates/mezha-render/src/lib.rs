//! Spec → files under `.claude/`, plus the fingerprints that let mezha tell
//! its own output from a hand edit: `settings.json`, and an agent, skill or
//! rule file for each one in the spec, whose body comes from a Markdown file
//! the user owns under `mezha/`.

pub mod components;
mod frontmatter;
pub mod settings;
pub mod state;
mod write;

use std::collections::BTreeMap;
use std::path::Path;

use mezha_spec::{OsMode, Spec, check_name};

pub use write::{
    Action, BACKUP_DIR, Change, Mode, Plan, Report, WriteError, plan, unified_diff, utc_stamp,
    write,
};

pub const SETTINGS_PATH: &str = ".claude/settings.json";

/// Whether mezha may generate `path`. Paths read back from the state file
/// (which an agent can edit) are checked against this.
pub fn is_generated(path: &str) -> bool {
    let named_md = |file: &str| {
        file.strip_suffix(".md")
            .is_some_and(|n| check_name(n).is_ok())
    };
    match path.split('/').collect::<Vec<_>>()[..] {
        [".claude", "settings.json"] => true,
        [".claude", "agents", file] | [".claude", "rules", file] => named_md(file),
        [".claude", "skills", name, "SKILL.md"] => check_name(name).is_ok(),
        _ => false,
    }
}

#[derive(Debug, Clone)]
pub struct Rendered {
    /// Path relative to the project root (with `/`) → content.
    pub files: BTreeMap<String, String>,
    /// Fingerprint of the spec text.
    pub spec: String,
    /// Files that couldn't be rendered, such as an agent whose body file is
    /// missing. Nothing should be written while there are any.
    pub problems: Vec<String>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RenderError {
    /// Native Windows support arrives in phase 4.
    NativeWindows,
    /// `permissions_ask` holds an invalid prefix (validation should have
    /// caught it first).
    Gates(String),
    /// `fetch_allow` holds an invalid host (validation catches it first).
    Fetch(String),
}

impl std::fmt::Display for RenderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RenderError::NativeWindows => write!(
                f,
                "os_mode = \"native-windows\" is not supported yet (phase 4): without a sandbox \
                 every gate is advisory and hooks may run in PowerShell 5.1, which can't fail \
                 closed. Use WSL2 with os_mode = \"full\"."
            ),
            RenderError::Gates(e) => write!(f, "policy.permissions_ask: {e}"),
            RenderError::Fetch(e) => write!(f, "policy.fetch_allow: {e}"),
        }
    }
}

impl std::error::Error for RenderError {}

/// Renders a validated spec. `spec_text` is the file it came from; body
/// files are read from under `root`.
pub fn render(spec: &Spec, spec_text: &str, root: &Path) -> Result<Rendered, RenderError> {
    if spec.project.os_mode == OsMode::NativeWindows {
        return Err(RenderError::NativeWindows);
    }
    let gates = spec.gates().map_err(RenderError::Gates)?;
    let fetch = spec.fetch_allow().map_err(RenderError::Fetch)?;
    let mut settings_text =
        serde_json::to_string_pretty(&settings::settings(spec, &gates, fetch.as_deref()))
            .expect("settings serialize");
    settings_text.push('\n');
    let components = components::render(spec, root);
    let mut files = components.files;
    files.insert(SETTINGS_PATH.to_string(), settings_text);
    Ok(Rendered {
        files,
        spec: state::fingerprint(spec_text),
        problems: components.problems,
        warnings: components.warnings,
    })
}
