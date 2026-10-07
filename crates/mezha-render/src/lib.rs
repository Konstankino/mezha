//! Spec → files under `.claude/`, plus the fingerprints that let mezha tell
//! its own output from a hand edit.
//!
//! Week 1 renders `.claude/settings.json` only. Agents, skills and rules are
//! validated by mezha-spec but rendered in phase 1.

pub mod settings;
pub mod state;
mod write;

use std::collections::BTreeMap;

use mezha_spec::{OsMode, Spec};

pub use write::{
    Action, BACKUP_DIR, Change, Mode, Plan, Report, WriteError, plan, unified_diff, utc_stamp,
    write,
};

/// Every path mezha may generate. Paths read back from the state file are
/// checked against this list.
pub const GENERATED: [&str; 1] = [".claude/settings.json"];

#[derive(Debug, Clone)]
pub struct Rendered {
    /// Path relative to the project root (with `/`) → content.
    pub files: BTreeMap<String, String>,
    /// Fingerprint of the spec text.
    pub spec: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RenderError {
    /// Native Windows support arrives in phase 4.
    NativeWindows,
    /// `permissions_ask` holds an invalid prefix (validation should have
    /// caught it first).
    Gates(String),
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
        }
    }
}

impl std::error::Error for RenderError {}

/// Renders a validated spec. `spec_text` is the file it came from.
pub fn render(spec: &Spec, spec_text: &str) -> Result<Rendered, RenderError> {
    if spec.project.os_mode == OsMode::NativeWindows {
        return Err(RenderError::NativeWindows);
    }
    let gates = spec.gates().map_err(RenderError::Gates)?;
    let mut settings_text = serde_json::to_string_pretty(&settings::settings(spec, &gates))
        .expect("settings serialize");
    settings_text.push('\n');
    Ok(Rendered {
        files: BTreeMap::from([(GENERATED[0].to_string(), settings_text)]),
        spec: state::fingerprint(spec_text),
    })
}
