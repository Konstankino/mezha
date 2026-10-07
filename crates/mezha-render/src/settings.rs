//! `.claude/settings.json`, built as JSON values (never from text templates)
//! and limited to keys Claude Code documents.

use mezha_spec::{CommandPrefix, Spec};
use serde_json::{Value, json};

pub const SCHEMA_URL: &str = "https://json.schemastore.org/claude-code-settings.json";

/// Edits that could switch a gate off ask first. `/path` in project settings
/// means "relative to the project root".
const ASK_EDITS: [&str; 4] = [
    "Edit(/mezha.toml)",
    "Edit(/.claude/settings.json)",
    "Edit(/.claude/settings.local.json)",
    "Edit(/.claude/.mezha-state.json)",
];

/// mezha commands that rewrite the generated files ask first too.
const ASK_COMMANDS: [&str; 3] = [
    "Bash(mezha compile *)",
    "Bash(mezha apply *)",
    "Bash(mezha init *)",
];

/// Paths sandboxed commands may not write. Sandbox paths use `~/` for home
/// and `./` for the project root. Claude Code already protects `.claude`
/// settings and `.git/hooks` on its own.
const DENY_WRITE: [&str; 3] = ["~/.mezha", "./mezha.toml", "./.claude/.mezha-state.json"];

pub fn settings(spec: &Spec, gates: &[CommandPrefix]) -> Value {
    let mut ask: Vec<String> = gates.iter().map(|g| format!("Bash({g} *)")).collect();
    ask.extend(ASK_EDITS.iter().chain(&ASK_COMMANDS).map(|s| s.to_string()));

    let mut deny = vec![
        "Bash(mezha approve *)".to_string(),
        "Edit(~/.mezha/**)".to_string(),
    ];
    deny.extend(spec.policy.deny_reads.iter().map(|p| format!("Read({p})")));

    let mut settings = json!({
        "$schema": SCHEMA_URL,
        "permissions": { "ask": ask, "deny": deny },
        "hooks": {
            "PreToolUse": [{
                "hooks": [{
                    "type": "command",
                    "command": mezha_hooks::command_line(gates),
                    "shell": "bash",
                }]
            }]
        },
    });
    if spec.policy.sandbox {
        settings["sandbox"] = json!({
            "enabled": true,
            // Strict: no unsandboxed retry, and no silent fallback to running
            // unsandboxed when the sandbox can't start (such as on WSL2
            // without bubblewrap).
            "allowUnsandboxedCommands": false,
            "failIfUnavailable": true,
            "network": { "allowedDomains": spec.policy.egress_allow },
            "filesystem": { "denyWrite": DENY_WRITE },
        });
    }
    settings
}
