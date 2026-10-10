//! `.claude/settings.json`, built as JSON values (never from text templates)
//! and limited to keys Claude Code documents.

use mezha_spec::{CommandPrefix, Spec};
use serde_json::{Map, Value, json};

pub const SCHEMA_URL: &str = "https://json.schemastore.org/claude-code-settings.json";

/// Edits that could switch a gate off, or change what an agent is told,
/// ask first. `/path` in project settings means "relative to the project
/// root". `mezha/` holds the bodies of agents, skills and rules.
const ASK_EDITS: [&str; 8] = [
    "Edit(/mezha.toml)",
    "Edit(/.claude/settings.json)",
    "Edit(/.claude/settings.local.json)",
    "Edit(/.claude/.mezha-state.json)",
    "Edit(/mezha/**)",
    "Edit(/.claude/agents/**)",
    "Edit(/.claude/skills/**)",
    "Edit(/.claude/rules/**)",
];

/// Agent memory changes only through `mezha dream`, which a person reviews
/// (ADR-0004): sessions may not write it in any scope. Claude Code checks
/// deny rules before its own "memory files may be written" allowance.
pub const MEMORY_DENY: [&str; 3] = [
    "Edit(/.claude/agent-memory/**)",
    "Edit(/.claude/agent-memory-local/**)",
    "Edit(~/.claude/agent-memory/**)",
];

/// Dream digests may hold PHI and other people's words: sessions may not
/// read them, with the Read tool or (merged into the sandbox's read
/// restrictions) from a sandboxed command. `mezha dream` writes them there.
pub const DREAMS_READ_DENY: &str = "Read(~/.mezha/dreams/**)";

/// mezha commands that rewrite the generated files ask first too.
const ASK_COMMANDS: [&str; 3] = [
    "Bash(mezha compile *)",
    "Bash(mezha apply *)",
    "Bash(mezha init *)",
];

/// Paths sandboxed commands may not write. Sandbox paths use `~/` for home
/// and `./` for the project root. Claude Code already protects `.claude`
/// settings, agents, skills and `.git/hooks` on its own, but not rules.
pub const DENY_WRITE: [&str; 8] = [
    "~/.mezha",
    "./mezha.toml",
    "./.claude/.mezha-state.json",
    "./mezha",
    "./.claude/rules",
    "./.claude/agent-memory",
    "./.claude/agent-memory-local",
    "~/.claude/agent-memory",
];

/// Hosts a forge accepts pushes on: git over HTTPS (and SSH over port
/// 443), and the APIs that write. Those `egress_allow` doesn't cover
/// become `deniedDomains`, which Claude Code refuses for sandboxed commands
/// in every permission mode, without an "allow" prompt to click
/// (ADR-0003, step 1c). The WebFetch tool isn't affected.
pub const FORGE_WRITE_HOSTS: [&str; 7] = [
    "github.com",
    "api.github.com",
    "uploads.github.com",
    "ssh.github.com",
    "gitlab.com",
    "bitbucket.org",
    "api.bitbucket.org",
];

/// Whether an `egress_allow` entry lets sandboxed commands reach `host`,
/// matched like the sandbox proxy does: `example.com` only itself,
/// `*.example.com` its subdomains, `*` everything. An entry limited to a
/// port still covers the host, so denying it wouldn't take the port away.
fn allows(entry: &str, host: &str) -> bool {
    let entry = entry.trim().to_ascii_lowercase();
    let entry = match entry.rsplit_once(':') {
        Some((h, port)) if port.chars().all(|c| c.is_ascii_digit()) => h.to_string(),
        _ => entry,
    };
    match entry.as_str() {
        "*" => true,
        e => match e.strip_prefix("*.") {
            Some(suffix) => host.len() > suffix.len() + 1 && host.ends_with(&format!(".{suffix}")),
            None => host == e,
        },
    }
}

/// The forge write hosts no `egress_allow` entry covers.
pub fn denied_domains(egress_allow: &[String]) -> Vec<&'static str> {
    FORGE_WRITE_HOSTS
        .iter()
        .copied()
        .filter(|host| !egress_allow.iter().any(|e| allows(e, host)))
        .collect()
}

/// Credential files and directories withheld from the agent, as
/// `(path, is_dir)`. The sandbox hides them from shell commands and a
/// `Read(...)` deny rule hides them from the Read tool, which runs outside
/// the sandbox. `mezha verify` checks against the same list (ADR-0003).
pub const CREDENTIAL_FILES: [(&str, bool); 25] = [
    ("~/.ssh", true),
    ("~/.gnupg", true),
    ("~/.aws", true),
    ("~/.azure", true),
    ("~/.config/gcloud", true),
    ("~/.kube", true),
    ("~/.config/gh", true),
    ("~/.config/glab-cli", true),
    ("~/.config/hub", false),
    ("~/.config/op", true),
    ("~/.gcm", true),
    ("~/.password-store", true),
    ("~/.netrc", false),
    ("~/.git-credentials", false),
    ("~/.config/git/credentials", false),
    ("~/.docker/config.json", false),
    ("~/.npmrc", false),
    ("~/.yarnrc.yml", false),
    ("~/.cargo/credentials", false),
    ("~/.cargo/credentials.toml", false),
    ("~/.pypirc", false),
    ("~/.gem/credentials", false),
    ("~/.terraform.d/credentials.tfrc.json", false),
    ("~/.pulumi/credentials.json", false),
    ("~/.vault-token", false),
];

/// Environment variables removed from sandboxed commands: tokens, and the
/// sockets and handles that lead to one (ssh-agent, VS Code's git askpass,
/// Windows interop from WSL).
pub const CREDENTIAL_ENV: [&str; 29] = [
    "GH_TOKEN",
    "GITHUB_TOKEN",
    "GH_ENTERPRISE_TOKEN",
    "GITHUB_ENTERPRISE_TOKEN",
    "HOMEBREW_GITHUB_API_TOKEN",
    "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
    "GITLAB_TOKEN",
    "GL_TOKEN",
    "CI_JOB_TOKEN",
    "GITEA_TOKEN",
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "AZURE_CLIENT_SECRET",
    "GOOGLE_APPLICATION_CREDENTIALS",
    "NPM_TOKEN",
    "NODE_AUTH_TOKEN",
    "YARN_NPM_AUTH_TOKEN",
    "CARGO_REGISTRY_TOKEN",
    "TWINE_USERNAME",
    "TWINE_PASSWORD",
    "PYPI_TOKEN",
    "UV_PUBLISH_TOKEN",
    "POETRY_PYPI_TOKEN_PYPI",
    "SSH_AUTH_SOCK",
    "VSCODE_GIT_IPC_HANDLE",
    "VSCODE_GIT_ASKPASS_MAIN",
    "VSCODE_GIT_ASKPASS_NODE",
    "WSL_INTEROP",
];

/// Git starts with no credential helper, no askpass and no terminal prompt.
/// An empty `credential.helper` read after every config file resets the
/// helpers before it, per-URL ones included. Advisory: a command can still
/// name a helper itself (`git -c credential.helper=...`).
pub const GIT_GUARD_ENV: [(&str, &str); 5] = [
    ("GIT_CONFIG_COUNT", "1"),
    ("GIT_CONFIG_KEY_0", "credential.helper"),
    ("GIT_CONFIG_VALUE_0", ""),
    ("GIT_TERMINAL_PROMPT", "0"),
    ("GIT_ASKPASS", ""),
];

/// The `Read(...)` deny rule hiding a credential path from the Read tool.
pub fn read_rule(path: &str, is_dir: bool) -> String {
    if is_dir {
        format!("Read({path}/**)")
    } else {
        format!("Read({path})")
    }
}

pub fn settings(spec: &Spec, gates: &[CommandPrefix]) -> Value {
    let mut ask: Vec<String> = gates.iter().map(|g| format!("Bash({g} *)")).collect();
    ask.extend(ASK_EDITS.iter().chain(&ASK_COMMANDS).map(|s| s.to_string()));

    let mut deny = vec![
        "Bash(mezha approve *)".to_string(),
        "Edit(~/.mezha/**)".to_string(),
        DREAMS_READ_DENY.to_string(),
    ];
    deny.extend(MEMORY_DENY.iter().map(|s| s.to_string()));
    deny.extend(spec.policy.deny_reads.iter().map(|p| format!("Read({p})")));
    deny.extend(CREDENTIAL_FILES.iter().map(|&(p, dir)| read_rule(p, dir)));

    let env: Map<String, Value> = GIT_GUARD_ENV
        .iter()
        .map(|&(k, v)| (k.to_string(), Value::from(v)))
        .collect();

    let mut settings = json!({
        "$schema": SCHEMA_URL,
        // Claude Code runs `!`cmd`` in a skill or command before the model
        // sees it; with this it inserts a placeholder instead (OWASP AST04,
        // "staged loader"). Bundled and managed skills aren't affected.
        "disableSkillShellExecution": true,
        // MCP servers run outside the sandbox: none from `.mcp.json` start
        // without a person approving each (OWASP AST02). This beats `true`
        // in user settings; local settings can still override it, and
        // verify fails when they do.
        "enableAllProjectMcpServers": false,
        "env": env,
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
        let files: Vec<Value> = CREDENTIAL_FILES
            .iter()
            .map(|&(path, _)| json!({ "path": path, "mode": "deny" }))
            .collect();
        let vars: Vec<Value> = CREDENTIAL_ENV
            .iter()
            .map(|name| json!({ "name": name, "mode": "deny" }))
            .collect();
        settings["sandbox"] = json!({
            "enabled": true,
            // Strict: no unsandboxed retry, and no silent fallback to running
            // unsandboxed when the sandbox can't start (such as on WSL2
            // without bubblewrap).
            "allowUnsandboxedCommands": false,
            "failIfUnavailable": true,
            "network": {
                "allowedDomains": spec.policy.egress_allow,
                "deniedDomains": denied_domains(&spec.policy.egress_allow),
            },
            "filesystem": { "denyWrite": DENY_WRITE },
            "credentials": { "files": files, "envVars": vars },
        });
    }
    settings
}

#[cfg(test)]
mod tests {
    use super::*;

    fn denied(egress: &[&str]) -> Vec<&'static str> {
        let egress: Vec<String> = egress.iter().map(|e| e.to_string()).collect();
        denied_domains(&egress)
    }

    #[test]
    fn forge_hosts_outside_egress_allow_are_denied() {
        assert_eq!(denied(&[]), FORGE_WRITE_HOSTS);
        assert_eq!(
            denied(&["github.com", "crates.io"]),
            [
                "api.github.com",
                "uploads.github.com",
                "ssh.github.com",
                "gitlab.com",
                "bitbucket.org",
                "api.bitbucket.org"
            ]
        );
        // A wildcard covers subdomains, not the apex.
        assert_eq!(
            denied(&["*.github.com", "GitLab.com:443", "*.bitbucket.org"]),
            ["github.com", "bitbucket.org"]
        );
        assert!(denied(&["*"]).is_empty());
        assert_eq!(denied(&["evilgithub.com"]).len(), 7);
    }
}
