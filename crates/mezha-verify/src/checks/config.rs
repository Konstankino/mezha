//! `project-config`: configuration Claude Code acts on when a session
//! starts is code (OWASP AST02, "config-file hijacking"): MCP servers from
//! `.mcp.json`, settings that run a command, and `env` values that send
//! Claude's traffic elsewhere or load code into its processes. All of it
//! runs outside the sandbox. In the shared project file, mezha's own, it
//! fails; in your local settings it warns, since that file is yours. User
//! settings aren't the repository's, so only one thing counts there:
//! approving every server in `.mcp.json`, which fails anywhere but managed
//! settings, since a later commit could add one.

use serde_json::Value;

use crate::ctx::Ctx;
use crate::layers::{Layer, Layers, Scope};
use crate::report::{Check, Findings, Kind};

/// Settings that run a command.
const RUNS_A_COMMAND: [&str; 6] = [
    "/apiKeyHelper",
    "/awsAuthRefresh",
    "/awsCredentialExport",
    "/otelHeadersHelper",
    "/statusLine",
    "/fileSuggestion",
];

/// Settings that install code from elsewhere.
const INSTALLS: [&str; 2] = ["/enabledPlugins", "/extraKnownMarketplaces"];

/// `env` names that redirect Claude's traffic or load code into it.
fn redirects(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    (upper.starts_with("ANTHROPIC_") && upper.ends_with("_URL"))
        || matches!(
            upper.as_str(),
            "HTTP_PROXY"
                | "HTTPS_PROXY"
                | "ALL_PROXY"
                | "NODE_OPTIONS"
                | "NODE_EXTRA_CA_CERTS"
                | "LD_PRELOAD"
                | "LD_LIBRARY_PATH"
                | "BASH_ENV"
                | "ENV"
        )
        || upper.starts_with("DYLD_")
}

pub fn check(ctx: &Ctx, layers: &Layers) -> Check {
    let check = Check::new(
        "project-config",
        "no configuration runs code or redirects Claude",
        Kind::Integrity,
    );
    let mut f = Findings::default();
    let report = |f: &mut Findings, layer: &Layer, what: String, fix: String| {
        if layer.scope == Scope::Project {
            f.fail(format!("{what} in {}", layer.label), fix);
        } else {
            f.warn(
                format!(
                    "{what} in {} (yours; it runs outside the sandbox)",
                    layer.label
                ),
                None,
            );
        }
    };

    // The user's own settings apply to every project and are theirs to
    // keep; the files in the repository directory are what a clone brings.
    for layer in layers.layers.iter().filter(|l| l.scope.is_repository()) {
        for key in RUNS_A_COMMAND {
            if layer.value.pointer(key).is_some() {
                let name = &key[1..];
                report(
                    &mut f,
                    layer,
                    format!("{name} runs a command"),
                    format!("Remove {name} and run `mezha compile`."),
                );
            }
        }
        for key in INSTALLS {
            if layer
                .value
                .pointer(key)
                .and_then(Value::as_object)
                .is_some_and(|m| !m.is_empty())
            {
                let name = &key[1..];
                report(
                    &mut f,
                    layer,
                    format!("{name} installs plugins"),
                    format!("Remove {name} and run `mezha compile`."),
                );
            }
        }
        if let Some(env) = layer.value.pointer("/env").and_then(Value::as_object) {
            let mut names: Vec<&str> = env
                .keys()
                .map(String::as_str)
                .filter(|n| redirects(n))
                .collect();
            names.sort_unstable();
            if !names.is_empty() {
                report(
                    &mut f,
                    layer,
                    format!(
                        "env sets {}, which can send Claude's traffic elsewhere or load code into it",
                        names.join(", ")
                    ),
                    "Remove them and run `mezha compile`.".into(),
                );
            }
        }
        if let Some(hooks) = layer.value.pointer("/hooks").and_then(Value::as_object)
            && layer.scope != Scope::Project
            && !hooks.is_empty()
        {
            let mut events: Vec<&str> = hooks.keys().map(String::as_str).collect();
            events.sort_unstable();
            f.warn(
                format!(
                    "{} has hooks ({}): they run on your machine outside the sandbox",
                    layer.label,
                    events.join(", ")
                ),
                None,
            );
        }
    }

    if let Some((Value::Bool(true), layer)) = layers.winner("/enableAllProjectMcpServers")
        && layer.scope != Scope::Managed
    {
        f.fail(
            format!(
                "enableAllProjectMcpServers in {} approves every server in .mcp.json, including ones a later commit adds",
                layer.label
            ),
            format!(
                "Remove it from {}; approve servers one by one when Claude Code asks.",
                layer.label
            ),
        );
    }

    let mcp = ctx.root.join(".mcp.json");
    if let Ok(text) = std::fs::read_to_string(&mcp) {
        match serde_json::from_str::<Value>(&text) {
            Ok(v) => {
                let mut servers: Vec<String> = v
                    .pointer("/mcpServers")
                    .and_then(Value::as_object)
                    .map(|m| m.keys().cloned().collect())
                    .unwrap_or_default();
                servers.sort();
                if !servers.is_empty() {
                    let approved = approved(layers);
                    f.warn(
                        format!(
                            ".mcp.json defines MCP server(s) {}{}: each runs outside the sandbox with your environment and can reach the network",
                            servers.join(", "),
                            if approved.is_empty() {
                                String::new()
                            } else {
                                format!(" (approved: {})", approved.join(", "))
                            }
                        ),
                        Some("Approve a server only if you would run its command yourself; `claude mcp reset-project-choices` forgets approvals.".into()),
                    );
                }
            }
            Err(_) => f.warn(".mcp.json is not valid JSON", None),
        }
    }

    f.into_check(
        check,
        "no MCP servers, command-running settings or redirecting env",
    )
}

/// Servers approved in `enabledMcpjsonServers`, minus the rejected ones.
fn approved(layers: &Layers) -> Vec<String> {
    let rejected: Vec<&str> = layers
        .strings("/disabledMcpjsonServers")
        .into_iter()
        .map(|(s, _)| s)
        .collect();
    let mut out: Vec<String> = layers
        .strings("/enabledMcpjsonServers")
        .into_iter()
        .map(|(s, _)| s)
        .filter(|s| !rejected.contains(s))
        .map(str::to_string)
        .collect();
    out.sort();
    out.dedup();
    out
}

#[cfg(test)]
mod tests {
    use super::redirects;

    #[test]
    fn redirecting_env() {
        for yes in [
            "ANTHROPIC_BASE_URL",
            "ANTHROPIC_BEDROCK_BASE_URL",
            "https_proxy",
            "NODE_OPTIONS",
            "DYLD_INSERT_LIBRARIES",
            "LD_PRELOAD",
        ] {
            assert!(redirects(yes), "{yes}");
        }
        for no in [
            "ANTHROPIC_MODEL",
            "GIT_CONFIG_COUNT",
            "RUST_LOG",
            "NO_PROXY",
        ] {
            assert!(!redirects(no), "{no}");
        }
    }
}
