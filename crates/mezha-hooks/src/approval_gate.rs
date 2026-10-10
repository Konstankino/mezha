//! The approval gate: a PreToolUse hook on every tool. Gated commands need an
//! active `mezha approve`, the agent may not approve itself, and no tool may
//! touch `~/.mezha`. Anything it can't make sense of is blocked. Every
//! decision goes to the audit log ([`crate::audit`]).

use std::path::{Path, PathBuf};

use mezha_broker::approvals;
use mezha_spec::{CommandPrefix, HostPattern, url_host};
use serde_json::{Map, Value};

use crate::audit;
use crate::matcher::{self, Hit};
use crate::paths::{resolve, within};
use crate::{Env, MAX_INPUT, Outcome};

pub const NAME: &str = "approval-gate";

/// Tools whose input carries a shell command.
const COMMAND_TOOLS: [&str; 3] = ["Bash", "PowerShell", "Monitor"];

/// `tool_input` keys that name a file or directory.
const PATH_KEYS: [&str; 3] = ["file_path", "notebook_path", "path"];

const ADVISORY: &str = "(mezha approval gate: advisory. The boundary is the sandbox and the credentials it withholds.)";

/// Decides, then records the decision in the audit log. A call that can't
/// be recorded is blocked too (fail-closed).
pub fn run(
    gates: &[CommandPrefix],
    fetch: Option<&[HostPattern]>,
    input: &[u8],
    env: &Env,
) -> Outcome {
    let event = std::str::from_utf8(input)
        .ok()
        .filter(|_| input.len() <= MAX_INPUT)
        .and_then(|t| serde_json::from_str::<Value>(t).ok())
        .and_then(|v| match v {
            Value::Object(m) => Some(m),
            _ => None,
        })
        .unwrap_or_default();
    let outcome = decide(gates, fetch, input, env);
    let Some(home) = mezha_broker::home_dir(|k| env.var(k).map(str::to_string)) else {
        return outcome;
    };
    let root = project_dir(env, &event).map(|p| mezha_broker::repo_root(&p));
    let record = audit::admission(&event, input, env, root.as_deref(), &outcome);
    match audit::append(&home, root.as_deref(), env.now, &record) {
        Ok(()) => outcome,
        Err(e) if outcome.is_block() => Outcome::block(format!(
            "{}mezha: couldn't write the audit log either: {e}",
            outcome.stderr
        )),
        Err(e) => Outcome::block(format!(
            "mezha: couldn't write the audit log in {}: {e}. The call is blocked (fail-closed).",
            audit::dir(&home, root.as_deref()).display()
        )),
    }
}

fn decide(
    gates: &[CommandPrefix],
    fetch: Option<&[HostPattern]>,
    input: &[u8],
    env: &Env,
) -> Outcome {
    if input.len() > MAX_INPUT {
        return Outcome::block("mezha: hook input is too large to check");
    }
    let Ok(text) = std::str::from_utf8(input) else {
        return Outcome::block("mezha: hook input is not UTF-8");
    };
    let Ok(Value::Object(event)) = serde_json::from_str::<Value>(text) else {
        return Outcome::block("mezha: hook input is not a JSON object");
    };
    let event_name = event.get("hook_event_name").and_then(Value::as_str);
    if event_name != Some("PreToolUse") {
        return Outcome::block(format!(
            "mezha: {NAME} handles PreToolUse events, not {}",
            event_name.unwrap_or("an event without hook_event_name")
        ));
    }
    let Some(tool) = event.get("tool_name").and_then(Value::as_str) else {
        return Outcome::block("mezha: PreToolUse event without tool_name");
    };
    let Some(home) = mezha_broker::home_dir(|k| env.var(k).map(str::to_string)) else {
        return Outcome::block("mezha: can't find the home directory (HOME is unset)");
    };
    let project = project_dir(env, &event);
    let input = event.get("tool_input").and_then(Value::as_object);

    if let Some(blocked) = input.and_then(|i| store_path(i, &home, project.as_deref())) {
        return Outcome::block(format!(
            "mezha: `{blocked}` is inside {}, where approvals live; agents may not touch it.",
            approvals::mezha_home(&home).display()
        ));
    }

    if tool == "WebFetch"
        && let Some(hosts) = fetch
    {
        return gate_fetch(input, hosts);
    }

    match input.and_then(|i| i.get("command")) {
        Some(Value::String(command)) => {
            gate_command(command, gates, env, &home, project.as_deref())
        }
        Some(_) => Outcome::block("mezha: tool_input.command is not a string"),
        None if COMMAND_TOOLS.contains(&tool) => {
            Outcome::block(format!("mezha: {tool} call without a command"))
        }
        None => Outcome::allow(),
    }
}

/// WebFetch may reach only the hosts `policy.fetch_allow` lists (OWASP
/// AST05). A redirect to another host comes back as a new WebFetch call, so
/// a chain of references stays inside the list too.
fn gate_fetch(input: Option<&Map<String, Value>>, hosts: &[HostPattern]) -> Outcome {
    let url = input.and_then(|i| i.get("url")).and_then(Value::as_str);
    let Some(host) = url.and_then(url_host) else {
        return Outcome::block(format!(
            "mezha: WebFetch to `{}`: the host can't be read from the URL, so the call is blocked",
            url.unwrap_or("").escape_debug()
        ));
    };
    if hosts.iter().any(|h| h.matches(&host)) {
        Outcome::allow()
    } else {
        let listed: Vec<String> = hosts.iter().map(ToString::to_string).collect();
        Outcome::block(format!(
            "mezha: WebFetch may reach only the hosts in policy.fetch_allow ({}), not `{host}`. Ask the user to add the host to mezha.toml if it is needed.",
            if listed.is_empty() {
                "none".to_string()
            } else {
                listed.join(", ")
            }
        ))
    }
}

/// `CLAUDE_PROJECT_DIR`, else the event's `cwd`.
pub(crate) fn project_dir(env: &Env, event: &Map<String, Value>) -> Option<PathBuf> {
    env.var("CLAUDE_PROJECT_DIR")
        .or_else(|| {
            event
                .get("cwd")
                .and_then(Value::as_str)
                .filter(|c| !c.is_empty())
        })
        .map(PathBuf::from)
}

fn gate_command(
    command: &str,
    gates: &[CommandPrefix],
    env: &Env,
    home: &Path,
    project: Option<&Path>,
) -> Outcome {
    if command
        .chars()
        .any(|c| c.is_control() && !matches!(c, '\t' | '\n' | '\r'))
    {
        return Outcome::block(
            "mezha: the command contains control characters, so it can't be checked",
        );
    }
    match matcher::scan(command, gates) {
        None => Outcome::allow(),
        Some(Hit::TooDeep) => {
            Outcome::block("mezha: the command nests too deeply to check, so it is blocked")
        }
        Some(Hit::SelfApproval) => Outcome::block(format!(
            "mezha: `mezha approve` must be run by a human in their own terminal, not by the agent.\n{ADVISORY}"
        )),
        Some(Hit::Gate(i)) => {
            let Some(project) = project else {
                return Outcome::block("mezha: no project directory (CLAUDE_PROJECT_DIR or cwd)");
            };
            let root = mezha_broker::repo_root(project);
            if approvals::remaining(home, &root, env.now).is_some() {
                Outcome::allow()
            } else {
                Outcome::block(format!(
                    "mezha: `{}` is gated. Ask the user to run it in their own terminal: \
                     the sandbox withholds credentials, so it fails from here even after an \
                     approval. `mezha approve --minutes 30`, run by the user, only lifts this \
                     gate.\n{ADVISORY}",
                    gates[i]
                ))
            }
        }
    }
}

/// The first path in the tool input that points into `~/.mezha`.
fn store_path<'a>(
    input: &'a Map<String, Value>,
    home: &Path,
    project: Option<&Path>,
) -> Option<&'a str> {
    let store = resolve(&approvals::mezha_home(home));
    PATH_KEYS
        .iter()
        .filter_map(|k| input.get(*k).and_then(Value::as_str))
        .find(|p| {
            let path = if *p == "~" {
                home.to_path_buf()
            } else if let Some(rest) = p.strip_prefix("~/") {
                home.join(rest)
            } else {
                match project {
                    Some(dir) => dir.join(p),
                    None => PathBuf::from(p),
                }
            };
            within(&resolve(&path), &store)
        })
}
