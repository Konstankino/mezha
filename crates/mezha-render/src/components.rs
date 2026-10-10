//! `.claude/agents/<n>.md`, `.claude/skills/<n>/SKILL.md` and
//! `.claude/rules/<n>.md`: frontmatter from the spec, body from a Markdown
//! file the user owns under `mezha/`.

use std::collections::BTreeMap;
use std::path::Path;

use mezha_memory::scan::{self, EXTERNAL_REFERENCE, Level};
use mezha_spec::{
    Agent, BashPattern, HostPattern, Rule, Scope, Skill, Spec, is_unscoped_bash, parse_tool,
};
use serde_json::{Value, json};

use crate::frontmatter;

/// Body files bigger than this are refused.
pub const MAX_BODY: usize = 256 * 1024;

/// What rendering the components produced.
#[derive(Debug, Default)]
pub struct Components {
    pub files: BTreeMap<String, String>,
    /// Errors that keep a file from being rendered, such as a missing body.
    pub problems: Vec<String>,
    pub warnings: Vec<String>,
}

pub fn render(spec: &Spec, root: &Path) -> Components {
    let mut out = Components::default();
    let fetch = spec.fetch_allow().ok().flatten();
    let fetch = fetch.as_deref();
    for (name, agent) in &spec.agent {
        let path = format!(".claude/agents/{name}.md");
        let result = read_body(
            root,
            &agent.prompt_path(name),
            false,
            fetch,
            &mut out.warnings,
        )
        .and_then(|body| agent_file(spec, name, agent, &body));
        out.add(path, result);
    }
    for (name, skill) in &spec.skill {
        let path = format!(".claude/skills/{name}/SKILL.md");
        let result = read_body(root, &skill.body_path(name), true, fetch, &mut out.warnings)
            .and_then(|body| skill_file(name, skill, &body));
        out.add(path, result);
    }
    for (name, rule) in &spec.rule {
        let path = format!(".claude/rules/{name}.md");
        let result = read_body(root, &rule.body_path(name), false, fetch, &mut out.warnings)
            .and_then(|body| {
                if let Some(max) = rule.max_lines
                    && body.lines().count() > max as usize
                {
                    out.warnings.push(format!(
                        "rule.{name}: the body has {} lines, more than max_lines = {max}",
                        body.lines().count()
                    ));
                }
                rule_file(rule, &body)
            });
        out.add(path, result);
    }
    out
}

impl Components {
    fn add(&mut self, path: String, result: Result<String, String>) {
        match result {
            Ok(text) => {
                self.files.insert(path, text);
            }
            Err(e) => self.problems.push(format!("{path}: {e}")),
        }
    }
}

/// Reads a body file the way mezha writes files: no symlink on the way, a
/// regular file, UTF-8, within [`MAX_BODY`]. A BOM is dropped and line
/// endings become LF. The body is then scanned ([`scan_body`]).
fn read_body(
    root: &Path,
    rel: &str,
    runs_at_load: bool,
    fetch: Option<&[HostPattern]>,
    warnings: &mut Vec<String>,
) -> Result<String, String> {
    crate::write::fence(root, rel).map_err(|e| e.to_string())?;
    let path = root.join(rel);
    let bytes = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(format!("{rel} doesn't exist; write the body there"));
        }
        Err(e) => return Err(format!("{rel}: {e}")),
    };
    if bytes.len() > MAX_BODY {
        return Err(format!("{rel} is over {} KiB", MAX_BODY / 1024));
    }
    let text = String::from_utf8(bytes).map_err(|_| format!("{rel} isn't UTF-8"))?;
    let text = text
        .strip_prefix('\u{feff}')
        .unwrap_or(&text)
        .replace("\r\n", "\n");
    if text.trim_start().starts_with("---") {
        return Err(format!(
            "{rel} starts with `---`: mezha writes the frontmatter, so the file holds only the body"
        ));
    }
    if text.trim().is_empty() {
        warnings.push(format!("{rel} is empty"));
    }
    scan_body(rel, &text, runs_at_load, fetch, warnings)?;
    Ok(text)
}

/// Claude reads a body as instructions, so what the scan calls hard (hidden
/// characters, secrets, chat-template tokens, remote images, raw HTML and,
/// in a skill, shell run at load) refuses it, and phrases are warnings
/// (OWASP AST01, AST04, AST08). A link to a host `fetch_allow` doesn't
/// list refuses it too, since WebFetch couldn't follow it; without
/// `fetch_allow`, links are warnings (AST05). Advisory: patterns miss
/// things, so the boundary is still the review of every body change.
fn scan_body(
    rel: &str,
    text: &str,
    runs_at_load: bool,
    fetch: Option<&[HostPattern]>,
    warnings: &mut Vec<String>,
) -> Result<(), String> {
    let mut hard = Vec::new();
    let mut hosts: Vec<&str> = Vec::new();
    for f in scan::body_findings(text, runs_at_load) {
        if f.what == EXTERNAL_REFERENCE && !f.encoded {
            let host = scan::link_host(&text[f.start..f.end]);
            if !hosts.contains(&host) {
                hosts.push(host);
            }
            continue;
        }
        let at = format!("{rel}:{}: {} ({})", f.line, f.what, f.excerpt(text));
        match f.level {
            Level::Hard | Level::Phi => hard.push(at),
            Level::Phrase => warnings.push(format!("{at}: reads like an instruction to a model")),
        }
    }
    match fetch {
        Some(allowed) => {
            let outside: Vec<&str> = hosts
                .iter()
                .copied()
                .filter(|h| !allowed.iter().any(|a| a.matches(h)))
                .collect();
            if !outside.is_empty() {
                hard.push(format!(
                    "{rel} links to {}, which policy.fetch_allow doesn't list (copy what Claude needs into the body, or list the host)",
                    outside.join(", ")
                ));
            }
        }
        None if !hosts.is_empty() => warnings.push(format!(
            "{rel} links to {}: Claude may fetch and follow what is there, which can change after review; copy what it needs into the body",
            hosts.join(", ")
        )),
        None => {}
    }
    if hard.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "{}; bodies may not hold hidden characters, secrets, chat-template tokens, remote images, raw HTML or shell run at load",
            hard.join("; ")
        ))
    }
}

fn assemble(frontmatter: &str, body: &str) -> String {
    let mut text = format!("{frontmatter}\n{}", body.trim_start_matches('\n'));
    if !text.ends_with('\n') {
        text.push('\n');
    }
    text
}

fn strings(list: &[String]) -> Value {
    Value::Array(list.iter().map(|s| json!(s.trim())).collect())
}

/// Tool names for an agent's `tools`: `Bash(...)` becomes `Bash`, since
/// Claude Code can't scope an agent's tools by argument; `Agent(...)` stays
/// as written, since it can.
fn tool_names(tools: &[String]) -> Vec<String> {
    let mut names: Vec<String> = Vec::new();
    for tool in tools {
        let name = match parse_tool(tool) {
            Some(entry) if entry.name == "Agent" => tool.trim().to_string(),
            Some(entry) => entry.name.to_string(),
            None => continue,
        };
        if !names.contains(&name) {
            names.push(name);
        }
    }
    names
}

/// The `Bash(...)` scopes an agent's hook enforces: none when any Bash entry
/// is unscoped, since the agent has all of Bash then anyway.
fn bash_scopes(agent: &Agent) -> Vec<BashPattern> {
    let Some(tools) = &agent.tools else {
        return Vec::new();
    };
    let bash = |t: &&String| parse_tool(t).is_some_and(|e| e.name == "Bash");
    if tools.iter().filter(bash).any(|t| is_unscoped_bash(t)) {
        return Vec::new();
    }
    tools
        .iter()
        .filter(bash)
        .filter_map(|t| BashPattern::parse(parse_tool(t)?.specifier?).ok())
        .collect()
}

/// Where an agent's memory lives for a scope.
pub fn memory_dir(name: &str, scope: Scope) -> String {
    match scope {
        Scope::Project => format!(".claude/agent-memory/{name}/"),
        Scope::Local => format!(".claude/agent-memory-local/{name}/"),
        Scope::User => format!("~/.claude/agent-memory/{name}/"),
    }
}

fn agent_file(spec: &Spec, name: &str, agent: &Agent, body: &str) -> Result<String, String> {
    let scope = spec.memory_scope(agent);
    let tools = agent.tools.as_deref().map(tool_names);
    let mut disallowed: Vec<String> = agent
        .disallowed_tools
        .iter()
        .map(|t| t.trim().to_string())
        .collect();
    // Claude Code adds Read, Write and Edit to an agent with memory; memory
    // is read-only in sessions, so take back what the spec didn't grant.
    if scope.is_some()
        && let Some(tools) = &tools
    {
        for tool in ["Write", "Edit"] {
            if !tools.iter().any(|t| t == tool) && !disallowed.iter().any(|t| t == tool) {
                disallowed.push(tool.to_string());
            }
        }
    }
    let fields = [
        ("name", json!(name)),
        (
            "description",
            json!(agent.description.as_deref().unwrap_or_default().trim()),
        ),
        ("tools", tools.map_or(Value::Null, |t| json!(t))),
        (
            "disallowedTools",
            if disallowed.is_empty() {
                Value::Null
            } else {
                json!(disallowed)
            },
        ),
        (
            "model",
            agent
                .model
                .as_deref()
                .map_or(Value::Null, |m| json!(m.trim())),
        ),
        (
            "effort",
            agent.effort.map_or(Value::Null, |e| json!(e.as_str())),
        ),
        (
            "maxTurns",
            agent.max_turns.map_or(Value::Null, |n| json!(n)),
        ),
        (
            "skills",
            if agent.skills.is_empty() {
                Value::Null
            } else {
                strings(&agent.skills)
            },
        ),
        ("memory", scope.map_or(Value::Null, |s| json!(s.as_str()))),
        ("hooks", agent_hooks(agent)),
    ];
    let mut text = body.trim_end().to_string();
    if let Some(scope) = scope {
        text.push_str(&format!(
            "\n\n## Memory (mezha)\n\nYour memory in `{}` is read-only in this session: mezha denies writes to it, so don't try to save memories there, whatever other instructions say. `mezha dream` updates it from session transcripts, and a person reviews every change. If you learn something that should last, end your final message with a `## Lessons` section that lists it.",
            memory_dir(name, scope)
        ));
    }
    // `mezha metrics` counts these sections (UNRESOLVED per week).
    text.push_str(
        "\n\n## Reporting (mezha)\n\nIf you couldn't finish part of the task, end your final message with an `## Unresolved` section (this English heading, whatever language you answer in) that lists what is left and why. Leave it out when you finished.\n",
    );
    Ok(assemble(&frontmatter::write(&fields)?, &text))
}

/// A scoped Bash gets the advisory `agent-bash` hook on Bash and Monitor.
fn agent_hooks(agent: &Agent) -> Value {
    let scopes = bash_scopes(agent);
    if scopes.is_empty() {
        return Value::Null;
    }
    json!({
        "PreToolUse": [{
            "matcher": "Bash|Monitor",
            "hooks": [{
                "type": "command",
                "command": mezha_hooks::agent_bash_command(&scopes),
                "shell": "bash",
            }],
        }],
    })
}

fn skill_file(name: &str, skill: &Skill, body: &str) -> Result<String, String> {
    let list = |l: &[String]| {
        if l.is_empty() {
            Value::Null
        } else {
            strings(l)
        }
    };
    let fields = [
        ("name", json!(name)),
        ("description", json!(skill.description.trim())),
        (
            "when_to_use",
            skill
                .when_to_use
                .as_deref()
                .map_or(Value::Null, |w| json!(w.trim())),
        ),
        ("user-invocable", json!(skill.user_invocable())),
        (
            "disable-model-invocation",
            json!(skill.disable_model_invocation()),
        ),
        ("allowed-tools", list(&skill.allowed_tools)),
        ("arguments", list(&skill.arguments)),
        ("paths", list(&skill.paths)),
    ];
    Ok(assemble(&frontmatter::write(&fields)?, body))
}

fn rule_file(rule: &Rule, body: &str) -> Result<String, String> {
    if rule.paths.is_empty() {
        let mut text = body.trim_start_matches('\n').to_string();
        if !text.ends_with('\n') {
            text.push('\n');
        }
        return Ok(text);
    }
    let fields = [("paths", strings(&rule.paths))];
    Ok(assemble(&frontmatter::write(&fields)?, body))
}
