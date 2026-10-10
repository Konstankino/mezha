//! The compiler rules (`mezha-plan.md` section 4). Every rule runs, so one
//! pass reports everything; any error means nothing gets written.

use std::collections::BTreeSet;
use std::path::{Component, Path};

use crate::model::{BODY_DIR, Capability, Preset, Scope, Spec};
use crate::tools::{KNOWN_TOOLS, frontmatter_problem, parse_tool};
use crate::{CommandPrefix, SCHEMA_VERSION, check_name};

/// `description` + `when_to_use` beyond this are cut from Claude's skill listing.
pub const SKILL_LISTING_MAX: usize = 1536;
/// Knowledge skills need a description Claude can match against.
pub const KNOWLEDGE_DESCRIPTION_MIN: usize = 40;
/// Every agent's description is in Claude's listing on every turn.
pub const AGENT_DESCRIPTION_LONG: usize = 1024;

/// The most one role's dream may be allowed to cost, in US dollars.
pub const DREAM_BUDGET_MAX_USD: f64 = 50.0;
/// The most turns one role's dream may be allowed.
pub const DREAM_MAX_TURNS_LIMIT: u32 = 200;

/// Programs whose `Bash(...)` scope still allows any command.
const INTERPRETERS: [&str; 9] = [
    "sh", "bash", "zsh", "env", "eval", "xargs", "sudo", "exec", "command",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Error,
    Warning,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Diagnostic {
    pub severity: Severity,
    /// Where in the spec, such as `agent.implementer.rule_of_two`.
    pub path: String,
    pub message: String,
    pub hint: Option<String>,
}

impl std::fmt::Display for Diagnostic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let label = match self.severity {
            Severity::Error => "error",
            Severity::Warning => "warning",
        };
        write!(f, "{label}: {}: {}", self.path, self.message)?;
        if let Some(hint) = &self.hint {
            write!(f, "\n  hint: {hint}")?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Default)]
pub struct Diagnostics(pub Vec<Diagnostic>);

impl Diagnostics {
    pub fn errors(&self) -> impl Iterator<Item = &Diagnostic> {
        self.0.iter().filter(|d| d.severity == Severity::Error)
    }

    pub fn warnings(&self) -> impl Iterator<Item = &Diagnostic> {
        self.0.iter().filter(|d| d.severity == Severity::Warning)
    }

    pub fn has_errors(&self) -> bool {
        self.errors().next().is_some()
    }

    fn error(&mut self, path: impl Into<String>, message: impl Into<String>, hint: Option<&str>) {
        self.push(Severity::Error, path.into(), message.into(), hint);
    }

    fn warn(&mut self, path: impl Into<String>, message: impl Into<String>, hint: Option<&str>) {
        self.push(Severity::Warning, path.into(), message.into(), hint);
    }

    fn push(&mut self, severity: Severity, path: String, message: String, hint: Option<&str>) {
        self.0.push(Diagnostic {
            severity,
            path,
            message,
            hint: hint.map(str::to_string),
        });
    }
}

pub fn validate(spec: &Spec) -> Diagnostics {
    let mut d = Diagnostics::default();
    if let Some(schema) = spec.schema
        && schema != SCHEMA_VERSION
    {
        d.error(
            "schema",
            format!("unknown schema {schema}"),
            Some("use `schema = 1` or leave it out"),
        );
    }
    project(spec, &mut d);
    policy(spec, &mut d);
    memory(spec, &mut d);
    agents(spec, &mut d);
    skills(spec, &mut d);
    rules(spec, &mut d);
    d
}

fn project(spec: &Spec, d: &mut Diagnostics) {
    let name = &spec.project.name;
    if name.trim().is_empty() || name.chars().any(char::is_control) {
        d.error(
            "project.name",
            "must be a non-empty name without control characters",
            None,
        );
    }
}

fn policy(spec: &Spec, d: &mut Diagnostics) {
    let policy = &spec.policy;
    let mut gated_push = false;
    for (i, entry) in policy.permissions_ask.iter().enumerate() {
        match CommandPrefix::parse(entry) {
            Ok(p) => gated_push |= p.to_string() == "git push",
            Err(e) => d.error(format!("policy.permissions_ask[{i}]"), e, None),
        }
    }
    if !gated_push {
        d.warn(
            "policy.permissions_ask",
            "`git push` is not gated, so pushing needs no `mezha approve`",
            Some(r#"add "git push" to permissions_ask"#),
        );
    }
    for (i, pattern) in policy.deny_reads.iter().enumerate() {
        if let Some(problem) = rule_text_problem(pattern) {
            d.error(format!("policy.deny_reads[{i}]"), problem, None);
        }
    }
    for (i, host) in policy.egress_allow.iter().enumerate() {
        let path = format!("policy.egress_allow[{i}]");
        if let Some(problem) = rule_text_problem(host) {
            d.error(path, problem, None);
        } else if host.contains("://") || host.contains('/') {
            d.error(
                path,
                format!("`{host}` is not a host name"),
                Some("use a bare host such as github.com or *.example.com"),
            );
        }
    }
    for (i, name) in policy.external_skills.iter().enumerate() {
        if let Some(problem) = external_skill_problem(name) {
            d.error(format!("policy.external_skills[{i}]"), problem, None);
        } else if spec.skill.contains_key(name) {
            d.warn(
                format!("policy.external_skills[{i}]"),
                format!("`{name}` is defined in this spec, so listing it here does nothing"),
                Some("remove it"),
            );
        }
    }
    if !policy.sandbox {
        d.warn(
            "policy.sandbox",
            "the sandbox is off: agent commands can write the approval store, so the \
             `git push` gate is advisory only",
            None,
        );
    }
}

/// The dreamer's settings: they become `claude` arguments.
fn memory(spec: &Spec, d: &mut Diagnostics) {
    let memory = &spec.memory;
    if let Some(model) = &memory.dream_model
        && (model.is_empty()
            || model.starts_with('-')
            || model.chars().any(|c| c.is_whitespace() || c.is_control()))
    {
        d.error(
            "memory.dream_model",
            format!(
                "`{}` is not a model name: it must be non-empty, without whitespace, and not start with `-`",
                model.escape_debug()
            ),
            Some(r#"use an alias such as "sonnet" or a full model name"#),
        );
    }
    if let Some(budget) = memory.dream_budget_usd
        && !(budget.is_finite() && budget > 0.0 && budget <= DREAM_BUDGET_MAX_USD)
    {
        d.error(
            "memory.dream_budget_usd",
            format!("must be more than 0 and at most {DREAM_BUDGET_MAX_USD}"),
            None,
        );
    }
    let nightly = memory.dream_schedule == crate::model::DreamSchedule::Nightly;
    let cron = memory.dream_schedule == crate::model::DreamSchedule::Cron;
    if let Some(at) = &memory.dream_at {
        if let Err(e) = crate::cron::parse_time(at) {
            d.error("memory.dream_at", e, None);
        } else if !nightly {
            d.warn(
                "memory.dream_at",
                "is used only with dream_schedule = \"nightly\"",
                None,
            );
        }
    }
    match (&memory.dream_cron, cron) {
        (Some(expr), _) if crate::cron::check_cron(expr).is_err() => {
            let e = crate::cron::check_cron(expr).unwrap_err();
            d.error("memory.dream_cron", e, None);
        }
        (Some(_), false) => d.warn(
            "memory.dream_cron",
            "is used only with dream_schedule = \"cron\"",
            None,
        ),
        (None, true) => d.error(
            "memory.dream_schedule",
            "is \"cron\" but memory.dream_cron is missing",
            Some(r#"add dream_cron = "15 2 * * 1-5", or use "nightly" with dream_at"#),
        ),
        _ => {}
    }
    if let Some(turns) = memory.dream_max_turns
        && !(1..=DREAM_MAX_TURNS_LIMIT).contains(&turns)
    {
        d.error(
            "memory.dream_max_turns",
            format!("must be between 1 and {DREAM_MAX_TURNS_LIMIT}"),
            None,
        );
    }
}

/// A skill name, or `plugin:skill`: what an agent's `skills` and Claude's
/// skill listing call it.
fn external_skill_problem(name: &str) -> Option<String> {
    let ok = |part: &str| {
        !part.is_empty()
            && part.len() <= 64
            && part
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || "-_.".contains(c))
    };
    let valid = match name.split_once(':') {
        Some((plugin, skill)) => ok(plugin) && ok(skill),
        None => ok(name),
    };
    (!valid).then(|| {
        format!(
            "`{}` is not a skill name: use letters, digits, `-`, `_` and `.`, and `plugin:skill` for a plugin's",
            name.escape_debug()
        )
    })
}

/// These strings are pasted into permission rules such as `Read(...)`; a
/// paren, comma or line break could end the rule and start another.
fn rule_text_problem(text: &str) -> Option<String> {
    if text.is_empty() {
        return Some("must not be empty".into());
    }
    if text
        .chars()
        .any(|c| c.is_whitespace() || c.is_control() || "(),".contains(c))
    {
        return Some(format!(
            "`{}` contains whitespace, a parenthesis or a comma",
            text.escape_debug()
        ));
    }
    None
}

fn agents(spec: &Spec, d: &mut Diagnostics) {
    for (name, agent) in &spec.agent {
        let at = |field: &str| format!("agent.{name}.{field}");
        if let Err(e) = check_name(name) {
            d.error(format!("agent.{name}"), e, None);
        }

        match &agent.rule_of_two {
            None => d.error(
                at("rule_of_two"),
                "is missing: say which Rule of Two properties this agent has",
                Some(
                    r#"list any of "untrusted_input", "private_data", "external_action"; an empty list is fine"#,
                ),
            ),
            Some(caps) => {
                let distinct: BTreeSet<Capability> = caps.iter().copied().collect();
                if distinct.len() != caps.len() {
                    d.error(at("rule_of_two"), "lists a property twice", None);
                }
                let all_three = distinct.len() == Capability::ALL.len();
                match (all_three, agent.human_gate.is_some()) {
                    (true, false) => d.error(
                        at("rule_of_two"),
                        "has all three Rule of Two properties: an agent that reads untrusted \
                         input, sees private data and can act externally can be steered by a \
                         prompt injection into leaking or destroying that data",
                        Some(
                            "drop external_action (let a human push or publish) or split the \
                             agent in two; to build anyway, set human_gate = \"advisory\" and \
                             accept that the gate is advisory, not a boundary",
                        ),
                    ),
                    (true, true) => d.warn(
                        at("human_gate"),
                        "this agent has all three Rule of Two properties and builds only \
                         because of human_gate = \"advisory\": the gate is advisory, not a \
                         boundary",
                        None,
                    ),
                    (false, true) => d.warn(
                        at("human_gate"),
                        "is only needed when an agent has all three Rule of Two properties",
                        Some("remove it"),
                    ),
                    (false, false) => {}
                }
            }
        }

        match agent.description.as_deref().map(str::trim) {
            None => d.error(
                at("description"),
                "is missing: Claude decides when to use an agent from its description",
                Some("say what the agent does and when to use it"),
            ),
            Some("") => d.error(at("description"), "must not be empty", None),
            Some(text) => {
                frontmatter_text(d, &at("description"), text);
                if text.chars().count() > AGENT_DESCRIPTION_LONG {
                    d.warn(
                        at("description"),
                        format!(
                            "is over {AGENT_DESCRIPTION_LONG} characters, and every agent's \
                             description is in Claude's listing on every turn"
                        ),
                        None,
                    );
                }
            }
        }
        body_path(d, &at("prompt_file"), &agent.prompt_path(name));
        if let Some(model) = &agent.model {
            frontmatter_text(d, &at("model"), model);
        }
        if agent.max_turns == Some(0) {
            d.error(at("max_turns"), "must be at least 1", None);
        }
        agent_tools(agent, &at, d);

        for skill in &agent.skills {
            frontmatter_text(d, &at("skills"), skill);
            if !spec.skill.contains_key(skill) && !spec.policy.external_skills.contains(skill) {
                d.error(
                    at("skills"),
                    format!(
                        "skill `{skill}` is neither defined in this spec nor listed in \
                         policy.external_skills, so nobody has reviewed what the agent preloads"
                    ),
                    Some(
                        "define it with [skill.<name>], or read the personal or plugin skill and \
                         add its name (`plugin:skill` for a plugin's) to policy.external_skills",
                    ),
                );
            }
        }

        if let Some(memory) = &agent.memory
            && spec.is_phi(agent)
        {
            let why = if spec.is_phi_repo() {
                "this repository is listed in memory.phi_repos"
            } else {
                "its memory class is phi"
            };
            match memory.scope {
                Some(Scope::Project | Scope::User) => d.error(
                    at("memory.scope"),
                    format!(
                        "must be local because {why}: project memory is committed to the \
                         repository and user memory is shared across projects"
                    ),
                    Some(r#"remove scope or set scope = "local""#),
                ),
                Some(Scope::Local) => {}
                None => d.warn(
                    at("memory.scope"),
                    format!("set to local because {why}"),
                    None,
                ),
            }
        }
    }
}

/// True for a `Bash` permission that still allows any command: no scope, a
/// match-all scope, or a scope that only names an interpreter or wrapper.
pub fn is_unscoped_bash(tool: &str) -> bool {
    let tool = tool.trim();
    if tool == "Bash" {
        return true;
    }
    let Some(inner) = tool
        .strip_prefix("Bash(")
        .and_then(|rest| rest.strip_suffix(')'))
    else {
        return false;
    };
    let inner = inner.trim();
    if inner
        .chars()
        .all(|c| c == '*' || c == ':' || c.is_whitespace())
    {
        return true;
    }
    let first = inner
        .split(|c: char| c.is_whitespace() || c == ':')
        .next()
        .unwrap_or("");
    let program = first.rsplit('/').next().unwrap_or(first);
    INTERPRETERS.contains(&program)
}

/// The agent's `tools` and `disallowed_tools`: only Bash and Agent take a
/// specifier, since Claude Code can't scope the others per agent and
/// dropping the specifier would widen access.
fn agent_tools(agent: &crate::model::Agent, at: &dyn Fn(&str) -> String, d: &mut Diagnostics) {
    let known = |name: &str| KNOWN_TOOLS.contains(&name) || name.starts_with("mcp__");
    let Some(tools) = &agent.tools else {
        d.warn(
            at("tools"),
            "is not set, so the agent inherits every tool, including MCP tools and unscoped Bash",
            Some("list the tools it needs; tools = [] gives it none"),
        );
        return;
    };
    let mut names: BTreeSet<&str> = BTreeSet::new();
    let mut scoped_bash = false;
    for tool in tools {
        frontmatter_text(d, &at("tools"), tool);
        let Some(entry) = parse_tool(tool) else {
            d.error(
                at("tools"),
                format!("`{tool}` has an unclosed parenthesis"),
                None,
            );
            continue;
        };
        names.insert(entry.name);
        match (entry.name, entry.specifier) {
            ("Bash", _) if is_unscoped_bash(tool) => d.warn(
                at("tools"),
                format!("`{tool}` lets the agent run any command; the sandbox is the boundary"),
                Some("scope it to what the agent needs, such as Bash(cargo test *)"),
            ),
            ("Bash", Some(scope)) => match crate::BashPattern::parse(scope) {
                Ok(_) => scoped_bash = true,
                Err(e) => d.error(
                    at("tools"),
                    format!("`{tool}`: the scope {e}"),
                    Some("write the command as plain words, such as Bash(cargo test *)"),
                ),
            },
            ("Agent", _) | (_, None) => {}
            (name, Some(_)) => d.error(
                at("tools"),
                format!(
                    "`{tool}`: Claude Code can't scope an agent's {name} tool, and rendering it \
                     as {name} would allow all of it"
                ),
                Some(&format!("use {name}, or leave it out")),
            ),
        }
        if !known(entry.name) {
            d.warn(
                at("tools"),
                format!("`{}` is not a Claude Code tool mezha knows", entry.name),
                None,
            );
        }
    }
    if scoped_bash && names.contains("PowerShell") {
        d.error(
            at("tools"),
            "a scoped Bash entry is checked for Bash and Monitor only, so PowerShell would get around it",
            Some("drop PowerShell, or make Bash unscoped"),
        );
    }
    for tool in &agent.disallowed_tools {
        frontmatter_text(d, &at("disallowed_tools"), tool);
        match parse_tool(tool) {
            Some(entry) if entry.specifier.is_none() => {
                if names.contains(entry.name) {
                    d.error(
                        at("tools"),
                        format!("`{}` is in both tools and disallowed_tools", entry.name),
                        None,
                    );
                }
                if !known(entry.name) {
                    d.warn(
                        at("disallowed_tools"),
                        format!("`{}` is not a Claude Code tool mezha knows", entry.name),
                        None,
                    );
                }
            }
            _ => d.error(
                at("disallowed_tools"),
                format!("`{tool}`: disallowed_tools takes bare tool names"),
                None,
            ),
        }
    }
}

/// A body file: Markdown under `mezha/`, as a plain relative path.
pub fn body_path_problem(path: &str) -> Option<String> {
    let plain = !path.is_empty()
        && !path.contains('\\')
        && Path::new(path)
            .components()
            .all(|c| matches!(c, Component::Normal(_)))
        && !path
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..");
    if !plain {
        return Some(format!(
            "`{path}` must be a plain relative path (no `..`, `.`, leading `/` or `\\`)"
        ));
    }
    let parts: Vec<&str> = path.split('/').collect();
    if parts[0] != BODY_DIR || parts.len() < 2 {
        return Some(format!("`{path}` must be under {BODY_DIR}/"));
    }
    if parts
        .iter()
        .any(|p| p.eq_ignore_ascii_case(".claude") || p.eq_ignore_ascii_case(".git"))
    {
        return Some(format!("`{path}` may not be inside .claude or .git"));
    }
    if !path.ends_with(".md") {
        return Some(format!("`{path}` must be a Markdown file (.md)"));
    }
    None
}

fn body_path(d: &mut Diagnostics, at: &str, path: &str) {
    if let Some(problem) = body_path_problem(path) {
        d.error(
            at,
            problem,
            Some("keep bodies under mezha/, where compile's ask rule and the sandbox protect them"),
        );
    }
}

fn frontmatter_text(d: &mut Diagnostics, at: &str, text: &str) {
    if let Some(problem) = frontmatter_problem(text) {
        d.error(at, problem, None);
    }
}

fn skills(spec: &Spec, d: &mut Diagnostics) {
    for (name, skill) in &spec.skill {
        let at = |field: &str| format!("skill.{name}.{field}");
        if let Err(e) = check_name(name) {
            d.error(format!("skill.{name}"), e, None);
        }
        body_path(d, &at("body_file"), &skill.body_path(name));
        frontmatter_text(d, &at("description"), &skill.description);
        if let Some(when) = &skill.when_to_use {
            frontmatter_text(d, &at("when_to_use"), when);
        }
        for (field, list) in [
            ("paths", &skill.paths),
            ("arguments", &skill.arguments),
            ("allowed_tools", &skill.allowed_tools),
        ] {
            for item in list {
                frontmatter_text(d, &at(field), item);
            }
        }

        for tool in &skill.allowed_tools {
            if is_unscoped_bash(tool) {
                d.error(
                    at("allowed_tools"),
                    format!("`{tool}` lets the skill run any command without asking"),
                    Some("scope it to the commands the skill needs, such as Bash(cargo test *)"),
                );
            }
        }

        let description = skill.description.trim();
        if description.is_empty() {
            d.error(at("description"), "must not be empty", None);
        }
        let listing = skill.description.chars().count()
            + skill
                .when_to_use
                .as_deref()
                .map_or(0, |w| w.chars().count());
        if listing > SKILL_LISTING_MAX {
            d.error(
                at("description"),
                format!(
                    "description and when_to_use are {listing} characters together; Claude's \
                     skill listing keeps only {SKILL_LISTING_MAX}"
                ),
                None,
            );
        }

        match skill.preset {
            Preset::Command => {
                if skill.user_invocable == Some(false) {
                    d.error(
                        at("user_invocable"),
                        "a command skill hidden from the user can't be invoked at all, \
                         because Claude never invokes command skills itself",
                        Some("remove user_invocable or use preset = \"knowledge\""),
                    );
                }
            }
            Preset::Knowledge => {
                if !description.is_empty()
                    && description.chars().count() < KNOWLEDGE_DESCRIPTION_MIN
                {
                    d.error(
                        at("description"),
                        format!(
                            "is shorter than {KNOWLEDGE_DESCRIPTION_MIN} characters, too \
                             little for Claude to know when to load it"
                        ),
                        None,
                    );
                }
                if !description.to_lowercase().contains("use when") {
                    d.error(
                        at("description"),
                        "a knowledge skill's description must say \"Use when ...\"",
                        Some("end it with a sentence such as \"Use when writing Rust code.\""),
                    );
                }
            }
        }
    }
}

fn rules(spec: &Spec, d: &mut Diagnostics) {
    for (name, rule) in &spec.rule {
        if let Err(e) = check_name(name) {
            d.error(format!("rule.{name}"), e, None);
        }
        body_path(d, &format!("rule.{name}.body_file"), &rule.body_path(name));
        for path in &rule.paths {
            frontmatter_text(d, &format!("rule.{name}.paths"), path);
        }
        if rule.max_lines == Some(0) {
            d.error(format!("rule.{name}.max_lines"), "must be at least 1", None);
        }
        if rule.paths.is_empty() {
            d.warn(
                format!("rule.{name}.paths"),
                "a rule without paths loads like CLAUDE.md and is paid for on every turn",
                Some(r#"add paths, such as paths = ["src/**/*.rs"]"#),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::is_unscoped_bash;

    #[test]
    fn unscoped_bash() {
        for any in [
            "Bash",
            " Bash ",
            "Bash()",
            "Bash(*)",
            "Bash(:*)",
            "Bash(**)",
            "Bash(* *)",
            "Bash(sh *)",
            "Bash(bash -c *)",
            "Bash(env *)",
            "Bash(xargs:*)",
            "Bash(sudo *)",
            "Bash(/bin/sh *)",
        ] {
            assert!(is_unscoped_bash(any), "{any}");
        }
        for scoped in [
            "Bash(cargo test *)",
            "Bash(git tag *)",
            "Bash(git describe:*)",
            "Read",
            "Bashful",
        ] {
            assert!(!is_unscoped_bash(scoped), "{scoped}");
        }
    }
}
