//! The compiler rules (`mezha-plan.md` section 4). Every rule runs, so one
//! pass reports everything; any error means nothing gets written.

use std::collections::BTreeSet;

use crate::model::{Capability, Preset, Scope, Spec};
use crate::{CommandPrefix, SCHEMA_VERSION, check_name};

/// `description` + `when_to_use` beyond this are cut from Claude's skill listing.
pub const SKILL_LISTING_MAX: usize = 1536;
/// Knowledge skills need a description Claude can match against.
pub const KNOWLEDGE_DESCRIPTION_MIN: usize = 40;

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
    if !policy.sandbox {
        d.warn(
            "policy.sandbox",
            "the sandbox is off: agent commands can write the approval store, so the \
             `git push` gate is advisory only",
            None,
        );
    }
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

        let disallowed: BTreeSet<&str> =
            agent.disallowed_tools.iter().map(String::as_str).collect();
        for tool in &agent.tools {
            if disallowed.contains(tool.as_str()) {
                d.error(
                    at("tools"),
                    format!("`{tool}` is in both tools and disallowed_tools"),
                    None,
                );
            }
        }

        for skill in &agent.skills {
            if !spec.skill.contains_key(skill) {
                d.warn(
                    at("skills"),
                    format!(
                        "skill `{skill}` is not defined in this spec; it must come from a \
                         plugin or the user's own skills"
                    ),
                    None,
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

fn skills(spec: &Spec, d: &mut Diagnostics) {
    for (name, skill) in &spec.skill {
        let at = |field: &str| format!("skill.{name}.{field}");
        if let Err(e) = check_name(name) {
            d.error(format!("skill.{name}"), e, None);
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
