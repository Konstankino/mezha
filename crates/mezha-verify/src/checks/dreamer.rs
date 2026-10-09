//! `dreamer`: agent memory is clean and governed. Memory becomes part of an
//! agent's instructions, so it is checked like a boundary file: no hidden
//! characters, secrets or remote images (the hard scan `mezha dream` runs
//! too), no PHI in committed memory when the spec has PHI, no changes made
//! outside a dream, and code owners who review memory changes. The dreamer
//! itself is defined only at dream time, with its tools fixed in code.

use std::path::{Path, PathBuf};
use std::time::Duration;

use mezha_memory::review::{INDEX, MEMORY_BYTES, MEMORY_LINES};
use mezha_memory::scan::{self, Level, Scan};
use mezha_spec::{Scope, Spec};
use regex::Regex;

use crate::Options;
use crate::ctx::Ctx;
use crate::report::{Check, Findings, Kind};
use crate::runner::{Run, run};

const ID: &str = "dreamer";
const TITLE: &str = "agent memory is clean and reviewed";

/// Where GitHub looks for CODEOWNERS, in order; the first one found wins.
const CODEOWNERS: [&str; 3] = [".github/CODEOWNERS", "CODEOWNERS", "docs/CODEOWNERS"];

pub fn check(ctx: &Ctx, spec: &Spec, opts: &Options) -> Check {
    let roles: Vec<(&str, Scope)> = spec
        .agent
        .iter()
        .filter_map(|(n, a)| Some((n.as_str(), spec.memory_scope(a)?)))
        .collect();
    if roles.is_empty() {
        return Check::skip(ID, TITLE, Kind::Integrity, "no agent has memory");
    }
    let mut f = Findings::default();
    let phi = spec.has_phi();

    // Committed project memory, as it is on disk.
    let found = ctx.which_trusted("git");
    if let Some(note) = found.skipped_note("git") {
        f.warn(note, None);
    }
    let git = |args: &[&str]| {
        let program = found.path.as_deref()?;
        let mut full = vec!["-c", "core.fsmonitor=false"];
        full.extend_from_slice(args);
        run(
            ctx,
            &Run {
                program,
                args: &full,
                cwd: &ctx.root,
                env: &[("GIT_TERMINAL_PROMPT", "0")],
                remove: &[],
                stdin: b"",
                timeout: Duration::from_secs(10),
            },
        )
        .ok()
        .filter(|o| o.success())
        .map(|o| o.stdout)
    };
    match git(&["ls-files", "-z", "--", ".claude/agent-memory"]) {
        Some(listed) => {
            for rel in listed.split('\0').filter(|p| p.ends_with(".md")) {
                scan_file(&mut f, &ctx.root.join(rel), rel, phi);
            }
        }
        None => f.warn("git couldn't list the committed memory", None),
    }
    if let Some(changed) = git(&[
        "status",
        "--porcelain",
        "-z",
        "--untracked-files=all",
        "--",
        ".claude/agent-memory",
    ]) {
        let paths: Vec<&str> = changed
            .split('\0')
            .filter(|e| e.len() > 3)
            .map(|e| &e[3..])
            .collect();
        if !paths.is_empty() {
            f.warn(
                format!(
                    "memory changed outside a dream: {}",
                    paths
                        .iter()
                        .map(|p| scan::escape(p))
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
                Some(
                    "Sessions can't write memory, so a person or a tool did: commit it through \
                     review, or restore it with `git restore` and `git clean`."
                        .into(),
                ),
            );
        }
    }

    // Local and user memory on this machine. PHI belongs in local memory,
    // so it isn't PHI-scanned; the other hard markers still don't belong.
    if !opts.project_only {
        let config = ctx
            .var("CLAUDE_CONFIG_DIR")
            .map(PathBuf::from)
            .or_else(|| ctx.home.as_ref().map(|h| h.join(".claude")));
        for (role, scope) in &roles {
            let dir = match scope {
                Scope::Project => continue,
                Scope::Local => ctx.root.join(".claude/agent-memory-local").join(role),
                Scope::User => match &config {
                    Some(c) => c.join("agent-memory").join(role),
                    None => continue,
                },
            };
            for entry in std::fs::read_dir(&dir).into_iter().flatten().flatten() {
                let path = entry.path();
                let name = entry.file_name().to_string_lossy().into_owned();
                if name.ends_with(".md") && entry.file_type().is_ok_and(|t| t.is_file()) {
                    scan_file(&mut f, &path, &path.display().to_string(), false);
                }
            }
            if *scope == Scope::User && ctx.var("CLAUDE_CONFIG_DIR").is_some() {
                f.warn(
                    format!(
                        "agent.{role} has user memory in $CLAUDE_CONFIG_DIR/agent-memory, which \
                         the session deny rule `Edit(~/.claude/agent-memory/**)` doesn't cover"
                    ),
                    Some("Use project or local scope while CLAUDE_CONFIG_DIR is set.".into()),
                );
            }
        }
    }

    if roles.iter().any(|(_, s)| *s == Scope::Project) {
        codeowners(&mut f, &ctx.root, &roles);
    }
    // Claude Code turns agent memory off together with auto memory.
    let layers = crate::layers::Layers::load(ctx, opts.project_only);
    let setting_off = layers
        .winner("/autoMemoryEnabled")
        .is_some_and(|(v, _)| v == &serde_json::Value::Bool(false));
    let env_off = !opts.project_only
        && ctx
            .var("CLAUDE_CODE_DISABLE_AUTO_MEMORY")
            .is_some_and(|v| !matches!(v, "0" | "false"));
    if setting_off || env_off {
        f.warn(
            format!(
                "auto memory is off ({}), and Claude Code turns agent memory off with it: agents won't see their memory",
                if setting_off {
                    "autoMemoryEnabled = false"
                } else {
                    "CLAUDE_CODE_DISABLE_AUTO_MEMORY"
                }
            ),
            Some("Turn auto memory back on, or take `memory` off the agents.".into()),
        );
    }
    if !opts.project_only
        && let Some(home) = &ctx.home
    {
        last_scheduled_run(&mut f, home, &ctx.root);
    }
    f.into_check(
        Check::new(ID, TITLE, Kind::Integrity),
        "memory is clean and code owners review it; the dreamer exists only during `mezha dream`, \
         with Read, Grep, Glob, Edit and Write",
    )
}

/// Warns when the last dream a schedule ran failed: nobody was watching.
fn last_scheduled_run(f: &mut Findings, home: &Path, root: &Path) {
    let path = mezha_memory::dreams_dir(home, root).join("last-run.json");
    let Ok(text) = std::fs::read_to_string(&path) else {
        return;
    };
    let Ok(last) = serde_json::from_str::<serde_json::Value>(&text) else {
        return;
    };
    let scheduled = last.get("scheduled").and_then(serde_json::Value::as_bool) == Some(true);
    let ok = last.get("ok").and_then(serde_json::Value::as_bool) == Some(true);
    if scheduled && !ok {
        let at = last
            .get("at")
            .and_then(serde_json::Value::as_i64)
            .map(mezha_memory::time::format_iso)
            .unwrap_or_default();
        let error = last
            .get("error")
            .and_then(serde_json::Value::as_str)
            .map(scan::escape)
            .unwrap_or_default();
        f.warn(
            format!("the last scheduled dream ({at}) failed: {error}"),
            Some(format!(
                "Read {} and the schedule's log beside it, then run `mezha dream` yourself.",
                path.display()
            )),
        );
    }
}

/// Scans one memory file: hard markers (and PHI in committed memory of a
/// spec with PHI) fail, instruction-like phrases and budgets warn.
fn scan_file(f: &mut Findings, path: &Path, label: &str, phi: bool) {
    let Ok(text) = std::fs::read_to_string(path) else {
        return;
    };
    let mut phrases = 0;
    for finding in scan::findings(&text, Scan { phrases: true, phi }) {
        match finding.level {
            Level::Hard | Level::Phi => f.fail(
                format!(
                    "{label}:{}: {} ({})",
                    finding.line,
                    finding.what,
                    finding.excerpt(&text)
                ),
                "Agents load memory as instructions: remove it, then find how it got in.",
            ),
            Level::Phrase => phrases += 1,
        }
    }
    if phrases > 0 {
        f.warn(
            format!("{label}: {phrases} instruction-like phrase(s); read them in context"),
            None,
        );
    }
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy())
        .unwrap_or_default();
    if name == INDEX {
        let lines = text.lines().count();
        if lines > MEMORY_LINES || text.len() > MEMORY_BYTES {
            f.warn(
                format!(
                    "{label} has {lines} lines and {} bytes; Claude Code loads only the first \
                     {MEMORY_LINES} lines or {MEMORY_BYTES} bytes",
                    text.len()
                ),
                Some("Let the next dream compress it, or move details into topic files.".into()),
            );
        }
    }
}

/// Warns unless a CODEOWNERS rule gives every project-memory role an owner.
fn codeowners(f: &mut Findings, root: &Path, roles: &[(&str, Scope)]) {
    let fix = "Add `/.claude/agent-memory/ @your-team` to CODEOWNERS, and require code owner \
               reviews on the default branch (see branch-protection)."
        .to_string();
    let Some((file, text)) = CODEOWNERS
        .iter()
        .find_map(|rel| Some((*rel, std::fs::read_to_string(root.join(rel)).ok()?)))
    else {
        f.warn(
            "there is no CODEOWNERS file, so nobody in particular has to review memory changes",
            Some(fix),
        );
        return;
    };
    let rules: Vec<(Regex, bool)> = text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .filter_map(|l| {
            let mut words = l.split_whitespace();
            let pattern = words.next()?;
            let owned = words.next().is_some_and(|w| !w.starts_with('#'));
            Some((owner_pattern(pattern)?, owned))
        })
        .collect();
    let unowned: Vec<&str> = roles
        .iter()
        .filter(|(_, s)| *s == Scope::Project)
        .map(|(role, _)| *role)
        .filter(|role| {
            let path = format!(".claude/agent-memory/{role}/{INDEX}");
            // The last matching rule wins; a rule without owners clears them.
            !rules
                .iter()
                .rev()
                .find(|(re, _)| re.is_match(&path))
                .is_some_and(|(_, owned)| *owned)
        })
        .collect();
    if !unowned.is_empty() {
        f.warn(
            format!(
                "{file} gives no owner to the memory of {}",
                unowned.join(", ")
            ),
            Some(fix),
        );
    }
}

/// A CODEOWNERS pattern (gitignore rules, as GitHub reads them) as a regex
/// over a path relative to the repository root.
fn owner_pattern(pattern: &str) -> Option<Regex> {
    let dir_only = pattern.ends_with('/');
    let body = pattern.trim_end_matches('/');
    let anchored = body.starts_with('/') || body.contains('/');
    let body = body.trim_start_matches('/');
    if body.is_empty() {
        return None;
    }
    let mut re = String::from("^");
    if !anchored {
        re.push_str("(?:.*/)?");
    }
    let chars: Vec<char> = body.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        match chars[i] {
            '*' if chars.get(i + 1) == Some(&'*') => {
                if chars.get(i + 2) == Some(&'/') {
                    re.push_str("(?:.*/)?");
                    i += 3;
                } else {
                    re.push_str(".*");
                    i += 2;
                }
                continue;
            }
            '*' => re.push_str("[^/]*"),
            '?' => re.push_str("[^/]"),
            c => re.push_str(&regex::escape(&c.to_string())),
        }
        i += 1;
    }
    re.push_str(if dir_only { "/.*$" } else { "(?:/.*)?$" });
    Regex::new(&re).ok()
}

#[cfg(test)]
mod tests {
    use super::owner_pattern;

    #[test]
    fn codeowners_patterns() {
        let path = ".claude/agent-memory/implementer/MEMORY.md";
        for (pattern, matches) in [
            ("*", true),
            ("/.claude/agent-memory/", true),
            (".claude/agent-memory/", true),
            ("/.claude/", true),
            ("/.claude/agent-memory/**", true),
            ("**/agent-memory", true),
            ("agent-memory/", true),
            ("*.md", true),
            ("/.claude/agent-memory/explorer/", false),
            ("/docs/", false),
            ("/agent-memory/", false),
        ] {
            let re = owner_pattern(pattern).unwrap();
            assert_eq!(re.is_match(path), matches, "{pattern}");
        }
    }
}
