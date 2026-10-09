//! `plugin-validate`: `claude plugin validate .claude`, Claude Code's own
//! check of the agents and skills in the project. It doesn't check rules,
//! and a pass doesn't prove the YAML (anthropics/claude-code#100078), so
//! mezha's own frontmatter tests stay the real guard.

use std::path::Path;
use std::time::Duration;

use serde_json::Value;

use crate::Options;
use crate::ctx::Ctx;
use crate::report::{Check, Findings, Kind, Status};
use crate::runner::{Run, run};
use crate::scratch::Scratch;

const NOTE: &str = "rules aren't checked, and a pass isn't proof of the YAML";

fn new_check() -> Check {
    Check::new("plugin-validate", "claude plugin validate", Kind::Integrity)
}

pub fn check(ctx: &Ctx, opts: &Options) -> Check {
    let skip = |why: &str| {
        Check::skip(
            "plugin-validate",
            "claude plugin validate",
            Kind::Integrity,
            why,
        )
    };
    if opts.project_only {
        return skip("needs the claude CLI, which --project-only doesn't run");
    }
    let target = ctx.root.join(".claude");
    if !target.is_dir() {
        return skip("there is no .claude directory");
    }
    let mut f = Findings::default();
    let found = ctx.which_trusted("claude");
    if let Some(note) = found.skipped_note("claude") {
        f.warn(note, None);
    }
    let Some(claude) = found.path else {
        return skip("the `claude` CLI isn't on PATH");
    };
    let Ok(scratch) = Scratch::new("mezha-plugin") else {
        f.warn("couldn't create a scratch directory to run claude in", None);
        return f.into_check(new_check(), "");
    };
    let target_text = target.to_string_lossy();
    let out = run(
        ctx,
        &Run {
            program: &claude,
            args: &["plugin", "validate", &target_text, "--json"],
            cwd: scratch.path(),
            env: &[("DISABLE_AUTOUPDATER", "1")],
            remove: &["CLAUDECODE", "CLAUDE_CODE_ENTRYPOINT"],
            stdin: b"",
            timeout: Duration::from_secs(60),
        },
    );
    let out = match out {
        Ok(out) if !out.timed_out => out,
        Ok(_) => {
            f.warn("claude plugin validate timed out", None);
            return f.into_check(new_check(), "");
        }
        Err(e) => {
            f.warn(format!("claude plugin validate couldn't run ({e})"), None);
            return f.into_check(new_check(), "");
        }
    };
    let (errors, warnings) = findings(&out.stdout, &ctx.root);
    match out.code {
        Some(0) if warnings.is_empty() => f.add(
            Status::Pass,
            format!("agents and skills pass ({NOTE})"),
            None,
        ),
        Some(0) => f.warn(
            format!("passes with warnings: {}", warnings.join("; ")),
            None,
        ),
        Some(1) => {
            let listed = if errors.is_empty() {
                "see `claude plugin validate .claude`".to_string()
            } else {
                errors.join("; ")
            };
            f.fail(
                format!("fails: {listed}"),
                "Fix the files listed; for generated ones, fix the body under mezha/ or mezha.toml and run `mezha compile`.",
            );
        }
        code => {
            let why = out
                .stderr
                .lines()
                .find(|l| !l.trim().is_empty())
                .unwrap_or("no message");
            f.warn(
                format!(
                    "claude plugin validate couldn't finish (exit {}): {why}",
                    code.map_or("by signal".to_string(), |c| c.to_string())
                ),
                None,
            );
        }
    }
    f.into_check(new_check(), "")
}

/// `file: message` for each error and warning in the JSON report, with
/// paths shown relative to the project.
fn findings(stdout: &str, root: &Path) -> (Vec<String>, Vec<String>) {
    let Ok(report) = serde_json::from_str::<Value>(stdout) else {
        return (Vec::new(), Vec::new());
    };
    let root = std::fs::canonicalize(root).unwrap_or_else(|_| root.to_path_buf());
    let mut errors = Vec::new();
    let mut warnings = Vec::new();
    for item in report["contents"].as_array().into_iter().flatten() {
        let file = item["file"].as_str().unwrap_or("?");
        let canonical = std::fs::canonicalize(file).unwrap_or_else(|_| file.into());
        let shown = canonical
            .strip_prefix(&root)
            .map(|p| p.display().to_string())
            .unwrap_or_else(|_| file.to_string());
        for (key, list) in [("errors", &mut errors), ("warnings", &mut warnings)] {
            for entry in item[key].as_array().into_iter().flatten() {
                let message = entry["message"].as_str().unwrap_or("?");
                let first = message.lines().next().unwrap_or(message);
                list.push(format!("{shown}: {first}"));
            }
        }
    }
    (errors, warnings)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_json_report() {
        let tmp = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(tmp.path()).unwrap();
        let file = root.join(".claude/agents/bad.md");
        let report = serde_json::json!({
            "success": false,
            "contents": [{
                "file": file,
                "errors": [{"path": "frontmatter", "message": "YAML frontmatter failed to parse\nmore"}],
                "warnings": [{"path": "description", "message": "No description"}]
            }]
        });
        let (errors, warnings) = findings(&report.to_string(), &root);
        assert_eq!(
            errors,
            [".claude/agents/bad.md: YAML frontmatter failed to parse"]
        );
        assert_eq!(warnings, [".claude/agents/bad.md: No description"]);
        assert_eq!(findings("not json", &root), (Vec::new(), Vec::new()));
    }
}
