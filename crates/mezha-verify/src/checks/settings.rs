//! `settings-intact`: are the generated files (settings, agents, skills,
//! rules) what `mezha.toml` renders to, and does the gate in the settings
//! actually block? Only mezha's own render is ever run, never a command
//! found on disk.

use std::collections::BTreeMap;
use std::time::Duration;

use mezha_render::Rendered;
use mezha_render::state::{STATE_PATH, fingerprint, normalize};
use serde_json::{Value, json};

use crate::Options;
use crate::ctx::{Ctx, Platform};
use crate::layers::PROJECT_SETTINGS;
use crate::report::{Check, Findings, Kind};
use crate::runner::{Run, run};
use crate::scratch::Scratch;

const COMPILE: &str =
    "Run `mezha diff`, then `mezha compile` (or `mezha apply` to back up and replace hand edits).";

pub fn check(ctx: &Ctx, rendered: &Rendered, opts: &Options) -> Check {
    let check = Check::new(
        "settings-intact",
        "generated files and the gate",
        Kind::Integrity,
    );
    let mut f = Findings::default();
    for problem in &rendered.problems {
        f.fail(
            format!("can't render {problem}"),
            "Fix the body file under mezha/, then run `mezha compile`.",
        );
    }
    let recorded = recorded_prints(ctx);
    let mut settings_trusted = true;
    for (path, expected) in &rendered.files {
        let is_settings = path == PROJECT_SETTINGS;
        let Ok(disk) = std::fs::read_to_string(ctx.root.join(path)) else {
            f.fail(format!("{path} is missing"), "Run `mezha compile`.");
            settings_trusted &= !is_settings;
            continue;
        };
        let same = if is_settings {
            serde_json::from_str::<Value>(&disk).ok() == serde_json::from_str(expected).ok()
        } else {
            normalize(&disk) == normalize(expected)
        };
        if same {
            continue;
        }
        if recorded.get(path) == Some(&fingerprint(&disk)) {
            f.warn(
                format!("{path} is mezha's output from an older mezha.toml"),
                Some(COMPILE.into()),
            );
        } else {
            let why = if is_settings {
                ", so its gate and sandbox settings are unverified"
            } else {
                ""
            };
            f.fail(format!("{path} was edited by hand{why}"), COMPILE);
            settings_trusted &= !is_settings;
        }
    }
    let unmanaged = unmanaged_files(ctx, rendered);
    if !unmanaged.is_empty() {
        f.warn(
            format!(
                "not managed by mezha: {}; such files skip mezha's checks (such as rule_of_two) and an agent file can set its own permissionMode",
                unmanaged.join(", ")
            ),
            Some("Add them to mezha.toml with a body under mezha/, or remove them.".into()),
        );
    }

    if settings_trusted && !opts.project_only {
        let settings: Value = serde_json::from_str(&rendered.files[PROJECT_SETTINGS])
            .expect("mezha renders valid JSON");
        probe_gate(ctx, &settings, &mut f);
        probe_agent_hooks(ctx, rendered, &mut f);
    }
    f.into_check(check, "match mezha.toml, and the gate blocks a push")
}

/// Runs each generated agent's `agent-bash` hook as Claude Code would: a
/// command in its first scope must pass, and one outside every scope must
/// be blocked.
fn probe_agent_hooks(ctx: &Ctx, rendered: &Rendered, f: &mut Findings) {
    let hooks: Vec<(&str, String)> = rendered
        .files
        .iter()
        .filter(|(path, _)| path.starts_with(".claude/agents/"))
        .filter_map(|(path, text)| {
            let line = text
                .lines()
                .find_map(|l| l.trim_start().strip_prefix("- command: "))?;
            let command: String = serde_json::from_str(line).ok()?;
            command
                .contains("hook agent-bash")
                .then_some((path.as_str(), command))
        })
        .collect();
    if hooks.is_empty() || ctx.platform == Platform::Windows {
        return;
    }
    let (Some(_), Some(bash)) = (
        ctx.which_trusted("mezha").path,
        ctx.which_trusted("bash").path,
    ) else {
        return;
    };
    let mut wrong = Vec::new();
    for (path, command) in hooks {
        let Some(allowed) = first_scope_example(&command) else {
            continue;
        };
        for (cmd, expect) in [(allowed.as_str(), 0), ("mezha-verify-out-of-scope", 2)] {
            let event = json!({
                "hook_event_name": "PreToolUse",
                "tool_name": "Bash",
                "tool_input": { "command": cmd },
            });
            let out = run(
                ctx,
                &Run {
                    program: &bash,
                    args: &["-c", &command],
                    cwd: &ctx.root,
                    env: &[],
                    remove: &[],
                    stdin: event.to_string().as_bytes(),
                    timeout: Duration::from_secs(20),
                },
            );
            let code = out.as_ref().ok().and_then(|o| o.code);
            if code != Some(expect) {
                let got = code.map_or("no exit code".to_string(), |c| format!("exit {c}"));
                wrong.push(format!(
                    "{path}: `{cmd}` gave {got}, expected exit {expect}"
                ));
            }
        }
    }
    if !wrong.is_empty() {
        f.fail(
            format!("an agent's Bash hook doesn't behave: {}", wrong.join(", ")),
            "Reinstall mezha and run `mezha compile`; if it persists, report a mezha bug.",
        );
    }
}

/// A command inside the first `--allow '...'` scope: its words, with a
/// trailing `*` dropped and a middle one replaced by `x`.
fn first_scope_example(command: &str) -> Option<String> {
    let scope = command.split("--allow '").nth(1)?.split('\'').next()?;
    let words: Vec<&str> = scope.split_whitespace().collect();
    let (last, init) = words.split_last()?;
    let mut example: Vec<&str> = init
        .iter()
        .map(|w| if *w == "*" { "x" } else { w })
        .collect();
    if *last != "*" {
        example.push(last);
    }
    Some(example.join(" "))
}

/// The fingerprints the state file records, by path.
fn recorded_prints(ctx: &Ctx) -> BTreeMap<String, String> {
    std::fs::read_to_string(ctx.root.join(STATE_PATH))
        .ok()
        .and_then(|t| serde_json::from_str::<Value>(&t).ok())
        .and_then(|s| s["files"].as_object().cloned())
        .map(|files| {
            files
                .into_iter()
                .filter_map(|(k, v)| Some((k, v.as_str()?.to_string())))
                .collect()
        })
        .unwrap_or_default()
}

/// Agent, skill, rule and command files under `.claude/` that mezha
/// doesn't generate.
fn unmanaged_files(ctx: &Ctx, rendered: &Rendered) -> Vec<String> {
    let claude = ctx.root.join(".claude");
    let mut found = Vec::new();
    let md_in = |dir: &str, found: &mut Vec<String>| {
        for entry in std::fs::read_dir(claude.join(dir))
            .into_iter()
            .flatten()
            .flatten()
        {
            let name = entry.file_name().to_string_lossy().into_owned();
            let path = entry.path();
            if name.ends_with(".md") && path.is_file() {
                found.push(format!(".claude/{dir}/{name}"));
            } else if path.is_dir() && dir != "skills" {
                // Rules and commands are found in subdirectories too.
                for inner in std::fs::read_dir(&path).into_iter().flatten().flatten() {
                    let inner_name = inner.file_name().to_string_lossy().into_owned();
                    if inner_name.ends_with(".md") {
                        found.push(format!(".claude/{dir}/{name}/{inner_name}"));
                    }
                }
            } else if path.is_dir() && path.join("SKILL.md").is_file() {
                found.push(format!(".claude/{dir}/{name}/SKILL.md"));
            }
        }
    };
    for dir in ["agents", "skills", "rules", "commands"] {
        md_in(dir, &mut found);
    }
    found.retain(|p| !rendered.files.contains_key(p));
    found.sort();
    found
}

/// Runs the rendered hook command the way Claude Code would, with a scratch
/// home so no real approval can hide a broken gate.
fn probe_gate(ctx: &Ctx, settings: &Value, f: &mut Findings) {
    let install = "Install it: `cargo install --locked --force --path crates/mezha-cli` in the mezha repository (`--force` replaces an older mezha of the same version).";
    let found = ctx.which_trusted("mezha");
    if let Some(note) = found.skipped_note("mezha") {
        f.warn(note, None);
    }
    let Some(mezha) = found.path else {
        f.warn(
            "`mezha` is not on PATH, so Claude Code will block every tool call (fail-closed)",
            Some(install.into()),
        );
        return;
    };
    if let (Some(exe), Ok(found)) = (&ctx.mezha_exe, std::fs::canonicalize(&mezha))
        && std::fs::canonicalize(exe).is_ok_and(|e| e != found)
    {
        f.warn(
            format!(
                "the `mezha` on PATH ({}) is not the one running verify",
                found.display()
            ),
            None,
        );
    }
    let version = run(
        ctx,
        &Run {
            program: &mezha,
            args: &["--version"],
            cwd: &ctx.root,
            env: &[],
            remove: &[],
            stdin: b"",
            timeout: Duration::from_secs(10),
        },
    )
    .map(|o| o.stdout)
    .unwrap_or_default();
    let protocol = format!("(hook protocol {})", mezha_hooks::PROTOCOL);
    if !version.contains(&protocol) {
        f.warn(
            format!(
                "the `mezha` on PATH speaks a different hook protocol than this one ({}), so Claude Code will block every tool call",
                version.trim()
            ),
            Some(install.into()),
        );
        return;
    }
    if ctx.platform == Platform::Windows {
        f.warn("the gate probe doesn't run on native Windows yet", None);
        return;
    }
    let found = ctx.which_trusted("bash");
    if let Some(note) = found.skipped_note("bash") {
        f.warn(note, None);
    }
    let Some(bash) = found.path else {
        f.warn("bash is not on PATH, so the gate wasn't probed", None);
        return;
    };
    let Some(command) = settings["hooks"]["PreToolUse"][0]["hooks"][0]["command"].as_str() else {
        f.fail(
            "the rendered settings have no gate",
            "Report this as a mezha bug.",
        );
        return;
    };
    let Ok(scratch) = Scratch::new("mezha-verify") else {
        f.warn(
            "couldn't create a scratch directory for the gate probe",
            None,
        );
        return;
    };
    let mut wrong = Vec::new();
    let mut probes = vec![
        ("Bash", "git push origin main", 2),
        ("Bash", "mezha approve --minutes 5", 2),
        ("Bash", "git status", 0),
    ];
    // With fetch_allow, WebFetch to a host outside it must be blocked.
    if command.contains("--fetch-only") {
        probes.push(("WebFetch", "https://mezha-verify.invalid/", 2));
    }
    for &(tool, cmd, expect) in &probes {
        let input = if tool == "WebFetch" {
            json!({ "url": cmd, "prompt": "x" })
        } else {
            json!({ "command": cmd })
        };
        let event = json!({
            "session_id": "mezha-verify",
            "hook_event_name": "PreToolUse",
            "tool_name": tool,
            "tool_input": input,
            "cwd": ctx.root,
        });
        let home = scratch.path().to_string_lossy().into_owned();
        let root = ctx.root.to_string_lossy().into_owned();
        let out = run(
            ctx,
            &Run {
                program: &bash,
                args: &["-c", command],
                cwd: &ctx.root,
                env: &[
                    ("HOME", &home),
                    ("USERPROFILE", &home),
                    ("CLAUDE_PROJECT_DIR", &root),
                ],
                remove: &["CLAUDE_CONFIG_DIR"],
                stdin: event.to_string().as_bytes(),
                timeout: Duration::from_secs(20),
            },
        );
        let code = out.as_ref().ok().and_then(|o| o.code);
        if code != Some(expect) {
            let got = code.map_or("no exit code".to_string(), |c| format!("exit {c}"));
            wrong.push(format!("`{cmd}` gave {got}, expected exit {expect}"));
        }
    }
    let root = mezha_broker::repo_root(&ctx.root);
    let logged = audit_records(&mezha_hooks::audit::dir(scratch.path(), Some(&root)));
    drop(scratch);
    if !wrong.is_empty() {
        f.fail(
            format!("the gate doesn't behave: {}", wrong.join(", ")),
            "Reinstall mezha and run `mezha compile`; if it persists, report a mezha bug.",
        );
    } else if logged < probes.len() {
        f.fail(
            format!(
                "the gate decided {} calls but wrote {logged} audit record(s)",
                probes.len()
            ),
            "Reinstall mezha and run `mezha compile`; if it persists, report a mezha bug.",
        );
    }
}

/// Lines in the audit log files under `dir`.
fn audit_records(dir: &std::path::Path) -> usize {
    std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter(|e| e.path().extension().is_some_and(|x| x == "jsonl"))
        .filter_map(|e| std::fs::read_to_string(e.path()).ok())
        .map(|t| t.lines().count())
        .sum()
}

#[cfg(test)]
mod tests {
    use super::first_scope_example;

    #[test]
    fn scope_examples() {
        let ex = |c: &str| first_scope_example(c);
        assert_eq!(
            ex("mezha hook agent-bash --protocol 1 --allow 'cargo test *' --allow 'git status' || exit 2")
                .as_deref(),
            Some("cargo test")
        );
        assert_eq!(
            ex("mezha hook agent-bash --protocol 1 --allow 'git * main' || exit 2").as_deref(),
            Some("git x main")
        );
        assert_eq!(
            ex("mezha hook agent-bash --protocol 1 --allow 'cargo fmt --check' || exit 2")
                .as_deref(),
            Some("cargo fmt --check")
        );
        assert_eq!(ex("mezha hook agent-bash --protocol 1 || exit 2"), None);
    }
}
