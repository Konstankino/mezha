//! `settings-intact`: is `.claude/settings.json` what `mezha.toml` renders
//! to, and does the gate in it actually block? Only mezha's own render is
//! ever run, never a command found on disk.

use std::path::PathBuf;
use std::time::Duration;

use mezha_render::Rendered;
use mezha_render::state::{STATE_PATH, fingerprint};
use serde_json::{Value, json};

use crate::Options;
use crate::ctx::{Ctx, Platform};
use crate::layers::PROJECT_SETTINGS;
use crate::report::{Check, Findings, Kind};
use crate::runner::{Run, run};

pub fn check(ctx: &Ctx, rendered: &Rendered, opts: &Options) -> Check {
    let check = Check::new(
        "settings-intact",
        "generated settings and the gate",
        Kind::Integrity,
    );
    let mut f = Findings::default();
    let expected_text = &rendered.files[PROJECT_SETTINGS];
    let expected: Value = serde_json::from_str(expected_text).expect("mezha renders valid JSON");
    let compile = "Run `mezha diff`, then `mezha compile` (or `mezha apply` to back up and replace hand edits).";

    let Ok(disk_text) = std::fs::read_to_string(ctx.root.join(PROJECT_SETTINGS)) else {
        f.fail(
            format!("{PROJECT_SETTINGS} is missing"),
            "Run `mezha compile`.",
        );
        return f.into_check(check, "");
    };
    let disk: Option<Value> = serde_json::from_str(&disk_text).ok();
    if disk.as_ref() != Some(&expected) {
        let state_print = std::fs::read_to_string(ctx.root.join(STATE_PATH))
            .ok()
            .and_then(|t| serde_json::from_str::<Value>(&t).ok())
            .and_then(|s| s["files"][PROJECT_SETTINGS].as_str().map(str::to_string));
        if state_print.as_deref() == Some(fingerprint(&disk_text).as_str()) {
            f.warn(
                format!("{PROJECT_SETTINGS} is mezha's output from an older mezha.toml"),
                Some(compile.into()),
            );
        } else {
            f.fail(
                format!(
                    "{PROJECT_SETTINGS} was edited by hand, so its gate and sandbox settings are unverified"
                ),
                compile,
            );
            return f.into_check(check, "");
        }
    }

    if !opts.project_only {
        probe_gate(ctx, &expected, &mut f);
    }
    f.into_check(check, "matches mezha.toml, and the gate blocks a push")
}

/// Runs the rendered hook command the way Claude Code would, with a scratch
/// home so no real approval can hide a broken gate.
fn probe_gate(ctx: &Ctx, settings: &Value, f: &mut Findings) {
    let install =
        "Install it: `cargo install --locked --path crates/mezha-cli` in the mezha repository.";
    let Some(mezha) = ctx.which("mezha") else {
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
    let Some(bash) = ctx.which("bash") else {
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
    let scratch = scratch_dir();
    if std::fs::create_dir_all(&scratch).is_err() {
        f.warn(
            "couldn't create a scratch directory for the gate probe",
            None,
        );
        return;
    }
    let mut wrong = Vec::new();
    for (cmd, expect) in [
        ("git push origin main", 2),
        ("mezha approve --minutes 5", 2),
        ("git status", 0),
    ] {
        let event = json!({
            "session_id": "mezha-verify",
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": { "command": cmd },
            "cwd": ctx.root,
        });
        let home = scratch.to_string_lossy().into_owned();
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
    let _ = std::fs::remove_dir_all(&scratch);
    if !wrong.is_empty() {
        f.fail(
            format!("the gate doesn't behave: {}", wrong.join(", ")),
            "Reinstall mezha and run `mezha compile`; if it persists, report a mezha bug.",
        );
    }
}

fn scratch_dir() -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.subsec_nanos());
    std::env::temp_dir().join(format!("mezha-verify-{}-{nanos}", std::process::id()))
}
