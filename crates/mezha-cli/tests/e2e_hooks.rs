//! End to end: `mezha compile` writes `.claude/settings.json`, and the hook
//! command in it runs verbatim under bash, the way Claude Code runs it, with
//! a PreToolUse event on stdin. Every exit code must be 0 or 2.

#![cfg(unix)]

mod common;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use common::{Project, bash, now, stderr};
use mezha_broker::approvals;
use serde_json::{Value, json};

const SPEC: &str = r#"
[project]
name = "e2e"

[policy]
permissions_ask = ["git push", "terraform apply"]
"#;

struct Setup {
    p: Project,
    command: String,
    bin_dir: PathBuf,
}

fn git(dir: &Path, args: &[&str]) {
    let out = Command::new("git")
        .args(["-c", "user.name=t", "-c", "user.email=t@example.com"])
        .args(args)
        .current_dir(dir)
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap())
        .env("HOME", dir)
        .output()
        .unwrap();
    assert!(out.status.success(), "git {args:?}: {}", stderr(&out));
}

fn setup() -> Setup {
    let p = Project::new();
    git(&p.root, &["init", "-q"]);
    p.write_spec(SPEC);
    let out = p.mezha(&["compile"]);
    assert!(out.status.success(), "{}", stderr(&out));
    let settings: Value = serde_json::from_str(&p.read(".claude/settings.json")).unwrap();
    let group = &settings["hooks"]["PreToolUse"][0];
    assert!(group.get("matcher").is_none(), "the gate sees every tool");
    let hook = &group["hooks"][0];
    assert_eq!(hook["shell"], "bash");
    let command = hook["command"].as_str().unwrap().to_string();
    let bin_dir = Path::new(common::BIN).parent().unwrap().to_path_buf();
    Setup {
        p,
        command,
        bin_dir,
    }
}

#[derive(Clone, Copy)]
enum OnPath {
    /// The real mezha first on PATH.
    Mezha,
    /// No mezha anywhere on PATH.
    Missing,
}

impl Setup {
    fn path(&self, which: OnPath) -> String {
        match which {
            OnPath::Mezha => format!("{}:/usr/bin:/bin", self.bin_dir.display()),
            OnPath::Missing => "/usr/bin:/bin".to_string(),
        }
    }

    fn fire_with(
        &self,
        command: &str,
        path: &str,
        project: Option<&Path>,
        event: &Value,
    ) -> (i32, String) {
        let home = self.p.home.to_str().unwrap();
        let mut env = vec![("HOME", home), ("PATH", path)];
        let project_dir = project.map(|d| d.to_str().unwrap().to_string());
        if let Some(dir) = &project_dir {
            env.push(("CLAUDE_PROJECT_DIR", dir));
        }
        let out = bash(command, &self.p.root, &env, event.to_string().as_bytes());
        let code = out.status.code().expect("exited normally");
        assert!(code == 0 || code == 2, "exit {code}: {}", stderr(&out));
        (code, stderr(&out))
    }

    fn fire(&self, event: &Value) -> (i32, String) {
        self.fire_with(
            &self.command,
            &self.path(OnPath::Mezha),
            Some(&self.p.root),
            event,
        )
    }

    fn approve(&self, root: &Path) {
        approvals::grant(&self.p.home, &mezha_broker::repo_root(root), 10, now()).unwrap();
    }
}

fn bash_event(command: &str) -> Value {
    json!({
        "session_id": "e2e",
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": { "command": command },
    })
}

fn read_event() -> Value {
    json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Read",
        "tool_input": { "file_path": "/etc/hosts" },
    })
}

#[test]
fn a_push_is_blocked_until_a_human_approves() {
    let s = setup();
    let (code, err) = s.fire(&bash_event("git push origin main"));
    assert_eq!(code, 2);
    assert!(err.contains("mezha approve"), "{err}");
    s.approve(&s.p.root);
    assert_eq!(
        s.fire(&bash_event("git push origin main")),
        (0, String::new())
    );
}

#[test]
fn every_gate_from_the_spec_is_enforced() {
    let s = setup();
    assert_eq!(s.fire(&bash_event("terraform -chdir=infra apply")).0, 2);
    assert_eq!(s.fire(&bash_event("terraform plan")).0, 0);
}

#[test]
fn ordinary_calls_pass() {
    let s = setup();
    assert_eq!(s.fire(&bash_event("git status")), (0, String::new()));
    assert_eq!(s.fire(&read_event()), (0, String::new()));
}

#[test]
fn a_missing_binary_blocks_every_tool() {
    let s = setup();
    for event in [bash_event("git status"), read_event()] {
        let (code, err) = s.fire_with(
            &s.command,
            &s.path(OnPath::Missing),
            Some(&s.p.root),
            &event,
        );
        assert_eq!(code, 2, "{event}");
        assert!(err.contains("mezha"), "{err}");
    }
}

#[test]
fn a_crashing_or_failing_binary_blocks() {
    let s = setup();
    for exit in [1, 101, 127] {
        let fake = s.p.base.join(format!("fake-{exit}"));
        fs::create_dir_all(&fake).unwrap();
        let script = fake.join("mezha");
        fs::write(&script, format!("#!/bin/sh\nexit {exit}\n")).unwrap();
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
        let path = format!("{}:/usr/bin:/bin", fake.display());
        let (code, _) = s.fire_with(&s.command, &path, Some(&s.p.root), &read_event());
        assert_eq!(code, 2, "fake mezha exiting {exit}");
    }
}

#[test]
fn a_protocol_mismatch_blocks() {
    let s = setup();
    let other = s.command.replace(
        &format!("--protocol {}", mezha_hooks::PROTOCOL),
        "--protocol 999",
    );
    assert_ne!(other, s.command);
    let (code, err) = s.fire_with(
        &other,
        &s.path(OnPath::Mezha),
        Some(&s.p.root),
        &read_event(),
    );
    assert_eq!(code, 2);
    assert!(err.contains("protocol 999"), "{err}");
}

#[test]
fn malformed_input_blocks() {
    let s = setup();
    let (code, _) = s.fire(&json!("just a string"));
    assert_eq!(code, 2);
    let mut post = bash_event("ls");
    post["hook_event_name"] = json!("PostToolUse");
    assert_eq!(s.fire(&post).0, 2);
    let home = s.p.home.to_str().unwrap();
    let path = s.path(OnPath::Mezha);
    let root = s.p.root.to_str().unwrap();
    let out = bash(
        &s.command,
        &s.p.root,
        &[
            ("HOME", home),
            ("PATH", &path),
            ("CLAUDE_PROJECT_DIR", root),
        ],
        b"{not json",
    );
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn the_agent_cannot_approve_itself() {
    let s = setup();
    s.approve(&s.p.root);
    let (code, err) = s.fire(&bash_event("mezha approve --minutes 600"));
    assert_eq!(code, 2);
    assert!(err.contains("human"), "{err}");
}

#[test]
fn no_tool_may_write_the_approval_store() {
    let s = setup();
    let target = approvals::store_dir(&s.p.home).join("forged.json");
    let event = json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Write",
        "tool_input": { "file_path": target, "content": "{}" },
    });
    assert_eq!(s.fire(&event).0, 2);
}

#[test]
fn expired_and_implausible_approvals_block() {
    let s = setup();
    let root = mezha_broker::repo_root(&s.p.root);
    approvals::grant(&s.p.home, &root, 1, now() - 600).unwrap();
    assert_eq!(s.fire(&bash_event("git push")).0, 2, "expired");
    approvals::grant(&s.p.home, &root, 1440, now() + 2 * 86_400).unwrap();
    assert_eq!(s.fire(&bash_event("git push")).0, 2, "too far ahead");
}

#[test]
fn worktrees_share_an_approval_and_other_repos_do_not() {
    let s = setup();
    git(&s.p.root, &["commit", "-q", "--allow-empty", "-m", "init"]);
    let wt = s.p.base.join("wt");
    git(&s.p.root, &["worktree", "add", "-q", wt.to_str().unwrap()]);

    let other = s.p.base.join("other");
    fs::create_dir_all(&other).unwrap();
    git(&other, &["init", "-q"]);
    s.approve(&other);
    let path = s.path(OnPath::Mezha);
    assert_eq!(
        s.fire_with(&s.command, &path, Some(&wt), &bash_event("git push"))
            .0,
        2
    );

    s.approve(&s.p.root);
    assert_eq!(
        s.fire_with(&s.command, &path, Some(&wt), &bash_event("git push"))
            .0,
        0
    );
}

#[test]
fn without_claude_project_dir_the_event_cwd_is_used() {
    let s = setup();
    s.approve(&s.p.root);
    let path = s.path(OnPath::Mezha);
    let mut event = bash_event("git push");
    event["cwd"] = json!(s.p.root);
    assert_eq!(s.fire_with(&s.command, &path, None, &event).0, 0);
    let elsewhere = s.p.base.join("elsewhere");
    fs::create_dir_all(&elsewhere).unwrap();
    event["cwd"] = json!(elsewhere);
    assert_eq!(s.fire_with(&s.command, &path, None, &event).0, 2);
}

/// The `agent-bash` hook from a generated agent file, run verbatim under
/// bash as Claude Code runs a frontmatter hook.
#[test]
fn an_agent_s_bash_scope_is_enforced_by_its_hook() {
    let p = Project::new();
    git(&p.root, &["init", "-q"]);
    p.write_spec(&format!(
        "{SPEC}\n[agent.tester]\ndescription = \"Runs the tests.\"\ntools = [\"Read\", \"Bash(cargo test *)\"]\nrule_of_two = []\n"
    ));
    fs::create_dir_all(p.root.join("mezha/agents")).unwrap();
    fs::write(p.root.join("mezha/agents/tester.md"), "Run the tests.\n").unwrap();
    let out = p.mezha(&["compile"]);
    assert!(out.status.success(), "{}", stderr(&out));
    let agent = p.read(".claude/agents/tester.md");
    let line = agent
        .lines()
        .find_map(|l| l.trim_start().strip_prefix("- command: "))
        .expect("the agent has a hook");
    let command: String = serde_json::from_str(line).unwrap();
    assert!(
        command.starts_with("mezha hook agent-bash --protocol 1 --allow 'cargo test *'"),
        "{command}"
    );

    let bin_dir = Path::new(common::BIN).parent().unwrap().to_path_buf();
    let setup = Setup {
        p,
        command: command.clone(),
        bin_dir,
    };
    let fire = |cmd: &str, path: &str| setup.fire_with(&command, path, None, &bash_event(cmd)).0;
    let with = setup.path(OnPath::Mezha);
    assert_eq!(fire("cargo test --release", &with), 0);
    assert_eq!(
        fire("cargo test 2>&1 | grep FAIL", &with),
        2,
        "grep isn't in scope"
    );
    assert_eq!(fire("curl https://example.com", &with), 2);
    let (code, why) = setup.fire_with(&command, &with, None, &bash_event("rm -rf target"));
    assert_eq!(code, 2);
    assert!(why.contains("advisory"), "{why}");
    // Without mezha, the hook fails closed.
    assert_eq!(fire("cargo test", &setup.path(OnPath::Missing)), 2);
}

#[test]
fn every_call_lands_in_the_audit_log() {
    let s = setup();
    let mut push = bash_event("git push");
    push["tool_use_id"] = json!("toolu_9");
    assert_eq!(s.fire(&push).0, 2);
    assert_eq!(s.fire(&read_event()).0, 0);

    // The outcome hook, as compile renders it for both events.
    let settings: Value = serde_json::from_str(&s.p.read(".claude/settings.json")).unwrap();
    for event in ["PostToolUse", "PostToolUseFailure"] {
        let group = &settings["hooks"][event][0];
        assert!(group.get("matcher").is_none(), "{event} sees every tool");
        let command = group["hooks"][0]["command"].as_str().unwrap();
        let done = json!({
            "session_id": "e2e",
            "hook_event_name": event,
            "tool_name": "Bash",
            "tool_use_id": "toolu_9",
        });
        let (code, err) = s.fire_with(command, &s.path(OnPath::Mezha), Some(&s.p.root), &done);
        assert_eq!((code, err.as_str()), (0, ""));
    }

    let root = mezha_broker::repo_root(&s.p.root);
    let dir = mezha_hooks::audit::dir(&s.p.home, Some(&root));
    let text: String = fs::read_dir(&dir)
        .unwrap()
        .map(|e| fs::read_to_string(e.unwrap().path()).unwrap())
        .collect();
    let records: Vec<Value> = text
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    let kinds: Vec<(&str, &str)> = records
        .iter()
        .map(|r| {
            (
                r["type"].as_str().unwrap(),
                r["decision"]
                    .as_str()
                    .or(r["terminal_state"].as_str())
                    .unwrap(),
            )
        })
        .collect();
    assert_eq!(
        kinds,
        [
            ("admission", "block"),
            ("admission", "pass"),
            ("outcome", "committed"),
            ("outcome", "failed")
        ]
    );
    assert_eq!(records[0]["attempt_id"], records[2]["attempt_id"]);
    assert!(
        records[0]["policy"]
            .as_str()
            .unwrap()
            .starts_with("sha256:")
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&dir), 0o700);
        let file = fs::read_dir(&dir).unwrap().next().unwrap().unwrap().path();
        assert_eq!(mode(&file), 0o600);
    }
}

#[test]
fn an_unwritable_audit_log_blocks() {
    use std::os::unix::fs::PermissionsExt;
    let s = setup();
    let store = approvals::mezha_home(&s.p.home);
    fs::create_dir_all(&store).unwrap();
    fs::set_permissions(&store, fs::Permissions::from_mode(0o500)).unwrap();
    let (code, err) = s.fire(&read_event());
    fs::set_permissions(&store, fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(code, 2, "{err}");
    assert!(err.contains("couldn't write the audit log"), "{err}");
}
