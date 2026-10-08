//! The approval gate in-process: events in, exit code and reason out.

use std::path::{Path, PathBuf};

use mezha_broker::approvals;
use mezha_hooks::{Env, Outcome, PROTOCOL, run};
use serde_json::{Value, json};

const NOW: u64 = 1_800_000_000;

struct Fixture {
    _tmp: tempfile::TempDir,
    home: PathBuf,
    repo: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let base = std::fs::canonicalize(tmp.path()).unwrap();
        let home = base.join("home");
        let repo = base.join("repo");
        std::fs::create_dir_all(&home).unwrap();
        std::fs::create_dir_all(repo.join(".git")).unwrap();
        Fixture {
            _tmp: tmp,
            home,
            repo,
        }
    }

    fn env(&self) -> Env {
        Env::new(
            [
                ("HOME", self.home.to_str().unwrap()),
                ("CLAUDE_PROJECT_DIR", self.repo.to_str().unwrap()),
            ],
            NOW,
        )
    }

    fn fire(&self, event: Value) -> Outcome {
        self.fire_with(&self.env(), event)
    }

    fn fire_with(&self, env: &Env, event: Value) -> Outcome {
        let argv: Vec<String> = [
            "approval-gate",
            "--protocol",
            &PROTOCOL.to_string(),
            "--gate",
            "git push",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let out = run(&argv, event.to_string().as_bytes(), env);
        assert!(out.code == 0 || out.code == 2, "{out:?}");
        out
    }

    fn approve(&self, root: &Path) {
        approvals::grant(&self.home, root, 10, NOW).unwrap();
    }
}

fn bash(command: &str) -> Value {
    json!({
        "session_id": "s",
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": { "command": command },
        "cwd": "/somewhere/else",
    })
}

fn tool(name: &str, input: Value) -> Value {
    json!({ "hook_event_name": "PreToolUse", "tool_name": name, "tool_input": input })
}

#[test]
fn a_push_needs_an_approval() {
    let f = Fixture::new();
    let out = f.fire(bash("git push origin main"));
    assert!(out.is_block());
    assert!(out.stderr.contains("`git push` is gated"), "{}", out.stderr);
    assert!(out.stderr.contains("own terminal"));
    assert!(out.stderr.contains("mezha approve --minutes 30"));
    assert!(out.stderr.contains("advisory"));

    f.approve(&f.repo);
    assert_eq!(f.fire(bash("git push origin main")), Outcome::allow());
    // Allowing never means "allow": no output, so permission rules still ask.
    assert!(f.fire(bash("git push")).stderr.is_empty());
}

#[test]
fn ordinary_calls_pass() {
    let f = Fixture::new();
    assert_eq!(f.fire(bash("git status")), Outcome::allow());
    assert_eq!(
        f.fire(tool("Read", json!({ "file_path": "/etc/hosts" }))),
        Outcome::allow()
    );
    assert_eq!(
        f.fire(tool("TodoWrite", json!({ "todos": [] }))),
        Outcome::allow()
    );
}

#[test]
fn an_approval_for_another_repo_does_not_count() {
    let f = Fixture::new();
    f.approve(&f.repo.with_file_name("other"));
    assert!(f.fire(bash("git push")).is_block());
}

#[test]
fn an_approval_from_a_subdirectory_counts() {
    let f = Fixture::new();
    f.approve(&f.repo);
    let sub = f.repo.join("src");
    std::fs::create_dir_all(&sub).unwrap();
    let env = Env::new(
        [
            ("HOME", f.home.to_str().unwrap()),
            ("CLAUDE_PROJECT_DIR", sub.to_str().unwrap()),
        ],
        NOW,
    );
    assert_eq!(f.fire_with(&env, bash("git push")), Outcome::allow());
}

#[test]
fn without_claude_project_dir_the_event_cwd_is_used() {
    let f = Fixture::new();
    f.approve(&f.repo);
    let env = Env::new([("HOME", f.home.to_str().unwrap())], NOW);
    let mut event = bash("git push");
    event["cwd"] = json!(f.repo);
    assert_eq!(f.fire_with(&env, event), Outcome::allow());
    let mut event = bash("git push");
    event.as_object_mut().unwrap().remove("cwd");
    assert!(f.fire_with(&env, event).is_block());
}

#[test]
fn the_agent_cannot_approve_itself_even_when_approved() {
    let f = Fixture::new();
    f.approve(&f.repo);
    let out = f.fire(bash("mezha approve --minutes 600"));
    assert!(out.is_block());
    assert!(out.stderr.contains("must be run by a human"));
    assert_eq!(f.fire(bash("mezha approve --status")), Outcome::allow());
}

#[test]
fn no_tool_may_touch_the_store() {
    let f = Fixture::new();
    let store = approvals::store_dir(&f.home);
    let inside = store.join("x.json");
    for input in [
        json!({ "file_path": inside }),
        json!({ "file_path": "~/.mezha/approvals/x.json" }),
        json!({ "notebook_path": f.home.join(".mezha") }),
        json!({ "path": f.home.join("a/../.mezha/approvals") }),
        json!({ "file_path": format!("../home/.mezha/approvals/x.json") }),
    ] {
        for name in ["Edit", "Write", "NotebookEdit", "Grep"] {
            let out = f.fire(tool(name, input.clone()));
            assert!(out.is_block(), "{name} {input}: {out:?}");
        }
    }
    assert_eq!(
        f.fire(tool(
            "Edit",
            json!({ "file_path": f.home.join(".mezhafoo") })
        )),
        Outcome::allow()
    );
}

#[cfg(any(target_os = "macos", windows))]
#[test]
fn store_check_ignores_case_where_the_file_system_does() {
    let f = Fixture::new();
    let shouty = f.home.join(".MEZHA/Approvals/x.json");
    assert!(
        f.fire(tool("Write", json!({ "file_path": shouty })))
            .is_block()
    );
}

#[test]
fn malformed_input_blocks() {
    let f = Fixture::new();
    let argv: Vec<String> = ["approval-gate", "--protocol", "1"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    for input in [&b""[..], b"not json", b"[1,2]", b"null", b"\xff\xfe"] {
        assert!(run(&argv, input, &f.env()).is_block(), "{input:?}");
    }
    let huge = vec![b' '; mezha_hooks::MAX_INPUT + 1];
    assert!(run(&argv, &huge, &f.env()).is_block());
}

#[test]
fn unexpected_events_and_shapes_block() {
    let f = Fixture::new();
    let mut post = bash("ls");
    post["hook_event_name"] = json!("PostToolUse");
    assert!(f.fire(post).is_block());
    let mut nameless = bash("ls");
    nameless.as_object_mut().unwrap().remove("tool_name");
    assert!(f.fire(nameless).is_block());
    for name in ["Bash", "PowerShell", "Monitor"] {
        assert!(
            f.fire(tool(name, json!({ "description": "x" }))).is_block(),
            "{name}"
        );
    }
    assert!(
        f.fire(tool("Bash", json!({ "command": ["git", "push"] })))
            .is_block()
    );
    assert!(f.fire(bash("git status\u{1b}[2K")).is_block());
}

#[test]
fn any_tool_with_a_command_is_gated() {
    let f = Fixture::new();
    for name in ["PowerShell", "Monitor", "mcp__shell__run"] {
        assert!(
            f.fire(tool(name, json!({ "command": "git push" })))
                .is_block(),
            "{name}"
        );
    }
}

#[test]
fn expired_and_implausible_approvals_block() {
    let f = Fixture::new();
    approvals::grant(&f.home, &f.repo, 1, NOW - 120).unwrap();
    assert!(f.fire(bash("git push")).is_block(), "expired");
    approvals::grant(&f.home, &f.repo, 1440, NOW + 86_400).unwrap();
    assert!(f.fire(bash("git push")).is_block(), "too far ahead");
}
