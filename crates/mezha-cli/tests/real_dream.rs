//! One real dream against haiku: real `claude`, your login, a scratch
//! project, and a synthetic transcript placed under your Claude Code config
//! (removed afterwards, with the dream's workspace). It costs cents and is
//! ignored by default:
//!
//! ```text
//! MEZHA_REAL_DREAM=1 cargo test -p mezha --test real_dream -- --ignored --nocapture
//! ```

#![cfg(unix)]

mod common;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use common::{BIN, now, stderr, stdout};
use mezha_memory::time::format_iso;
use mezha_memory::transcripts::project_dir_name;

const SPEC: &str = r#"
[project]
name = "real-dream"

[policy]
permissions_ask = ["git push"]

[memory]
dream_model = "haiku"
dream_budget_usd = 0.30
dream_max_turns = 15

[agent.implementer]
description = "Implements changes in this repository."
tools = ["Read", "Edit"]
rule_of_two = ["private_data"]
memory = { scope = "project" }
"#;

/// Removes what the test put in your home, however it ends.
struct Cleanup(Vec<PathBuf>);

impl Drop for Cleanup {
    fn drop(&mut self) {
        for path in &self.0 {
            let _ = fs::remove_dir_all(path);
        }
    }
}

fn git(dir: &Path, args: &[&str]) {
    let out = Command::new("git")
        .args(["-c", "user.name=t", "-c", "user.email=t@example.com"])
        .args(args)
        .current_dir(dir)
        .output()
        .unwrap();
    assert!(out.status.success(), "git {args:?}: {}", stderr(&out));
}

#[test]
#[ignore = "runs the real claude against haiku; set MEZHA_REAL_DREAM=1"]
fn a_real_dream() {
    if std::env::var_os("MEZHA_REAL_DREAM").is_none() {
        eprintln!("set MEZHA_REAL_DREAM=1 to run it");
        return;
    }
    let home = PathBuf::from(std::env::var("HOME").unwrap());
    let tmp = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(tmp.path()).unwrap().join("real-dream");
    fs::create_dir_all(root.join("mezha/agents")).unwrap();
    fs::write(root.join("mezha.toml"), SPEC).unwrap();
    fs::write(
        root.join("mezha/agents/implementer.md"),
        "You implement changes in this repository.\n",
    )
    .unwrap();
    fs::write(
        root.join("README.md"),
        "# real-dream\n\nTests: `make test`.\n",
    )
    .unwrap();
    git(&root, &["init", "-q", "-b", "main"]);
    git(&root, &["add", "-A"]);
    git(&root, &["commit", "-q", "-m", "init"]);

    let config = std::env::var("CLAUDE_CONFIG_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| home.join(".claude"));
    let dir = config
        .join("projects")
        .join(project_dir_name(&root.to_string_lossy()));
    let _cleanup = Cleanup(vec![dir.clone(), mezha_memory::dreams_dir(&home, &root)]);
    let ts = |ago: u64| format_iso((now() - ago) as i64);
    let cwd = root.to_string_lossy().into_owned();
    let parent = [
        serde_json::json!({"type": "user", "uuid": "p1", "timestamp": ts(600), "cwd": cwd, "sessionId": "s1", "origin": {"kind": "human"}, "message": {"role": "user", "content": "Add a test for the parser."}}),
        serde_json::json!({"type": "user", "uuid": "p2", "timestamp": ts(400), "cwd": cwd, "sessionId": "s1", "toolUseResult": {"status": "completed", "agentId": "r1"}, "message": {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "t1", "content": "done"}]}}),
        serde_json::json!({"type": "user", "uuid": "p3", "timestamp": ts(300), "cwd": cwd, "sessionId": "s1", "origin": {"kind": "human"}, "message": {"role": "user", "content": "Good. Next time run `make test` before saying it's done; you didn't."}}),
    ];
    let agent = [
        serde_json::json!({"type": "user", "uuid": "r1-1", "timestamp": ts(590), "cwd": cwd, "sessionId": "s1", "isSidechain": true, "agentId": "r1", "message": {"role": "user", "content": "Add a test for the parser."}}),
        serde_json::json!({"type": "assistant", "uuid": "r1-2", "timestamp": ts(450), "cwd": cwd, "sessionId": "s1", "isSidechain": true, "agentId": "r1", "message": {"id": "m1", "role": "assistant", "content": [{"type": "text", "text": "Added tests/parser_test.rs.\n\n## Lessons\n\n- The test suite runs with `make test`, not `cargo test`."}]}}),
    ];
    let lines = |records: &[serde_json::Value]| -> String {
        records.iter().map(|r| format!("{r}\n")).collect()
    };
    fs::create_dir_all(dir.join("s1/subagents")).unwrap();
    fs::write(dir.join("s1.jsonl"), lines(&parent)).unwrap();
    fs::write(dir.join("s1/subagents/agent-r1.jsonl"), lines(&agent)).unwrap();
    fs::write(
        dir.join("s1/subagents/agent-r1.meta.json"),
        r#"{"agentType":"implementer","description":"x"}"#,
    )
    .unwrap();

    let out = Command::new(BIN)
        .args(["dream"])
        .current_dir(&root)
        .env_remove("CLAUDECODE")
        .env_remove("CLAUDE_CODE_ENTRYPOINT")
        .output()
        .unwrap();
    println!("{}\n{}", stdout(&out), stderr(&out));
    assert!(out.status.success(), "mezha dream failed");
    let branches = Command::new("git")
        .args([
            "for-each-ref",
            "--format=%(refname:short)",
            "refs/heads/mezha/",
        ])
        .current_dir(&root)
        .output()
        .unwrap();
    let branches = stdout(&branches);
    if let Some(branch) = branches.lines().next() {
        let show = Command::new("git")
            .args(["log", "-p", &format!("main..{branch}")])
            .current_dir(&root)
            .output()
            .unwrap();
        println!("{}", stdout(&show));
    } else {
        assert!(
            stdout(&out).contains("no changes"),
            "neither a commit nor `no changes`"
        );
    }
}
