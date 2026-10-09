//! One real skill eval against haiku, in a mezha-compiled scratch project:
//! a knowledge skill holds a codename, two prompts should load it and two
//! shouldn't, and one task asks for the codename, so it should pass with
//! the skill and fail without it. It costs a few cents, needs srt for the
//! check, and is ignored by default:
//!
//! ```text
//! MEZHA_REAL_SKILL_EVAL=1 cargo test -p mezha --test real_skill_eval -- --ignored --nocapture
//! ```

#![cfg(unix)]

mod common;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use common::{BIN, stderr, stdout};

const SPEC: &str = r#"
[project]
name = "real-eval"

[policy]
permissions_ask = ["git push"]

[skill.codenames]
preset = "knowledge"
description = "This project's codename and release naming rules. Use when someone asks for the project's codename or names a release."
"#;

const BODY: &str = "# Codenames\n\nThis project's codename is PERSIMMON. When someone asks for it, write it in capitals.\n";

const CASES: &str = r#"
[eval]
model = "haiku"
budget_usd = 0.3
max_turns = 10
trigger_turns = 3
timeout_minutes = 5

[[trigger]]
prompt = "What is this project's codename?"
should_trigger = true

[[trigger]]
prompt = "We're naming the next release. What are the rules for release names here?"
should_trigger = true

[[trigger]]
prompt = "What is 17 times 23? Answer with the number only."
should_trigger = false

[[trigger]]
prompt = "Write a two-line poem about autumn rain. Don't use any tools."
should_trigger = false

[[task]]
name = "codename"
prompt = "Write this project's codename into codename.txt."
check = "grep -q PERSIMMON codename.txt"
"#;

struct Cleanup(Vec<PathBuf>);

impl Drop for Cleanup {
    fn drop(&mut self) {
        for path in &self.0 {
            let _ = fs::remove_dir_all(path);
        }
    }
}

fn run(dir: &Path, program: &str, args: &[&str], path: &str) {
    let out = Command::new(program)
        .args(args)
        .current_dir(dir)
        .env("PATH", path)
        .env_remove("CLAUDECODE")
        .env_remove("CLAUDE_CODE_ENTRYPOINT")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{program} {args:?}: {}{}",
        stdout(&out),
        stderr(&out)
    );
}

#[test]
#[ignore = "runs real claude sessions against haiku; set MEZHA_REAL_SKILL_EVAL=1"]
fn a_real_skill_eval() {
    if std::env::var_os("MEZHA_REAL_SKILL_EVAL").is_none() {
        eprintln!("set MEZHA_REAL_SKILL_EVAL=1 to run it");
        return;
    }
    let home = PathBuf::from(std::env::var("HOME").unwrap());
    let tmp = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(tmp.path()).unwrap().join("real-eval");
    fs::create_dir_all(root.join("mezha/skills")).unwrap();
    fs::create_dir_all(root.join("mezha/evals")).unwrap();
    fs::write(root.join("mezha.toml"), SPEC).unwrap();
    fs::write(root.join("mezha/skills/codenames.md"), BODY).unwrap();
    fs::write(root.join("mezha/evals/codenames.toml"), CASES).unwrap();
    // Claude Code creates the project's (auto memory) directory even when
    // the run may not write it.
    let config = std::env::var("CLAUDE_CONFIG_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| home.join(".claude"));
    let _cleanup = Cleanup(vec![
        mezha_memory::metrics_dir(&home, &root),
        config
            .join("projects")
            .join(mezha_memory::transcripts::project_dir_name(
                &root.to_string_lossy(),
            )),
    ]);
    // The project's hooks call `mezha`: put this build first on PATH.
    let mezha_dir = Path::new(BIN).parent().unwrap();
    let path = format!("{}:{}", mezha_dir.display(), std::env::var("PATH").unwrap());
    run(&root, "git", &["init", "-q", "-b", "main"], &path);
    run(&root, BIN, &["compile"], &path);
    run(&root, "git", &["add", "-A"], &path);
    run(
        &root,
        "git",
        &[
            "-c",
            "user.name=t",
            "-c",
            "user.email=t@example.com",
            "commit",
            "-q",
            "-m",
            "init",
        ],
        &path,
    );
    let out = Command::new(BIN)
        .args(["skill", "eval", "codenames", "--yes"])
        .current_dir(&root)
        .env("PATH", &path)
        .env_remove("CLAUDECODE")
        .env_remove("CLAUDE_CODE_ENTRYPOINT")
        .output()
        .unwrap();
    let o = stdout(&out);
    println!("{o}\n{}", stderr(&out));
    assert!(out.status.success(), "the skill eval failed");
    assert!(
        o.contains("codename with the skill: passed"),
        "the run with the skill should find the codename"
    );
    assert!(
        o.contains("codename without: failed"),
        "the run without the skill can't know the codename"
    );
    assert!(o.contains("Precision "), "{o}");
}
