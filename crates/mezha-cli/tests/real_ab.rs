//! One real A/B task against haiku, in a mezha-compiled scratch project:
//! the agent's memory holds a codename the task asks for, so the run with
//! memory should pass and the run without it fail. It costs a few cents,
//! needs srt for the check, and is ignored by default:
//!
//! ```text
//! MEZHA_REAL_AB=1 cargo test -p mezha --test real_ab -- --ignored --nocapture
//! ```

#![cfg(unix)]

mod common;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use common::{BIN, stderr, stdout};

const SPEC: &str = r#"
[project]
name = "real-ab"

[policy]
permissions_ask = ["git push"]

[agent.implementer]
description = "Implements small changes in this repository."
tools = ["Read", "Write", "Edit", "Glob"]
rule_of_two = ["private_data"]
memory = { scope = "project" }
"#;

const MEMORY: &str = "# Memory\n\n- This project's codename is PERSIMMON. When someone asks for the codename, write it in capitals to codename.txt in the repository root.\n";

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
#[ignore = "runs real claude sessions against haiku; set MEZHA_REAL_AB=1"]
fn a_real_ab_run() {
    if std::env::var_os("MEZHA_REAL_AB").is_none() {
        eprintln!("set MEZHA_REAL_AB=1 to run it");
        return;
    }
    let home = PathBuf::from(std::env::var("HOME").unwrap());
    let tmp = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(tmp.path()).unwrap().join("real-ab");
    fs::create_dir_all(root.join("mezha/agents")).unwrap();
    fs::create_dir_all(root.join(".claude/agent-memory/implementer")).unwrap();
    fs::write(root.join("mezha.toml"), SPEC).unwrap();
    fs::write(
        root.join("mezha/agents/implementer.md"),
        "You implement small changes in this repository.\n",
    )
    .unwrap();
    fs::write(
        root.join(".claude/agent-memory/implementer/MEMORY.md"),
        MEMORY,
    )
    .unwrap();
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
    let tasks = tmp.path().join("tasks.toml");
    fs::write(
        &tasks,
        "[ab]\nmodel = \"haiku\"\nbudget_usd = 0.3\nmax_turns = 10\ntimeout_minutes = 5\n\n[[task]]\nname = \"codename\"\nprompt = \"Write this project's codename into codename.txt.\"\nagent = \"implementer\"\ncheck = \"grep -q PERSIMMON codename.txt\"\n",
    )
    .unwrap();
    let out = Command::new(BIN)
        .args(["metrics", "--ab", tasks.to_str().unwrap(), "--yes"])
        .current_dir(&root)
        .env("PATH", &path)
        .env_remove("CLAUDECODE")
        .env_remove("CLAUDE_CODE_ENTRYPOINT")
        .output()
        .unwrap();
    println!("{}\n{}", stdout(&out), stderr(&out));
    assert!(out.status.success(), "the A/B run failed");
    assert!(
        stdout(&out).contains("codename with memory: passed"),
        "the run with memory should find the codename"
    );
}
