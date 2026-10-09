//! `mezha metrics --ab` end to end with a stand-in `claude` and `srt`. The
//! check passes only when the agent's memory is in the worktree, so the
//! report must show memory 1/1 and emptied 0/1.

#![cfg(unix)]

mod common;

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use common::{Project, stderr, stdout};

const SPEC: &str = r#"
[project]
name = "abtest"

[policy]
permissions_ask = ["git push"]

[agent.implementer]
description = "Implements changes."
tools = ["Read", "Edit"]
rule_of_two = ["private_data"]
memory = { scope = "project" }
"#;

const FAKE_CLAUDE: &str = r#"#!/bin/sh
if [ "$1" = "--version" ]; then echo "2.1.285 (Claude Code)"; exit 0; fi
agent=""; mode=""; persist=1; settings=""
while [ $# -gt 0 ]; do
  case "$1" in
    --agent) agent="$2"; shift ;;
    --permission-mode) mode="$2"; shift ;;
    --no-session-persistence) persist=0 ;;
    --settings) settings="$2"; shift ;;
    --output-format|--max-turns|--max-budget-usd|--permission-prompts|--model) shift ;;
    -p|--verbose|--strict-mcp-config) ;;
    *) echo "unexpected argument: $1" >&2; exit 9 ;;
  esac
  shift
done
[ "$mode" = acceptEdits ] && [ "$persist" = 0 ] && [ "$agent" = implementer ] || { echo "bad arguments" >&2; exit 9; }
[ -z "$CLAUDE_CODE_DISABLE_AUTO_MEMORY" ] || { echo "agent memory would be off" >&2; exit 9; }
case "$settings" in *'Edit(~/.claude/projects/**)'*) ;; *) echo "auto memory writable" >&2; exit 9 ;; esac
pwd >> "$FAKE_LOG"
git log -1 --format=%s >> "$FAKE_LOG"
cat > /dev/null
printf '{"type":"system","subtype":"init","tools":["Bash","Edit"],"mcp_servers":[],"permissionMode":"acceptEdits","agents":["implementer"],"claude_code_version":"2.1.285"}\n'
if [ "$FAKE_MODE" = budget ]; then
  printf '{"type":"result","subtype":"error_max_budget_usd","is_error":true,"num_turns":3,"total_cost_usd":0.4}\n'; exit 1
fi
echo work > work.txt
printf '{"type":"result","subtype":"success","is_error":false,"num_turns":2,"total_cost_usd":0.1,"result":"done"}\n'
"#;

/// srt's stand-in: checks it got settings that let the check write the
/// worktree, then runs the command.
const FAKE_SRT: &str = r#"#!/bin/sh
if [ "$1" = "--version" ]; then echo "0.0.79"; exit 0; fi
[ "$1" = "--settings" ] && [ "$3" = "-c" ] || { echo "bad srt arguments" >&2; exit 9; }
grep -q "\"$(pwd)\"" "$2" || { echo "the worktree isn't writable in $2" >&2; exit 9; }
echo srt >> "$FAKE_LOG"
exec /bin/sh -c "$4"
"#;

struct Setup {
    p: Project,
    bin: PathBuf,
    log: PathBuf,
    tasks: PathBuf,
}

fn git(dir: &Path, home: &Path, args: &[&str]) {
    let out = Command::new("git")
        .args(args)
        .current_dir(dir)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", home)
        .output()
        .unwrap();
    assert!(out.status.success(), "git {args:?}: {}", stderr(&out));
}

fn write(path: &Path, text: &str) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, text).unwrap();
}

fn tool(dir: &Path, name: &str, body: &str) {
    write(&dir.join(name), body);
    fs::set_permissions(dir.join(name), fs::Permissions::from_mode(0o755)).unwrap();
}

fn setup() -> Setup {
    let p = Project::new();
    write(
        &p.home.join(".gitconfig"),
        "[user]\n\tname = Test\n\temail = test@example.com\n",
    );
    git(&p.root, &p.home, &["init", "-q", "-b", "main"]);
    p.write_spec(SPEC);
    write(
        &p.root.join(".claude/agent-memory/implementer/MEMORY.md"),
        "- run tests first\n",
    );
    write(
        &p.root.join(".claude/agents/implementer.md"),
        "---\nname: \"implementer\"\n---\n\nImplement.\n",
    );
    write(&p.root.join("src/lib.rs"), "// code\n");
    git(&p.root, &p.home, &["add", "-A"]);
    git(&p.root, &p.home, &["commit", "-q", "-m", "init"]);
    let bin = p.base.join("bin");
    tool(&bin, "claude", FAKE_CLAUDE);
    tool(&bin, "srt", FAKE_SRT);
    let tasks = p.base.join("tasks.toml");
    write(
        &tasks,
        "[ab]\nbudget_usd = 0.5\n\n[[task]]\nname = \"remember\"\nprompt = \"Do the thing.\"\nagent = \"implementer\"\ncheck = \"test -f .claude/agent-memory/implementer/MEMORY.md\"\n",
    );
    let log = p.base.join("fake.log");
    Setup { p, bin, log, tasks }
}

impl Setup {
    fn ab(&self, mode: &str, args: &[&str]) -> Output {
        let mezha_dir = Path::new(common::BIN).parent().unwrap();
        let path = format!(
            "{}:{}:/usr/bin:/bin",
            self.bin.display(),
            mezha_dir.display()
        );
        let log = self.log.to_string_lossy().into_owned();
        let tasks = self.tasks.to_string_lossy().into_owned();
        let mut full = vec!["metrics", "--ab", tasks.as_str()];
        full.extend_from_slice(args);
        self.p.mezha_env(
            &full,
            &[
                ("PATH", path.as_str()),
                ("FAKE_MODE", mode),
                ("FAKE_LOG", log.as_str()),
            ],
        )
    }
}

#[test]
fn memory_against_emptied_memory() {
    let s = setup();
    // Without a terminal it needs --yes.
    let out = s.ab("ok", &[]);
    assert_eq!(out.status.code(), Some(1));
    assert!(stderr(&out).contains("pass --yes"), "{}", stderr(&out));
    assert!(!s.log.exists(), "nothing ran");

    let out = s.ab("ok", &["--yes"]);
    let o = stdout(&out);
    assert!(out.status.success(), "{o}\n{}", stderr(&out));
    assert!(o.contains("at most $1.00"), "{o}");
    assert!(o.contains("check for remember (in srt)"), "{o}");
    assert!(o.contains("| remember | 1/1 passed"), "{o}");
    assert!(o.contains("| 0/1 passed"), "{o}");
    assert!(o.contains("Not enough runs to claim a difference"), "{o}");

    // Worktrees under the temp dir with neutral names, the same commit
    // message in both, checks through srt, and nothing left behind.
    let log = fs::read_to_string(&s.log).unwrap();
    let dirs: Vec<&str> = log.lines().filter(|l| l.starts_with('/')).collect();
    assert_eq!(dirs.len(), 2, "{log}");
    for dir in &dirs {
        assert!(dir.contains("mezha-ab-") && dir.contains("/run-"), "{dir}");
        assert!(!dir.contains("memory") && !dir.contains("empty"), "{dir}");
        assert!(!dir.contains(".mezha"), "{dir}");
        assert!(!Path::new(dir).exists(), "{dir} was left behind");
    }
    assert_eq!(log.matches("ab: prepare run").count(), 2, "{log}");
    assert_eq!(log.matches("srt").count(), 2, "{log}");
    let worktrees = Command::new("git")
        .args(["worktree", "list"])
        .current_dir(&s.p.root)
        .output()
        .unwrap();
    assert_eq!(stdout(&worktrees).lines().count(), 1);

    // Recorded, and in the report.
    let store = mezha_memory::metrics_dir(&s.p.home, &s.p.root);
    assert_eq!(
        fs::read_to_string(store.join("ab.jsonl"))
            .unwrap()
            .lines()
            .count(),
        2
    );
    let report_dir = fs::read_dir(&store)
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| p.file_name().unwrap().to_string_lossy().starts_with("ab-"))
        .unwrap();
    let diff = fs::read_to_string(report_dir.join("remember-memory-0.diff")).unwrap();
    assert!(diff.contains("+work"), "{diff}");
    assert!(!diff.contains("agent-memory"), "{diff}");
}

#[test]
fn a_run_that_hits_its_budget_keeps_its_cost() {
    let s = setup();
    let out = s.ab("budget", &["--yes"]);
    assert!(out.status.success(), "{}", stderr(&out));
    let store = mezha_memory::metrics_dir(&s.p.home, &s.p.root);
    let rows: Vec<serde_json::Value> = fs::read_to_string(store.join("ab.jsonl"))
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(rows.len(), 2);
    for row in &rows {
        assert_eq!(row["cost_usd"], 0.4);
        assert_eq!(row["subtype"], "error_max_budget_usd");
        assert_eq!(row["is_error"], true);
    }
}

#[test]
fn refusals() {
    let s = setup();
    let out = s.p.mezha_env(
        &["metrics", "--ab", s.tasks.to_str().unwrap(), "--yes"],
        &[("CLAUDECODE", "1")],
    );
    assert_eq!(out.status.code(), Some(1));
    assert!(stderr(&out).contains("refuses to run inside Claude Code"));
    write(
        &s.tasks,
        "[[task]]\nname = \"t\"\nprompt = \"p\"\nagent = \"nobody\"\n",
    );
    let out = s.ab("ok", &["--yes"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(stderr(&out).contains("no agent.nobody"), "{}", stderr(&out));
    // Checks need srt unless you say otherwise.
    fs::remove_file(s.bin.join("srt")).unwrap();
    write(
        &s.tasks,
        "[[task]]\nname = \"t\"\nprompt = \"p\"\nagent = \"implementer\"\ncheck = \"true\"\n",
    );
    let out = s.ab("ok", &["--yes"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        stderr(&out).contains("--unsandboxed-check"),
        "{}",
        stderr(&out)
    );
    let out = s.ab("ok", &["--yes", "--unsandboxed-check"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(stdout(&out).contains("(UNSANDBOXED)"));
}

/// Refused before claude is even looked for: a tasks file that isn't there,
/// named in full, and a base whose runs couldn't differ.
#[test]
fn refuses_runs_that_cant_differ() {
    let s = setup();
    // A relative path is from the current directory, not the project.
    let out =
        s.p.mezha(&["metrics", "--ab", "nowhere/tasks.toml", "--yes"]);
    assert_eq!(out.status.code(), Some(1));
    let missing = s.p.root.join("nowhere/tasks.toml");
    assert!(
        stderr(&out).contains(&format!("error: {}:", missing.display())),
        "{}",
        stderr(&out)
    );

    // Without memory in the base, both variants would be the same.
    git(
        &s.p.root,
        &s.p.home,
        &["rm", "-q", "-r", ".claude/agent-memory"],
    );
    git(&s.p.root, &s.p.home, &["commit", "-q", "-m", "forget"]);
    let out = s.ab("ok", &["--yes"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        stderr(&out).contains("agent.implementer has no memory in main"),
        "{}",
        stderr(&out)
    );
    assert!(!stdout(&out).contains("at most $"), "{}", stdout(&out));

    // Without the agent, Claude Code wouldn't know it.
    git(
        &s.p.root,
        &s.p.home,
        &["rm", "-q", ".claude/agents/implementer.md"],
    );
    git(
        &s.p.root,
        &s.p.home,
        &["commit", "-q", "-m", "drop the agent"],
    );
    let out = s.ab("ok", &["--yes"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        stderr(&out).contains(".claude/agents/implementer.md isn't in main"),
        "{}",
        stderr(&out)
    );
    assert!(!s.log.exists(), "nothing ran");
}
