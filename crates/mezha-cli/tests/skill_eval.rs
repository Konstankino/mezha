//! `mezha skill eval` end to end with a stand-in `claude` and `srt`. The
//! stand-in loads the skill only when its SKILL.md is in the worktree and
//! the prompt asks for it, and knows the codename only from the skill, so
//! the report must show every trigger right and the task passing only
//! with the skill.

#![cfg(unix)]

mod common;

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use common::{Project, stderr, stdout};

const SPEC: &str = r#"
[project]
name = "evaltest"

[policy]
permissions_ask = ["git push"]

[skill.conventions]
preset = "knowledge"
description = "The project's naming conventions and codename. Use when naming things or asked for the codename."

[skill.release]
preset = "command"
description = "Cut a release."
"#;

const CASES: &str = r#"
[eval]
budget_usd = 0.25
trigger_turns = 3

[[trigger]]
prompt = "LOAD: what's the codename?"
should_trigger = true

[[trigger]]
prompt = "Summarise the README."
should_trigger = false

[[trigger]]
prompt = "READ the conventions, then rename x."
should_trigger = true

[[task]]
name = "codename"
prompt = "LOAD the skill and write the codename to codename.txt."
check = "grep -q PERSIMMON codename.txt"
expect = ["PERSIMMON"]
"#;

const FAKE_CLAUDE: &str = r#"#!/bin/sh
if [ "$1" = "--version" ]; then echo "2.1.285 (Claude Code)"; exit 0; fi
mode=""; persist=1; settings=""; turns=""
while [ $# -gt 0 ]; do
  case "$1" in
    --permission-mode) mode="$2"; shift ;;
    --no-session-persistence) persist=0 ;;
    --settings) settings="$2"; shift ;;
    --max-turns) turns="$2"; shift ;;
    --output-format|--max-budget-usd|--permission-prompts|--model) shift ;;
    -p|--verbose|--strict-mcp-config) ;;
    *) echo "unexpected argument: $1" >&2; exit 9 ;;
  esac
  shift
done
[ "$mode" = acceptEdits ] && [ "$persist" = 0 ] || { echo "bad arguments" >&2; exit 9; }
case "$settings" in *'Edit(~/.claude/projects/**)'*) ;; *) echo "auto memory writable" >&2; exit 9 ;; esac
prompt=$(cat)
skill=.claude/skills/conventions/SKILL.md
{
  pwd
  git log -1 --format=%s
  echo "turns=$turns skill=$([ -f $skill ] && echo yes || echo no) body=$([ -f mezha/skills/conventions.md ] && echo yes || echo no) evals=$([ -e mezha/evals ] && echo yes || echo no) status=$(git status --porcelain | wc -l | tr -d ' ') remotes=$(git remote | wc -l | tr -d ' ') git=$([ -d "$(git rev-parse --show-toplevel)/.git" ] && echo dir || echo link)"
} >> "$FAKE_LOG"
# As Claude Code does, even when the run may not write auto memory.
mkdir -p "$HOME/.claude/projects/$(pwd | sed 's/[^A-Za-z0-9]/-/g')/memory"
printf '{"type":"system","subtype":"init","tools":["Bash","Edit","Read","Skill"],"mcp_servers":[],"permissionMode":"acceptEdits","skills":[],"claude_code_version":"2.1.285"}\n'
printf '{"type":"assistant","parent_tool_use_id":null,"message":{"id":"m1","content":[{"type":"text","text":"Looking."}]}}\n'
loaded=no
if [ -f $skill ] || [ "$FAKE_MODE" = collide ]; then
  case "$prompt" in
    LOAD*)
      printf '{"type":"assistant","parent_tool_use_id":null,"message":{"id":"m2","content":[{"type":"tool_use","id":"t1","name":"Skill","input":{"skill":"conventions"}}]}}\n'
      printf '{"type":"user","message":{"content":[{"type":"tool_result","tool_use_id":"t1","content":"Launching skill: conventions"}]}}\n'
      loaded=yes ;;
    READ*)
      printf '{"type":"assistant","parent_tool_use_id":null,"message":{"id":"m2","content":[{"type":"tool_use","id":"t2","name":"Read","input":{"file_path":"%s/%s"}}]}}\n' "$(pwd)" "$skill"
      printf '{"type":"user","message":{"content":[{"type":"tool_result","tool_use_id":"t2","content":"..."}]}}\n'
      loaded=yes ;;
  esac
fi
if [ "$loaded" = yes ] && grep -q PERSIMMON $skill 2>/dev/null; then
  echo PERSIMMON > codename.txt
  printf '{"type":"result","subtype":"success","is_error":false,"num_turns":2,"total_cost_usd":0.1,"result":"The codename is PERSIMMON."}\n'
elif [ "$turns" = 3 ]; then
  printf '{"type":"result","subtype":"error_max_turns","is_error":true,"num_turns":4,"total_cost_usd":0.05}\n'
else
  printf '{"type":"result","subtype":"success","is_error":false,"num_turns":3,"total_cost_usd":0.1,"result":"I do not know the codename."}\n'
fi
"#;

const FAKE_SRT: &str = r#"#!/bin/sh
if [ "$1" = "--version" ]; then echo "0.0.79"; exit 0; fi
[ "$1" = "--settings" ] && [ "$3" = "-c" ] || { echo "bad srt arguments" >&2; exit 9; }
echo srt >> "$FAKE_LOG"
exec /bin/sh -c "$4"
"#;

struct Setup {
    p: Project,
    bin: PathBuf,
    log: PathBuf,
    /// The project inside the repository: `p.root` or a directory in it.
    dir: PathBuf,
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

/// A committed project in `sub` of the repository (or at its root).
fn setup(sub: &str) -> Setup {
    let p = Project::new();
    write(
        &p.home.join(".gitconfig"),
        "[user]\n\tname = Test\n\temail = test@example.com\n",
    );
    git(&p.root, &p.home, &["init", "-q", "-b", "main"]);
    let dir = p.root.join(sub);
    write(&dir.join("mezha.toml"), SPEC);
    write(
        &dir.join("mezha/skills/conventions.md"),
        "The codename is PERSIMMON.\n",
    );
    write(&dir.join("mezha/skills/release.md"), "Release.\n");
    write(&dir.join("mezha/evals/conventions.toml"), CASES);
    write(&dir.join("README.md"), "# evaltest\n");
    git(&p.root, &p.home, &["add", "-A"]);
    git(&p.root, &p.home, &["commit", "-q", "-m", "init"]);
    let bin = p.base.join("bin");
    tool(&bin, "claude", FAKE_CLAUDE);
    tool(&bin, "srt", FAKE_SRT);
    let log = p.base.join("fake.log");
    Setup { p, bin, log, dir }
}

impl Setup {
    fn eval(&self, mode: &str, args: &[&str]) -> Output {
        let mezha_dir = Path::new(common::BIN).parent().unwrap();
        let path = format!(
            "{}:{}:/usr/bin:/bin",
            self.bin.display(),
            mezha_dir.display()
        );
        let log = self.log.to_string_lossy().into_owned();
        let dir = self.dir.to_string_lossy().into_owned();
        let mut full = vec!["-p", dir.as_str(), "skill", "eval"];
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

    /// The log's lines about each session: (cwd, HEAD subject, facts).
    fn sessions(&self) -> Vec<(String, String, String)> {
        let log = fs::read_to_string(&self.log).unwrap_or_default();
        let lines: Vec<&str> = log.lines().filter(|l| *l != "srt").collect();
        lines
            .chunks(3)
            .map(|c| (c[0].to_string(), c[1].to_string(), c[2].to_string()))
            .collect()
    }

    fn store_rows(&self) -> Vec<serde_json::Value> {
        let store = mezha_memory::metrics_dir(&self.p.home, &self.dir);
        fs::read_to_string(store.join("skill-evals.jsonl"))
            .unwrap_or_default()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }
}

#[test]
fn triggers_and_tasks_with_and_without_the_skill() {
    let s = setup("");
    // Without a terminal it needs --yes.
    let out = s.eval("ok", &["conventions"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(stderr(&out).contains("pass --yes"), "{}", stderr(&out));
    assert!(!s.log.exists(), "nothing ran");

    let out = s.eval("ok", &["conventions", "--yes"]);
    let (o, e) = (stdout(&out), stderr(&out));
    assert!(out.status.success(), "{o}\n{e}");
    // It was never compiled, so it says where the skill comes from.
    assert!(e.contains("isn't what mezha.toml renders now"), "{e}");
    assert!(o.contains("= 5 Claude Code session(s)"), "{o}");
    assert!(o.contains("at most $1.25"), "{o}");
    assert!(o.contains("check for codename (in srt)"), "{o}");
    assert!(
        o.contains("trigger 1 (should load): loaded at turn 2"),
        "{o}"
    );
    assert!(
        o.contains("trigger 2 (shouldn't load): not loaded, $0.05, 4 turns\n"),
        "running out of turns is no failure: {o}"
    );
    assert!(o.contains("codename with the skill: passed"), "{o}");
    assert!(o.contains("codename without: failed"), "{o}");
    assert!(o.contains("Precision 100%: 2 of 2 loads"), "{o}");
    assert!(o.contains("Recall 100%"), "{o}");
    assert!(
        o.contains("| codename | 1/1 passed, $0.10, 2.0 turns, loaded 1/1 | 0/1 passed"),
        "{o}"
    );

    // Each arm saw what it should; the case files were in neither, and
    // every run started from the same clean commit.
    let sessions = s.sessions();
    assert_eq!(sessions.len(), 5, "{sessions:?}");
    for (i, (dir, head, facts)) in sessions.iter().enumerate() {
        assert!(
            dir.contains("mezha-eval-") && dir.contains("/run-"),
            "{dir}"
        );
        assert!(!Path::new(dir).exists(), "{dir} was left behind");
        assert_eq!(head, "eval: prepare run");
        assert!(
            facts.contains("evals=no") && facts.contains("status=0"),
            "{facts}"
        );
        // A clone that doesn't lead back to the project: Claude Code reads
        // a linked worktree's skills from the main checkout.
        assert!(facts.contains("remotes=0 git=dir"), "{facts}");
        let turns = if i < 3 { "turns=3" } else { "turns=30" };
        assert!(facts.contains(turns), "{i}: {facts}");
    }
    let with: Vec<&String> = sessions
        .iter()
        .map(|s| &s.2)
        .filter(|f| f.contains("skill=yes"))
        .collect();
    assert_eq!(with.len(), 4, "three triggers and one task: {sessions:?}");
    assert!(with.iter().all(|f| f.contains("body=yes")));
    let without: Vec<&String> = sessions
        .iter()
        .map(|s| &s.2)
        .filter(|f| f.contains("skill=no"))
        .collect();
    assert_eq!(without.len(), 1);
    assert!(without[0].contains("body=no"), "{}", without[0]);
    assert_eq!(
        fs::read_to_string(&s.log).unwrap().matches("srt").count(),
        2
    );
    let worktrees = Command::new("git")
        .args(["worktree", "list"])
        .current_dir(&s.p.root)
        .output()
        .unwrap();
    assert_eq!(stdout(&worktrees).lines().count(), 1);
    let projects = s.p.home.join(".claude/projects");
    assert_eq!(
        fs::read_dir(&projects).unwrap().count(),
        0,
        "left in {projects:?}"
    );
    // The prepare commits stayed in the clones.
    let log = Command::new("git")
        .args(["log", "--all", "--format=%s"])
        .current_dir(&s.p.root)
        .output()
        .unwrap();
    assert_eq!(stdout(&log).trim(), "init");

    // Recorded without text, and in the report.
    let rows = s.store_rows();
    assert_eq!(rows.len(), 5);
    assert!(
        !fs::read_to_string(mezha_memory::metrics_dir(&s.p.home, &s.dir).join("skill-evals.jsonl"))
            .unwrap()
            .contains("codename?")
    );
    let trigger = rows.iter().find(|r| r["case"] == "trigger-3").unwrap();
    assert_eq!(trigger["loaded"], true);
    assert_eq!(trigger["load_turn"], 2);
    assert_eq!(trigger["should_trigger"], true);
    let store = mezha_memory::metrics_dir(&s.p.home, &s.dir);
    let report = fs::read_dir(&store)
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| {
            p.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("skill-conventions-")
        })
        .unwrap();
    let md = fs::read_to_string(report.join("report.md")).unwrap();
    assert!(
        md.contains("| 1 | yes | 1/1 | LOAD: what's the codename? |"),
        "{md}"
    );
    assert!(
        fs::read_to_string(report.join("codename-with-0.md"))
            .unwrap()
            .contains("PERSIMMON")
    );
    let diff = fs::read_to_string(report.join("codename-with-0.diff")).unwrap();
    assert!(diff.contains("+PERSIMMON"), "{diff}");
    assert!(
        fs::read_to_string(report.join("codename-without-0.diff"))
            .unwrap()
            .is_empty()
    );

    // mezha metrics shows the latest eval.
    let out =
        s.p.mezha_env(&["-p", s.dir.to_str().unwrap(), "metrics"], &[]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(
        stdout(&out).contains("Skill eval  conventions"),
        "{}",
        stdout(&out)
    );
}

#[test]
fn a_project_in_a_subdirectory_and_one_kind_of_case() {
    let s = setup("sub/proj");
    let out = s.eval("ok", &["conventions", "--yes", "--only", "tasks"]);
    assert!(out.status.success(), "{}\n{}", stdout(&out), stderr(&out));
    let sessions = s.sessions();
    assert_eq!(sessions.len(), 2, "{sessions:?}");
    for (dir, _, facts) in &sessions {
        assert!(dir.ends_with("/sub/proj"), "{dir}");
        assert!(facts.contains("evals=no"), "{facts}");
    }
    assert!(sessions.iter().any(|s| s.2.contains("skill=yes body=yes")));
    assert!(sessions.iter().any(|s| s.2.contains("skill=no body=no")));
    assert!(stdout(&out).contains("codename with the skill: passed"));

    fs::remove_file(&s.log).unwrap();
    let out = s.eval("ok", &["conventions", "--yes", "--only", "triggers"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(s.sessions().len(), 3);
    assert!(!stdout(&out).contains("## Tasks"));
}

#[test]
fn refusals() {
    let s = setup("");
    let out = s.p.mezha_env(
        &["skill", "eval", "conventions", "--yes"],
        &[("CLAUDECODE", "1")],
    );
    assert_eq!(out.status.code(), Some(1));
    assert!(stderr(&out).contains("refuses to run inside Claude Code"));

    // A command skill never loads on its own.
    write(&s.dir.join("mezha/evals/release.toml"), CASES);
    let out = s.eval("ok", &["release", "--yes"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(stderr(&out).contains("command skill"), "{}", stderr(&out));

    let out = s.eval("ok", &["nothing", "--yes"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        stderr(&out).contains("write the skill's cases there, or pass --cases"),
        "{}",
        stderr(&out)
    );

    // Only one kind of trigger.
    let cases = s.p.base.join("one-sided.toml");
    write(
        &cases,
        "[[trigger]]\nprompt = \"LOAD\"\nshould_trigger = true\n",
    );
    let out = s.eval(
        "ok",
        &["conventions", "--yes", "--cases", cases.to_str().unwrap()],
    );
    assert_eq!(out.status.code(), Some(1));
    assert!(stderr(&out).contains("with false"), "{}", stderr(&out));
    assert!(!s.log.exists(), "nothing ran");

    // A skill of the same name loading without the project's stops it.
    let out = s.eval("collide", &["conventions", "--yes", "--only", "tasks"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        stderr(&out).contains("a user or plugin skill has the same name"),
        "{}",
        stderr(&out)
    );
    let worktrees = Command::new("git")
        .args(["worktree", "list"])
        .current_dir(&s.p.root)
        .output()
        .unwrap();
    assert_eq!(stdout(&worktrees).lines().count(), 1);
}
