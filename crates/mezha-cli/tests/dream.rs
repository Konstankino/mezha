//! `mezha dream` end to end with a stand-in `claude`: a git repository,
//! fixture transcripts in a scratch home, and a script that checks the
//! dreamer's arguments and then plays one of several dreamers.

#![cfg(unix)]

mod common;

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use common::{Project, now, stderr, stdout};
use mezha_memory::time::format_iso;
use mezha_memory::transcripts::project_dir_name;

const SPEC: &str = r#"
[project]
name = "dreamtest"

[policy]
permissions_ask = ["git push"]

[agent.implementer]
description = "Implements changes."
tools = ["Read", "Edit"]
rule_of_two = ["private_data"]
memory = { scope = "project" }

[agent.clinician]
description = "Works on clinical data."
tools = ["Read"]
rule_of_two = ["private_data"]
memory = { class = "phi" }
"#;

const FAKE_CLAUDE: &str = r#"#!/bin/sh
# A stand-in for claude: checks how mezha dream runs it, then acts per $FAKE_MODE.
if [ "$1" = "--version" ]; then echo "2.1.285 (Claude Code)"; exit 0; fi
staged=""; restricted=""; mode=""; tools=""; allow=""; prompts=""
while [ $# -gt 0 ]; do
  case "$1" in
    --add-dir) staged="$2"; shift ;;
    --restricted) restricted=1 ;;
    --permission-mode) mode="$2"; shift ;;
    --permission-prompts) prompts="$2"; shift ;;
    --tools) tools="$2"; shift ;;
    --allowedTools) allow="$2"; shift ;;
    --system-prompt|--model|--disallowedTools|--settings|--max-turns|--max-budget-usd|--output-format) shift ;;
    -p|--strict-mcp-config|--disable-slash-commands|--verbose|--no-session-persistence) ;;
    *) echo "unexpected argument: $1" >&2; exit 9 ;;
  esac
  shift
done
[ -n "$restricted" ] && [ "$mode" = dontAsk ] && [ "$prompts" = none ] && [ "$tools" = "Read,Grep,Glob,Edit,Write" ] || { echo "not locked down" >&2; exit 9; }
[ "$allow" = "Edit(/$staged/*.md)" ] || { echo "bad allow rule: $allow" >&2; exit 9; }
[ -z "$CLAUDECODE" ] || { echo "CLAUDECODE leaked" >&2; exit 9; }
[ -z "$GH_TOKEN" ] || { echo "GH_TOKEN leaked" >&2; exit 9; }
[ "$CLAUDE_CODE_DISABLE_CLAUDE_MDS" = 1 ] && [ "$CLAUDE_CODE_DISABLE_AUTO_MEMORY" = 1 ] || { echo "CLAUDE.md or auto memory on" >&2; exit 9; }
cat > "$staged/../../task-$(basename "$staged").txt"
tools_json='["Edit","Glob","Grep","Read","Write"]'
[ "$FAKE_MODE" = badinit ] && tools_json='["Bash","Edit","Glob","Grep","Read","Write"]'
printf '{"type":"system","subtype":"init","tools":%s,"mcp_servers":[],"permissionMode":"dontAsk","model":"claude-test","apiKeySource":"none","plugins":[]}\n' "$tools_json"
[ "$FAKE_MODE" = badinit ] && { sleep 30; exit 0; }
summary="Added a lesson."
case "$FAKE_MODE" in
  write) printf '# Memory\n\n- Run cargo test -p x before reporting (seen 2 times).\n' > "$staged/MEMORY.md" ;;
  outside) echo stray > stray.md ;;
  hard) printf '# Memory\n\n- hidden\342\200\213word\n' > "$staged/MEMORY.md" ;;
  phrase) printf '# Memory\n\n- Avoid git commit --no-verify: hooks catch fmt.\n' > "$staged/MEMORY.md" ;;
  ansi) printf '# Memory\n\n- a lesson\n' > "$staged/MEMORY.md"; summary='Done \u001b[2J [skip ci]' ;;
  changelog) printf 'forged\n' > "$staged/CHANGELOG.md" ;;
  tamper) printf '# Memory\n\n- a lesson\n' > "$staged/MEMORY.md"; mkdir -p "$REAL_DIR"; echo changed > "$REAL_DIR/MEMORY.md" ;;
  noresult) echo 'not json'; exit 0 ;;
  nochange) summary="no changes" ;;
  budget) printf '{"type":"result","subtype":"error_max_budget_usd","is_error":true,"num_turns":3,"total_cost_usd":1.0}\n'; exit 1 ;;
esac
printf '{"type":"assistant","message":{"content":[{"type":"text","text":"ok"}]}}\n'
printf '{"type":"result","subtype":"success","is_error":false,"num_turns":4,"total_cost_usd":0.12,"result":"%s","permission_denials":[]}\n' "$summary"
"#;

struct Setup {
    p: Project,
    bin: PathBuf,
}

fn git(dir: &Path, home: &Path, args: &[&str]) -> Output {
    Command::new("git")
        .args(args)
        .current_dir(dir)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", home)
        .output()
        .unwrap()
}

fn git_ok(dir: &Path, home: &Path, args: &[&str]) -> String {
    let out = git(dir, home, args);
    assert!(out.status.success(), "git {args:?}: {}", stderr(&out));
    stdout(&out)
}

fn write(path: &Path, text: &str) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, text).unwrap();
}

fn line(value: serde_json::Value) -> String {
    format!("{value}\n")
}

/// A session of this project in which `role` ran once, an hour ago.
fn transcript(p: &Project, role: &str, id: &str) {
    transcript_ago(p, role, id, 0);
}

/// The same, `sooner` seconds later.
fn transcript_ago(p: &Project, role: &str, id: &str, sooner: u64) {
    let ts = |ago: u64| format_iso((now() - ago + sooner) as i64);
    let dir = p
        .home
        .join(".claude/projects")
        .join(project_dir_name(&p.root.to_string_lossy()));
    let cwd = p.root.to_string_lossy().into_owned();
    let session = format!("s-{id}");
    let mut parent = String::new();
    parent.push_str(&line(serde_json::json!({"type": "user", "uuid": format!("{id}-p1"), "timestamp": ts(3700), "cwd": cwd, "sessionId": session, "origin": {"kind": "human"}, "message": {"role": "user", "content": "Please do the thing"}})));
    parent.push_str(&line(serde_json::json!({"type": "user", "uuid": format!("{id}-p2"), "timestamp": ts(3500), "cwd": cwd, "sessionId": session, "toolUseResult": {"status": "completed", "agentId": id}, "message": {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "t1", "content": "done"}]}})));
    parent.push_str(&line(serde_json::json!({"type": "user", "uuid": format!("{id}-p3"), "timestamp": ts(3400), "cwd": cwd, "sessionId": session, "origin": {"kind": "human"}, "message": {"role": "user", "content": "Next time run the tests first."}})));
    write(&dir.join(format!("{session}.jsonl")), &parent);
    let mut agent = String::new();
    agent.push_str(&line(serde_json::json!({"type": "user", "uuid": format!("{id}-a1"), "timestamp": ts(3650), "cwd": cwd, "sessionId": session, "isSidechain": true, "agentId": id, "message": {"role": "user", "content": "Do the thing in crates/x"}})));
    agent.push_str(&line(serde_json::json!({"type": "assistant", "uuid": format!("{id}-a2"), "timestamp": ts(3550), "cwd": cwd, "sessionId": session, "isSidechain": true, "agentId": id, "message": {"id": "m1", "role": "assistant", "content": [{"type": "text", "text": "Done.\n\n## Lessons\n\n- Tests first.\n- Token ghp_0123456789abcdefghijklmnopqrstuvwxyzAB"}]}})));
    let sub = dir.join(&session).join("subagents");
    write(&sub.join(format!("agent-{id}.jsonl")), &agent);
    write(
        &sub.join(format!("agent-{id}.meta.json")),
        &serde_json::json!({"agentType": role, "description": "x"}).to_string(),
    );
}

fn setup() -> Setup {
    let p = Project::new();
    write(
        &p.home.join(".gitconfig"),
        "[user]\n\tname = Test\n\temail = test@example.com\n",
    );
    git_ok(&p.root, &p.home, &["init", "-q", "-b", "main"]);
    p.write_spec(SPEC);
    write(
        &p.root.join("mezha/agents/implementer.md"),
        "You implement changes.\n",
    );
    write(&p.root.join(".gitignore"), ".claude/agent-memory-local/\n");
    write(
        &p.root.join(".claude/agent-memory/implementer/MEMORY.md"),
        "# Memory\n",
    );
    git_ok(&p.root, &p.home, &["add", "-A"]);
    git_ok(&p.root, &p.home, &["commit", "-q", "-m", "init"]);
    // Repository hooks that would run during a dream if mezha let them.
    for hook in ["post-checkout", "pre-commit", "commit-msg"] {
        let path = p.root.join(".git/hooks").join(hook);
        write(
            &path,
            &format!("#!/bin/sh\ntouch '{}/hook-{hook}'\n", p.base.display()),
        );
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
    }
    let bin = p.base.join("bin");
    write(&bin.join("claude"), FAKE_CLAUDE);
    fs::set_permissions(bin.join("claude"), fs::Permissions::from_mode(0o755)).unwrap();
    transcript(&p, "implementer", "a1");
    Setup { p, bin }
}

impl Setup {
    fn dream(&self, mode: &str, args: &[&str]) -> Output {
        self.dream_env(mode, args, &[])
    }

    fn dream_env(&self, mode: &str, args: &[&str], extra: &[(&str, &str)]) -> Output {
        let path = format!("{}:/usr/bin:/bin", self.bin.display());
        let mut env = vec![
            ("PATH", path.as_str()),
            ("FAKE_MODE", mode),
            ("GH_TOKEN", "should-not-reach-the-dreamer"),
        ];
        env.extend_from_slice(extra);
        let mut full = vec!["dream"];
        full.extend_from_slice(args);
        self.p.mezha_env(&full, &env)
    }

    fn dreams(&self) -> PathBuf {
        mezha_memory::dreams_dir(&self.p.home, &self.p.root)
    }

    fn branches(&self) -> Vec<String> {
        git_ok(
            &self.p.root,
            &self.p.home,
            &[
                "for-each-ref",
                "--format=%(refname:short)",
                "refs/heads/mezha/",
            ],
        )
        .lines()
        .map(str::to_string)
        .collect()
    }

    fn workspaces(&self) -> Vec<PathBuf> {
        let mut found: Vec<PathBuf> = fs::read_dir(self.dreams())
            .unwrap()
            .map(|e| e.unwrap().path())
            .filter(|p| p.file_name().unwrap().to_string_lossy().starts_with("20"))
            .collect();
        found.sort();
        found
    }

    fn no_hook_ran(&self) {
        for hook in ["post-checkout", "pre-commit", "commit-msg"] {
            assert!(
                !self.p.base.join(format!("hook-{hook}")).exists(),
                "{hook} ran"
            );
        }
    }
}

#[test]
fn project_memory_becomes_a_commit() {
    let s = setup();
    let out = s.dream("write", &["--role", "implementer"]);
    let (o, e) = (stdout(&out), stderr(&out));
    assert!(out.status.success(), "{o}\n{e}");
    let branches = s.branches();
    assert_eq!(branches.len(), 1, "{branches:?}");
    let branch = &branches[0];
    let at = |path: &str| git_ok(&s.p.root, &s.p.home, &["show", &format!("{branch}:{path}")]);
    assert_eq!(
        at(".claude/agent-memory/implementer/MEMORY.md"),
        "# Memory\n\n- Run cargo test -p x before reporting (seen 2 times).\n"
    );
    let log = at(".claude/agent-memory/implementer/CHANGELOG.md");
    assert!(
        log.contains("Dreamer: claude-test, 4 turns, $0.12, Claude Code 2.1.285"),
        "{log}"
    );
    assert!(log.contains("Added a lesson."), "{log}");
    let message = git_ok(&s.p.root, &s.p.home, &["log", "-1", "--format=%B", branch]);
    assert!(
        message.starts_with("mezha dream: implementer (1 runs)"),
        "{message}"
    );
    assert!(message.contains("Mezha-Dream: "), "{message}");
    assert!(
        !message.contains("Added a lesson"),
        "model text in the commit message: {message}"
    );
    s.no_hook_ran();
    // The worktree is gone; the main checkout is untouched.
    let worktrees = git_ok(&s.p.root, &s.p.home, &["worktree", "list", "--porcelain"]);
    assert_eq!(worktrees.matches("worktree ").count(), 1, "{worktrees}");
    assert_eq!(
        s.p.read(".claude/agent-memory/implementer/MEMORY.md"),
        "# Memory\n"
    );
    // What the dreamer read: the digest, redacted.
    let ws = s.workspaces().pop().unwrap();
    let task = fs::read_to_string(ws.join("task-implementer.txt")).unwrap();
    assert!(task.contains("Role: implementer"), "{task}");
    assert!(task.contains("Do the thing in crates/x"), "{task}");
    assert!(task.contains("Next time run the tests first."), "{task}");
    assert!(task.contains("[mezha: redacted GitHub token]"), "{task}");
    assert!(!task.contains("ghp_0123"), "{task}");
    assert!(ws.join("pr.md").is_file());
    assert!(o.contains("git push -u origin mezha/dream-"), "{o}");

    // The cursor moved: nothing new for a second dream.
    let again = s.dream("write", &["--role", "implementer"]);
    assert!(again.status.success(), "{}", stderr(&again));
    assert!(
        stdout(&again).contains("Nothing new to dream about."),
        "{}",
        stdout(&again)
    );
}

#[test]
fn refusals_keep_the_workspace() {
    for (mode, why) in [
        ("outside", "the worktree changed during the dream"),
        ("hard", "zero-width"),
        ("changelog", "CHANGELOG.md: the dreamer changed it"),
        ("budget", "it reached its budget"),
        ("noresult", "claude ended without a result"),
        ("badinit", "the dreamer got the tools"),
    ] {
        let s = setup();
        let out = s.dream(mode, &["--role", "implementer"]);
        let e = stderr(&out);
        assert_eq!(out.status.code(), Some(1), "{mode}: {}\n{e}", stdout(&out));
        let text = format!("{}{e}", stdout(&out));
        let expected = if mode == "hard" {
            "invisible character"
        } else {
            why
        };
        assert!(text.contains(expected), "{mode}: {text}");
        let branch = &s.branches()[0];
        let ahead = git_ok(
            &s.p.root,
            &s.p.home,
            &["rev-list", "--count", &format!("main..{branch}")],
        );
        assert_eq!(ahead.trim(), "0", "{mode}: something was committed");
        let ws = s.workspaces().pop().unwrap();
        assert!(ws.join("wt").is_dir(), "{mode}: the worktree should stay");
        s.no_hook_ran();
    }
}

#[test]
fn phrases_are_highlighted_not_refused() {
    let s = setup();
    let out = s.dream("phrase", &["--role", "implementer"]);
    assert!(out.status.success(), "{}", stderr(&out));
    let o = stdout(&out);
    assert!(o.contains("look at: MEMORY.md:3: check bypass"), "{o}");
    let pr = fs::read_to_string(s.workspaces().pop().unwrap().join("pr.md")).unwrap();
    assert!(pr.contains("Phrases to look at"), "{pr}");
}

#[test]
fn terminal_escapes_are_shown_not_sent() {
    let s = setup();
    let out = s.dream("ansi", &["--role", "implementer"]);
    // A control character in the summary is a hard marker: no commit.
    assert_eq!(out.status.code(), Some(1), "{}", stdout(&out));
    let all = format!("{}{}", stdout(&out), stderr(&out));
    assert!(!all.contains('\u{1b}'), "{all}");
    assert!(
        all.contains("the dreamer's summary: control character (\\u{1b})"),
        "{all}"
    );
}

#[test]
fn no_change_leaves_no_branch() {
    let s = setup();
    let out = s.dream("nochange", &["--role", "implementer"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(stdout(&out).contains("no changes"));
    assert!(s.branches().is_empty());
    let again = s.dream("nochange", &["--role", "implementer"]);
    assert!(stdout(&again).contains("Nothing new to dream about."));
}

#[test]
fn local_memory_without_a_terminal_is_a_patch() {
    let s = setup();
    transcript(&s.p, "clinician", "c1");
    let out = s.dream("write", &["--role", "clinician"]);
    let o = stdout(&out);
    assert!(out.status.success(), "{o}\n{}", stderr(&out));
    assert!(o.contains("Not applied."), "{o}");
    assert!(o.contains("patch -p1 -E -d"), "{o}");
    assert!(
        !s.p.root
            .join(".claude/agent-memory-local/clinician")
            .exists()
    );
    let ws = s.workspaces().pop().unwrap();
    let patch = fs::read_to_string(ws.join("clinician.patch")).unwrap();
    assert!(patch.contains("+- Run cargo test -p x"), "{patch}");
    assert!(s.branches().is_empty());
    // The cursor didn't move: the next dream reads the run again.
    let again = s.dream("nochange", &["--role", "clinician"]);
    assert!(
        !stdout(&again).contains("Nothing new"),
        "{}",
        stdout(&again)
    );
}

#[test]
fn local_memory_that_changed_during_the_dream_is_not_applied() {
    let s = setup();
    transcript(&s.p, "clinician", "c1");
    let real = s.p.root.join(".claude/agent-memory-local/clinician");
    let out = s.dream_env(
        "tamper",
        &["--role", "clinician"],
        &[("REAL_DIR", real.to_str().unwrap())],
    );
    assert_eq!(out.status.code(), Some(1), "{}", stdout(&out));
    assert!(
        stderr(&out).contains("changed during the dream"),
        "{}",
        stderr(&out)
    );
    assert_eq!(
        fs::read_to_string(real.join("MEMORY.md")).unwrap(),
        "changed\n"
    );
}

#[test]
fn refuses_inside_claude_code_and_dry_runs_cost_nothing() {
    let s = setup();
    let out = s.dream_env("write", &[], &[("CLAUDECODE", "1")]);
    assert_eq!(out.status.code(), Some(1));
    assert!(stderr(&out).contains("refuses to run inside Claude Code"));
    assert!(!s.dreams().exists());

    let out = s.dream("write", &["--dry-run"]);
    let o = stdout(&out);
    assert!(out.status.success(), "{o}\n{}", stderr(&out));
    assert!(o.contains("Dry run: no dreamer ran"), "{o}");
    assert!(o.contains("--restricted"), "{o}");
    let ws = s.workspaces().pop().unwrap();
    assert!(!ws.join("task-implementer.txt").exists(), "claude ran");
    assert!(fs::read_dir(ws.join("inbox/implementer")).unwrap().count() > 0);
    assert!(s.branches().is_empty());
}

#[test]
fn refuses_memory_behind_a_symlink() {
    let s = setup();
    let dir = s.p.root.join(".claude/agent-memory/implementer");
    fs::remove_dir_all(&dir).unwrap();
    std::os::unix::fs::symlink("../../elsewhere", &dir).unwrap();
    git_ok(&s.p.root, &s.p.home, &["add", "-A"]);
    git_ok(
        &s.p.root,
        &s.p.home,
        &["commit", "-q", "--no-verify", "-m", "link"],
    );
    let out = s.dream("write", &["--role", "implementer"]);
    assert_eq!(out.status.code(), Some(1), "{}", stdout(&out));
    assert!(stderr(&out).contains("is a symlink"), "{}", stderr(&out));
    assert!(s.branches().is_empty());
}

impl Setup {
    /// Any mezha command, with the stand-in claude and the real mezha on PATH.
    fn cmd(&self, args: &[&str], mode: &str, extra: &[(&str, &str)]) -> Output {
        let mezha_dir = Path::new(common::BIN).parent().unwrap();
        let path = format!(
            "{}:{}:/usr/bin:/bin",
            self.bin.display(),
            mezha_dir.display()
        );
        let mut env = vec![("PATH", path.as_str()), ("FAKE_MODE", mode)];
        env.extend_from_slice(extra);
        self.p.mezha_env(args, &env)
    }

    fn nightly(&self) {
        self.p.write_spec(&format!(
            "{SPEC}\n[memory]\ndream_schedule = \"nightly\"\ndream_at = \"02:30\"\n"
        ));
    }

    fn last_run(&self) -> serde_json::Value {
        serde_json::from_str(&fs::read_to_string(self.dreams().join("last-run.json")).unwrap())
            .unwrap()
    }
}

#[test]
fn schedules_are_printed_not_installed() {
    let s = setup();
    let out = s.cmd(&["dream", "--schedule", "launchd"], "write", &[]);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        stderr(&out).contains("dream_schedule = \"manual\""),
        "{}",
        stderr(&out)
    );

    s.nightly();
    let out = s.cmd(&["dream", "--schedule", "launchd"], "write", &[]);
    let o = stdout(&out);
    assert!(out.status.success(), "{o}\n{}", stderr(&out));
    let mezha = Path::new(common::BIN);
    for want in [
        format!("<string>{}</string>", mezha.display()),
        format!("<string>{}</string>", s.p.root.display()),
        "<string>--scheduled</string>".to_string(),
        "<integer>2</integer>".to_string(),
        "<integer>30</integer>".to_string(),
        "launchctl bootstrap gui/$(id -u)".to_string(),
    ] {
        assert!(o.contains(&want), "{want}: {o}");
    }
    assert!(!s.p.home.join("Library").exists(), "nothing is installed");
    assert!(s.dreams().is_dir(), "the log's directory exists");

    let o = stdout(&s.cmd(&["dream", "--schedule", "systemd"], "write", &[]));
    assert!(o.contains("OnCalendar=*-*-* 02:30:00"), "{o}");
    let o = stdout(&s.cmd(&["dream", "--schedule", "cron"], "write", &[]));
    assert!(o.contains("30 2 * * * env PATH="), "{o}");
    let bad = s.cmd(&["dream", "--schedule", "anacron"], "write", &[]);
    assert!(stderr(&bad).contains("launchd, systemd or cron"));
}

#[test]
fn scheduled_dreams_skip_what_needs_you() {
    let s = setup();
    transcript(&s.p, "clinician", "c1");
    let out = s.dream("write", &["--scheduled"]);
    let o = stdout(&out);
    assert!(out.status.success(), "{o}\n{}", stderr(&out));
    assert!(
        o.contains("Skipping clinician: its local memory needs you at a terminal."),
        "{o}"
    );
    let first = s.branches();
    assert_eq!(first.len(), 1);
    let last = s.last_run();
    assert_eq!(
        (last["ok"].as_bool(), last["scheduled"].as_bool()),
        (Some(true), Some(true))
    );

    // A new run, but the last dream is still on its branch: skipped.
    transcript_ago(&s.p, "implementer", "a2", 600);
    let out = s.dream("write", &["--scheduled"]);
    let o = stdout(&out);
    assert!(out.status.success(), "{o}\n{}", stderr(&out));
    assert!(
        o.contains("Skipping implementer: its last dream on mezha/dream-"),
        "{o}"
    );
    assert!(o.contains("Nothing to dream about tonight."), "{o}");

    // Merged as it was: decided, and the next night dreams again.
    git_ok(
        &s.p.root,
        &s.p.home,
        &[
            "merge",
            "-q",
            "--no-ff",
            "--no-verify",
            "-m",
            "Merge the dream",
            &first[0],
        ],
    );
    let report = s.cmd(&["metrics", "--json"], "write", &[]);
    let json: serde_json::Value = serde_json::from_str(&stdout(&report)).unwrap();
    assert_eq!(json["dreams"]["without_edits"], 1, "{json}");
    assert_eq!(json["dreams"]["pending"], 0, "{json}");
    // The stand-in writes the lesson that just landed, so: no changes.
    let out = s.dream("write", &["--scheduled"]);
    let o = stdout(&out);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(o.contains("Dreaming implementer"), "{o}");
    assert!(o.contains("no changes"), "{o}");
}

#[test]
fn a_refused_dream_stops_the_schedule_and_says_why() {
    let s = setup();
    let out = s.dream("outside", &["--role", "implementer"]);
    assert_eq!(out.status.code(), Some(1));
    let last = s.last_run();
    assert_eq!(last["ok"], false);
    assert!(
        last["error"].as_str().unwrap().contains("worktree changed"),
        "{last}"
    );
    let out = s.dream("write", &["--scheduled"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        stderr(&out).contains("a refused dream is waiting for you"),
        "{}",
        stderr(&out)
    );
    let report = stdout(&s.cmd(&["metrics"], "write", &[]));
    assert!(report.contains("Last dream"), "{report}");
    assert!(report.contains("FAILED"), "{report}");
}

#[test]
fn one_dream_at_a_time() {
    let s = setup();
    fs::create_dir_all(s.dreams()).unwrap();
    let _held = mezha_memory::lock::try_lock(&s.dreams().join("dream.lock"), "pid 42").unwrap();
    let out = s.dream("write", &["--role", "implementer"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        stderr(&out).contains("another dream of this project is running (pid 42)"),
        "{}",
        stderr(&out)
    );
}

#[test]
fn metrics_record_and_report() {
    let s = setup();
    let out = s.cmd(&["metrics", "--record"], "write", &[]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(stdout(&out).is_empty());
    let file = mezha_memory::metrics_dir(&s.p.home, &s.p.root).join("sessions.jsonl");
    let lines = || fs::read_to_string(&file).unwrap().lines().count();
    assert_eq!(lines(), 1);
    s.cmd(&["metrics", "--record"], "write", &[]);
    assert_eq!(lines(), 1, "recording twice adds nothing");

    let report = s.cmd(&["metrics", "--json"], "write", &[]);
    let json: serde_json::Value = serde_json::from_str(&stdout(&report)).unwrap();
    assert_eq!(json["sessions"], 1);
    assert_eq!(json["roles"]["implementer"]["runs"], 1);
    assert_eq!(json["roles"]["implementer"]["with_lessons"], 1);
    let human = stdout(&s.cmd(&["metrics"], "write", &[]));
    assert!(human.contains("1 session(s)"), "{human}");

    let inside = s.cmd(&["metrics", "--record"], "write", &[("CLAUDECODE", "1")]);
    assert_eq!(inside.status.code(), Some(1));
}
