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

/// A second project role, a role whose memory lives in your user config,
/// and one without memory.
const MORE_ROLES: &str = r#"
[agent.reviewer]
description = "Reviews changes."
tools = ["Read"]
rule_of_two = ["private_data"]
memory = { scope = "project" }

[agent.scribe]
description = "Keeps notes across projects."
tools = ["Read"]
rule_of_two = ["private_data"]
memory = { scope = "user" }

[agent.plain]
description = "Remembers nothing."
tools = ["Read"]
rule_of_two = ["private_data"]
"#;

const FAKE_CLAUDE: &str = r#"#!/bin/sh
# A stand-in for claude: checks how mezha dream runs it, then acts per $FAKE_MODE,
# or per $FAKE_ROLE_MODE (`<role>=<mode>`) for that one role.
if [ "$1" = "--version" ]; then echo "${FAKE_VERSION:-2.1.285 (Claude Code)}"; exit 0; fi
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
role=$(basename "$staged")
mode="$FAKE_MODE"
case "$FAKE_ROLE_MODE" in "$role="*) mode="${FAKE_ROLE_MODE#*=}" ;; esac
cat > "$staged/../../task-$role.txt"
env > "$staged/../../env-$role.txt"
[ "$mode" = noinit ] && exit 0
tools_json='["Edit","Glob","Grep","Read","Write"]'
[ "$mode" = badinit ] && tools_json='["Bash","Edit","Glob","Grep","Read","Write"]'
plugins='[]'
[ "$mode" = plugins ] && plugins='[{"name":"tidy","source":"tidy@shop"},{"name":"core","source":"core@builtin"}]'
printf '{"type":"system","subtype":"init","tools":%s,"mcp_servers":[],"permissionMode":"dontAsk","model":"claude-test","apiKeySource":"none","plugins":%s}\n' "$tools_json" "$plugins"
[ "$mode" = badinit ] && { sleep 30; exit 0; }
summary="Added a lesson."
denials='[]'
case "$mode" in
  write) printf '# Memory\n\n- Run cargo test -p x before reporting (seen 2 times).\n' > "$staged/MEMORY.md" ;;
  plugins) printf '# Memory\n\n- a lesson\n' > "$staged/MEMORY.md"; denials='[{"tool_name":"Bash","tool_input":{"command":"rm -rf /"}}]' ;;
  empty) : > "$staged/MEMORY.md" ;;
  long) i=0; while [ $i -lt 201 ]; do echo "- line $i"; i=$((i+1)); done > "$staged/MEMORY.md" ;;
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
# Ten messages and an event of another kind, as a real session streams them.
i=0; while [ $i -lt 10 ]; do printf '{"type":"assistant","message":{"content":[{"type":"text","text":"ok"}]}}\n'; i=$((i+1)); done
printf '{"type":"user","message":{"content":[]}}\n'
printf '{"type":"result","subtype":"success","is_error":false,"num_turns":4,"total_cost_usd":0.12,"result":"%s","permission_denials":%s}\n' "$summary" "$denials"
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
    transcript_in(p, &p.root, role, id, sooner);
}

/// A session that ran in `root` (the project or a worktree of it).
fn transcript_in(p: &Project, root: &Path, role: &str, id: &str, sooner: u64) {
    transcript_padded(p, root, role, id, sooner, "");
}

/// The same, with `pad` added to the task and the final message, for runs
/// whose digests are big.
fn transcript_padded(p: &Project, root: &Path, role: &str, id: &str, sooner: u64, pad: &str) {
    let ts = |ago: u64| format_iso((now() - ago + sooner) as i64);
    let dir = p
        .home
        .join(".claude/projects")
        .join(project_dir_name(&root.to_string_lossy()));
    let cwd = root.to_string_lossy().into_owned();
    let session = format!("s-{id}");
    let mut parent = String::new();
    parent.push_str(&line(serde_json::json!({"type": "user", "uuid": format!("{id}-p1"), "timestamp": ts(3700), "cwd": cwd, "sessionId": session, "origin": {"kind": "human"}, "message": {"role": "user", "content": "Please do the thing"}})));
    parent.push_str(&line(serde_json::json!({"type": "user", "uuid": format!("{id}-p2"), "timestamp": ts(3500), "cwd": cwd, "sessionId": session, "toolUseResult": {"status": "completed", "agentId": id}, "message": {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "t1", "content": "done"}]}})));
    parent.push_str(&line(serde_json::json!({"type": "user", "uuid": format!("{id}-p3"), "timestamp": ts(3400), "cwd": cwd, "sessionId": session, "origin": {"kind": "human"}, "message": {"role": "user", "content": "Next time run the tests first."}})));
    write(&dir.join(format!("{session}.jsonl")), &parent);
    let mut agent = String::new();
    agent.push_str(&line(serde_json::json!({"type": "user", "uuid": format!("{id}-a1"), "timestamp": ts(3650), "cwd": cwd, "sessionId": session, "isSidechain": true, "agentId": id, "message": {"role": "user", "content": format!("Do the thing in crates/x{pad}")}})));
    agent.push_str(&line(serde_json::json!({"type": "assistant", "uuid": format!("{id}-a2"), "timestamp": ts(3550), "cwd": cwd, "sessionId": session, "isSidechain": true, "agentId": id, "message": {"id": "m1", "role": "assistant", "content": [{"type": "text", "text": format!("Done.{pad}\n\n## Lessons\n\n- Tests first.\n- Token ghp_0123456789abcdefghijklmnopqrstuvwxyzAB")}]}})));
    let sub = dir.join(&session).join("subagents");
    write(&sub.join(format!("agent-{id}.jsonl")), &agent);
    write(
        &sub.join(format!("agent-{id}.meta.json")),
        &serde_json::json!({"agentType": role, "description": "x"}).to_string(),
    );
}

fn setup() -> Setup {
    setup_spec(SPEC)
}

/// A committed project with `spec`, with implementer's memory in git and a
/// run of implementer in the transcripts.
fn setup_spec(spec: &str) -> Setup {
    let p = Project::new();
    write(
        &p.home.join(".gitconfig"),
        "[user]\n\tname = Test\n\temail = test@example.com\n",
    );
    git_ok(&p.root, &p.home, &["init", "-q", "-b", "main"]);
    p.write_spec(spec);
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
        ("noinit", "claude didn't report how it started"),
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

#[test]
fn the_base_can_be_named_and_must_be_a_commit() {
    let s = setup();
    let out = s.dream("write", &["--dry-run", "--base", "main"]);
    let o = stdout(&out);
    assert!(out.status.success(), "{o}\n{}", stderr(&out));
    assert!(o.contains("in a worktree of main:"), "{o}");

    let out = s.dream("write", &["--dry-run", "--base=-x"]);
    assert_eq!(out.status.code(), Some(1), "{}", stdout(&out));
    assert!(
        stderr(&out).contains("--base `-x` is not a revision"),
        "{}",
        stderr(&out)
    );
    let out = s.dream("write", &["--dry-run", "--base", "nowhere"]);
    assert_eq!(out.status.code(), Some(1), "{}", stdout(&out));
    assert!(
        stderr(&out).contains("--base nowhere is not a commit"),
        "{}",
        stderr(&out)
    );
    assert!(s.branches().is_empty());
}

#[test]
fn origin_head_is_the_default_base() {
    let s = setup();
    let head = git_ok(&s.p.root, &s.p.home, &["rev-parse", "HEAD"]);
    git_ok(
        &s.p.root,
        &s.p.home,
        &["update-ref", "refs/remotes/origin/main", head.trim()],
    );
    git_ok(
        &s.p.root,
        &s.p.home,
        &[
            "symbolic-ref",
            "refs/remotes/origin/HEAD",
            "refs/remotes/origin/main",
        ],
    );
    let out = s.dream("write", &["--role", "implementer"]);
    let (o, e) = (stdout(&out), stderr(&out));
    assert!(out.status.success(), "{o}\n{e}");
    assert!(o.contains("(from origin/main)"), "{o}");
    assert!(
        o.contains("gh pr create --base main --head mezha/dream-"),
        "{o}"
    );
    assert!(!e.contains("no origin/HEAD"), "{e}");
}

#[test]
fn a_branch_name_already_taken_gets_a_suffix() {
    let s = setup();
    let start = now();
    for t in start..start + 5 {
        git_ok(
            &s.p.root,
            &s.p.home,
            &[
                "branch",
                &format!("mezha/dream-{}", mezha_render::utc_stamp(t)),
            ],
        );
    }
    let out = s.dream("write", &["--role", "implementer"]);
    let o = stdout(&out);
    assert!(out.status.success(), "{o}\n{}", stderr(&out));
    let created: Vec<String> = s
        .branches()
        .into_iter()
        .filter(|b| b.ends_with("-2"))
        .collect();
    assert_eq!(created.len(), 1, "{:?}", s.branches());
    assert!(o.contains(&format!("on {} (from main)", created[0])), "{o}");
}

#[test]
fn notes_say_what_the_dream_does_not_see() {
    let s = setup();
    // Old finished dreams beyond the newest few are pruned.
    for n in 1..=6 {
        fs::create_dir_all(s.dreams().join(format!("2020010{n}T000000Z"))).unwrap();
    }
    // A refused dream leaves its worktree, which the next dream points out.
    let out = s.dream("outside", &["--role", "implementer"]);
    assert_eq!(out.status.code(), Some(1), "{}", stdout(&out));
    let refused = s.workspaces().pop().unwrap();
    // Memory edited here but not committed, and another worktree whose
    // sessions count as this project's.
    fs::write(
        s.p.root.join(".claude/agent-memory/implementer/MEMORY.md"),
        "# Memory\n\n- edited here, not committed\n",
    )
    .unwrap();
    let feature = s.p.base.join("feature");
    git_ok(
        &s.p.root,
        &s.p.home,
        &["worktree", "add", "-q", feature.to_str().unwrap()],
    );
    transcript_in(&s.p, &feature, "implementer", "f1", 300);
    let config = s.p.home.join(".claude");
    let out = s.dream_env(
        "write",
        &["--role", "implementer"],
        &[
            ("CLAUDE_CONFIG_DIR", config.to_str().unwrap()),
            (
                "CLAUDE_CODE_PROJECT_DIR_NAME",
                &project_dir_name(&s.p.root.to_string_lossy()),
            ),
        ],
    );
    let (o, e) = (stdout(&out), stderr(&out));
    assert!(out.status.success(), "{o}\n{e}");
    assert!(
        e.contains(&format!(
            "note: refused dreams still have worktrees: {}",
            refused.join("wt").display()
        )),
        "{e}"
    );
    assert!(
        e.contains("note: .claude/agent-memory has uncommitted changes here; the dream starts from main without them"),
        "{e}"
    );
    assert!(o.contains("Read 2 session(s)"), "{o}");
    assert!(o.contains("implementer    project  2 run(s)"), "{o}");
    assert!(!s.dreams().join("20200101T000000Z").exists(), "not pruned");
    assert!(
        s.dreams().join("20200102T000000Z").is_dir(),
        "pruned too much"
    );
    assert!(
        refused.join("wt").is_dir(),
        "a refused dream is never pruned"
    );
}

#[test]
fn tracked_local_memory_is_refused() {
    let s = setup();
    write(
        &s.p.root
            .join(".claude/agent-memory-local/clinician/MEMORY.md"),
        "# Local\n",
    );
    git_ok(
        &s.p.root,
        &s.p.home,
        &["add", "-f", ".claude/agent-memory-local"],
    );
    git_ok(
        &s.p.root,
        &s.p.home,
        &["commit", "-q", "--no-verify", "-m", "oops"],
    );
    let out = s.dream("write", &["--role", "implementer"]);
    assert_eq!(out.status.code(), Some(1), "{}", stdout(&out));
    assert!(
        stderr(&out).contains("main tracks .claude/agent-memory-local/, which is local memory"),
        "{}",
        stderr(&out)
    );
    assert!(s.branches().is_empty());
}

#[test]
fn roles_are_checked_before_anything_runs() {
    let s = setup_spec(&format!("{SPEC}{MORE_ROLES}"));
    let out = s.dream("write", &["--role", "nobody"]);
    assert_eq!(out.status.code(), Some(1), "{}", stdout(&out));
    assert!(
        stderr(&out).contains("there is no agent.nobody in mezha.toml"),
        "{}",
        stderr(&out)
    );
    let out = s.dream("write", &["--role", "plain"]);
    assert_eq!(out.status.code(), Some(1), "{}", stdout(&out));
    assert!(
        stderr(&out).contains("agent.plain has no memory"),
        "{}",
        stderr(&out)
    );
    assert!(!s.dreams().exists(), "nothing was set up");

    let s = setup_spec(
        "[project]\nname = \"dreamtest\"\n\n[policy]\npermissions_ask = [\"git push\"]\n\n[agent.plain]\ndescription = \"Remembers nothing.\"\ntools = [\"Read\"]\nrule_of_two = [\"private_data\"]\n",
    );
    let out = s.dream("write", &[]);
    assert_eq!(out.status.code(), Some(1), "{}", stdout(&out));
    assert!(
        stderr(&out).contains("no agent in mezha.toml has memory"),
        "{}",
        stderr(&out)
    );
}

#[test]
fn project_memory_must_be_flat_files() {
    let s = setup();
    write(
        &s.p.root
            .join(".claude/agent-memory/implementer/notes/deep.md"),
        "deep\n",
    );
    git_ok(&s.p.root, &s.p.home, &["add", "-A"]);
    git_ok(
        &s.p.root,
        &s.p.home,
        &["commit", "-q", "--no-verify", "-m", "nested"],
    );
    let out = s.dream("write", &["--role", "implementer"]);
    assert_eq!(out.status.code(), Some(1), "{}", stdout(&out));
    assert!(
        stderr(&out).contains(".claude/agent-memory/implementer/notes/deep.md at ")
            && stderr(&out).contains("isn't a plain file directly in the memory directory"),
        "{}",
        stderr(&out)
    );
    assert!(s.branches().is_empty());
}

#[test]
fn refuses_local_memory_behind_a_symlink() {
    let s = setup();
    transcript(&s.p, "clinician", "c1");
    let elsewhere = s.p.base.join("elsewhere");
    fs::create_dir_all(&elsewhere).unwrap();
    std::os::unix::fs::symlink(&elsewhere, s.p.root.join(".claude/agent-memory-local")).unwrap();
    let out = s.dream("write", &["--role", "clinician"]);
    assert_eq!(out.status.code(), Some(1), "{}", stdout(&out));
    assert!(
        stderr(&out)
            .contains("agent-memory-local is a symlink, so local memory can't be dreamed safely"),
        "{}",
        stderr(&out)
    );
    assert!(
        fs::read_dir(&elsewhere).unwrap().next().is_none(),
        "something was written"
    );
}

#[test]
fn user_memory_is_dreamed_from_your_config_but_never_through_a_symlink() {
    let s = setup_spec(&format!("{SPEC}{MORE_ROLES}"));
    transcript(&s.p, "scribe", "u1");
    let out = s.dream("write", &["--role", "scribe"]);
    let o = stdout(&out);
    assert!(out.status.success(), "{o}\n{}", stderr(&out));
    assert!(o.contains("scribe         user     1 run(s)"), "{o}");
    let user_dir = s.p.home.join(".claude/agent-memory/scribe");
    assert!(
        o.contains(&format!(
            "The dreamer's changes to the memory of scribe in {}:",
            user_dir.display()
        )),
        "{o}"
    );
    assert!(o.contains("Not applied."), "{o}");
    assert!(!user_dir.exists(), "applied without asking");
    assert!(s.branches().is_empty());

    fs::create_dir_all(user_dir.parent().unwrap()).unwrap();
    let elsewhere = s.p.base.join("elsewhere");
    fs::create_dir_all(&elsewhere).unwrap();
    std::os::unix::fs::symlink(&elsewhere, &user_dir).unwrap();
    let out = s.dream("write", &["--role", "scribe"]);
    assert_eq!(out.status.code(), Some(1), "{}", stdout(&out));
    assert!(
        stderr(&out).contains("scribe is a symlink, so user memory can't be dreamed safely"),
        "{}",
        stderr(&out)
    );
}

#[test]
fn claude_must_be_a_recent_version_that_runs() {
    let s = setup();
    let out = s.dream_env(
        "write",
        &["--role", "implementer"],
        &[("FAKE_VERSION", "banana")],
    );
    assert_eq!(out.status.code(), Some(1), "{}", stdout(&out));
    assert!(
        stderr(&out).contains("`claude --version` said \"banana\", not a version"),
        "{}",
        stderr(&out)
    );
    let out = s.dream_env(
        "write",
        &["--role", "implementer"],
        &[("FAKE_VERSION", "1.0.0 (Claude Code)")],
    );
    assert_eq!(out.status.code(), Some(1), "{}", stdout(&out));
    assert!(
        stderr(&out).contains("Claude Code 1.0.0 (Claude Code) is older than"),
        "{}",
        stderr(&out)
    );
    // One that can't start at all.
    write(&s.bin.join("claude"), "#!/nonexistent/interpreter\n");
    let out = s.dream("write", &["--role", "implementer"]);
    assert_eq!(out.status.code(), Some(1), "{}", stdout(&out));
    assert!(
        stderr(&out).contains("error:") && stderr(&out).contains("os error"),
        "{}",
        stderr(&out)
    );
    assert!(s.branches().is_empty(), "{:?}", s.branches());
}

#[test]
fn a_refusal_after_a_commit_names_the_roles_already_on_the_branch() {
    let s = setup_spec(&format!("{SPEC}{MORE_ROLES}"));
    transcript(&s.p, "reviewer", "r1");
    let out = s.dream_env("write", &[], &[("FAKE_ROLE_MODE", "reviewer=outside")]);
    let (o, e) = (stdout(&out), stderr(&out));
    assert_eq!(out.status.code(), Some(1), "{o}\n{e}");
    assert!(o.contains("committed 2 file(s)"), "{o}");
    assert!(e.contains("The dream of reviewer was refused:"), "{e}");
    assert!(
        e.contains("Roles committed before it are on mezha/dream-")
            && e.contains(": implementer\n"),
        "{e}"
    );
    let last = s.last_run();
    assert_eq!(last["roles"], serde_json::json!(["implementer"]), "{last}");
    assert_eq!(last["cost_usd"], 0.24, "both sessions cost: {last}");
    assert!(
        last["error"].as_str().unwrap().starts_with("reviewer: "),
        "{last}"
    );
    let branch = &s.branches()[0];
    let ahead = git_ok(
        &s.p.root,
        &s.p.home,
        &["rev-list", "--count", &format!("main..{branch}")],
    );
    assert_eq!(ahead.trim(), "1", "only implementer was committed");
}

#[test]
fn the_dreamer_s_progress_plugins_and_denials_are_shown() {
    let s = setup();
    let out = s.dream("plugins", &["--role", "implementer"]);
    let o = stdout(&out);
    assert!(out.status.success(), "{o}\n{}", stderr(&out));
    assert!(o.contains("  … 10 messages"), "{o}");
    assert!(
        o.contains("done: 4 turns, $0.12; plugins loaded: tidy\n"),
        "builtin plugins aren't listed: {o}"
    );
    assert!(
        o.contains("refused by Claude Code: Bash {\"command\":\"rm -rf /\"}"),
        "{o}"
    );
}

#[test]
fn an_emptied_file_is_removed_and_a_long_index_is_a_warning() {
    let s = setup();
    let out = s.dream("empty", &["--role", "implementer"]);
    let o = stdout(&out);
    assert!(out.status.success(), "{o}\n{}", stderr(&out));
    assert!(o.contains("  remove MEMORY.md"), "{o}");
    let branch = &s.branches()[0];
    let listed = git_ok(
        &s.p.root,
        &s.p.home,
        &[
            "ls-tree",
            "-r",
            "--name-only",
            branch,
            ".claude/agent-memory/implementer/",
        ],
    );
    assert_eq!(
        listed.trim(),
        ".claude/agent-memory/implementer/CHANGELOG.md",
        "{listed}"
    );

    let s = setup();
    let out = s.dream("long", &["--role", "implementer"]);
    let (o, e) = (stdout(&out), stderr(&out));
    assert!(out.status.success(), "{o}\n{e}");
    assert!(e.contains("warning: MEMORY.md has 201 lines and"), "{e}");
    assert_eq!(s.branches().len(), 1, "a warning doesn't refuse");
}

#[test]
fn an_unwritable_metrics_store_is_a_note_not_a_refusal() {
    let s = setup();
    let store = mezha_memory::metrics_dir(&s.p.home, &s.p.root);
    // A directory where the store's files should be: nothing can be written.
    fs::create_dir_all(store.join("sessions.jsonl")).unwrap();
    fs::create_dir_all(store.join("dreams.jsonl")).unwrap();
    let out = s.dream("write", &["--role", "implementer"]);
    let (o, e) = (stdout(&out), stderr(&out));
    assert!(out.status.success(), "{o}\n{e}");
    assert!(e.contains("note: couldn't record metrics:"), "{e}");
    assert!(
        e.contains("note: couldn't record the dream in the metrics store:"),
        "{e}"
    );
    assert_eq!(s.branches().len(), 1, "{:?}", s.branches());
}

#[test]
fn an_unwritable_dreams_directory_is_an_error() {
    let s = setup();
    fs::create_dir_all(s.dreams()).unwrap();
    fs::set_permissions(s.dreams(), fs::Permissions::from_mode(0o500)).unwrap();
    let out = s.dream("write", &["--role", "implementer"]);
    fs::set_permissions(s.dreams(), fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(out.status.code(), Some(1), "{}", stdout(&out));
    assert!(
        stderr(&out).contains(&format!(
            "can't lock {}",
            s.dreams().join("dream.lock").display()
        )),
        "{}",
        stderr(&out)
    );
    assert!(s.branches().is_empty());
}

#[test]
fn user_settings_reach_the_dreamer_except_what_needs_you() {
    let s = setup();
    write(
        &s.p.home.join(".claude/settings.json"),
        r#"{"env": {"ANTHROPIC_BASE_URL": "http://proxy.localhost:1", "EDITOR": "vi"}, "awsAuthRefresh": "aws sso login"}"#,
    );
    let out = s.dream("write", &["--scheduled"]);
    let o = stdout(&out);
    assert!(out.status.success(), "{o}\n{}", stderr(&out));
    assert!(o.contains("Not using awsAuthRefresh unattended"), "{o}");
    assert!(
        o.contains("From your user settings: ANTHROPIC_BASE_URL\n"),
        "{o}"
    );
    let ws = s.workspaces().pop().unwrap();
    let settings = fs::read_to_string(ws.join("settings-implementer.json")).unwrap();
    assert!(!settings.contains("awsAuthRefresh"), "{settings}");
    let env = fs::read_to_string(ws.join("env-implementer.txt")).unwrap();
    assert!(
        env.contains("ANTHROPIC_BASE_URL=http://proxy.localhost:1\n"),
        "{env}"
    );
    assert!(!env.contains("EDITOR="), "{env}");

    // At a terminal, the refresh command is forwarded as it is.
    let s = setup();
    write(
        &s.p.home.join(".claude/settings.json"),
        r#"{"awsAuthRefresh": "aws sso login"}"#,
    );
    let out = s.dream("write", &["--role", "implementer"]);
    let o = stdout(&out);
    assert!(out.status.success(), "{o}\n{}", stderr(&out));
    assert!(
        o.contains("From your user settings: awsAuthRefresh\n"),
        "{o}"
    );
}

#[test]
fn the_newest_dream_of_a_role_decides_whether_it_is_pending() {
    let s = setup();
    let out = s.dream("write", &["--role", "implementer"]);
    assert!(out.status.success(), "{}", stderr(&out));
    let first = s.branches()[0].clone();
    git_ok(
        &s.p.root,
        &s.p.home,
        &[
            "merge",
            "-q",
            "--no-ff",
            "--no-verify",
            "-m",
            "Merge",
            &first,
        ],
    );
    // A second dream, a second later so the store keeps both.
    transcript_ago(&s.p, "implementer", "a2", 600);
    std::thread::sleep(std::time::Duration::from_millis(1100));
    let out = s.dream("phrase", &["--role", "implementer"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(s.branches().len(), 2, "{:?}", s.branches());
    let rows =
        fs::read_to_string(mezha_memory::metrics_dir(&s.p.home, &s.p.root).join("dreams.jsonl"))
            .unwrap();
    assert_eq!(rows.lines().count(), 2, "{rows}");

    // The newest is still on its branch, so a scheduled run skips the role.
    transcript_ago(&s.p, "implementer", "a3", 1200);
    let out = s.dream("write", &["--scheduled"]);
    let o = stdout(&out);
    assert!(out.status.success(), "{o}\n{}", stderr(&out));
    assert!(
        o.contains("Skipping implementer: its last dream on mezha/dream-"),
        "{o}"
    );
    assert_eq!(s.branches().len(), 2, "{:?}", s.branches());
}

#[test]
fn metrics_count_sessions_in_worktrees_but_not_in_ab_runs() {
    let s = setup();
    let feature = s.p.base.join("feature");
    git_ok(
        &s.p.root,
        &s.p.home,
        &["worktree", "add", "-q", feature.to_str().unwrap()],
    );
    transcript_in(&s.p, &feature, "implementer", "f1", 100);
    // An A/B worktree under the temp dir runs no sessions of yours.
    let ab = s.p.tmp.join("mezha-ab-x1y2").join("run-abc");
    fs::create_dir_all(ab.parent().unwrap()).unwrap();
    git_ok(
        &s.p.root,
        &s.p.home,
        &["worktree", "add", "-q", ab.to_str().unwrap()],
    );
    transcript_in(&s.p, &ab, "implementer", "x1", 200);
    let report = s.cmd(&["metrics", "--json"], "write", &[]);
    assert!(report.status.success(), "{}", stderr(&report));
    let json: serde_json::Value = serde_json::from_str(&stdout(&report)).unwrap();
    assert_eq!(json["sessions"], 2, "{json}");

    // Without a trusted git, only the project itself is read. PATH names
    // an empty directory: /bin has git where it is /usr/bin (Ubuntu).
    let no_git = s.p.base.join("no-git");
    fs::create_dir_all(&no_git).unwrap();
    let report = s.p.mezha_env(
        &["metrics", "--json"],
        &[("PATH", no_git.to_str().unwrap())],
    );
    assert!(report.status.success(), "{}", stderr(&report));
    let json: serde_json::Value = serde_json::from_str(&stdout(&report)).unwrap();
    assert_eq!(json["sessions"], 1, "{json}");
}

#[test]
fn recorded_dreams_are_listed_as_they_are_when_they_cannot_be_judged() {
    let row = |scope: &str, at: u64| {
        serde_json::json!({
            "v": 1, "key": format!("20260101T000000Z/{scope}"), "stamp": "20260101T000000Z",
            "role": "implementer", "scope": scope, "at": at, "runs": 1, "turns": 2,
            "cost_usd": 0.1, "commit": null, "dir": null, "patch_id": null,
            "branch": null, "applied": scope != "project", "outcome": null
        })
        .to_string()
    };
    // Local memory has no branch to watch; a project dream without a
    // recorded directory can't be matched with the base's commits.
    let s = setup();
    let store = mezha_memory::metrics_dir(&s.p.home, &s.p.root);
    fs::create_dir_all(&store).unwrap();
    fs::write(
        store.join("dreams.jsonl"),
        format!(
            "{}\n{}\n",
            row("local", now() - 100),
            row("project", now() - 50)
        ),
    )
    .unwrap();
    let report = s.cmd(&["metrics", "--json"], "write", &[]);
    assert!(report.status.success(), "{}", stderr(&report));
    let json: serde_json::Value = serde_json::from_str(&stdout(&report)).unwrap();
    assert_eq!(json["dreams"]["with_edits"], 0, "{json}");
    assert_eq!(json["dreams"]["without_edits"], 0, "{json}");
    let human = stdout(&s.cmd(&["metrics"], "write", &[]));
    assert!(human.contains("Dreams"), "{human}");

    // A repository without commits has no base to judge against.
    let p = Project::new();
    git_ok(&p.root, &p.home, &["init", "-q", "-b", "main"]);
    p.write_spec(SPEC);
    let store = mezha_memory::metrics_dir(&p.home, &p.root);
    fs::create_dir_all(&store).unwrap();
    fs::write(store.join("dreams.jsonl"), row("project", now() - 50)).unwrap();
    let report = p.mezha(&["metrics", "--json"]);
    assert!(report.status.success(), "{}", stderr(&report));
    let json: serde_json::Value = serde_json::from_str(&stdout(&report)).unwrap();
    assert_eq!(json["dreams"]["with_edits"], 0, "{json}");
    assert_eq!(json["dreams"]["without_edits"], 0, "{json}");
}

#[test]
fn a_changelog_only_commit_in_the_base_is_not_a_memory_change() {
    let s = setup();
    let out = s.dream("write", &["--role", "implementer"]);
    assert!(out.status.success(), "{}", stderr(&out));
    let branch = s.branches()[0].clone();
    git_ok(
        &s.p.root,
        &s.p.home,
        &[
            "merge",
            "-q",
            "--no-ff",
            "--no-verify",
            "-m",
            "Merge",
            &branch,
        ],
    );
    write(
        &s.p.root
            .join(".claude/agent-memory/implementer/CHANGELOG.md"),
        "# Changelog\n\n- rewritten by hand\n",
    );
    git_ok(&s.p.root, &s.p.home, &["add", "-A"]);
    git_ok(
        &s.p.root,
        &s.p.home,
        &["commit", "-q", "--no-verify", "-m", "tidy the changelog"],
    );
    let report = s.cmd(&["metrics", "--json"], "write", &[]);
    assert!(report.status.success(), "{}", stderr(&report));
    let json: serde_json::Value = serde_json::from_str(&stdout(&report)).unwrap();
    assert_eq!(json["dreams"]["without_edits"], 1, "{json}");
    assert_eq!(json["dreams"]["with_edits"], 0, "{json}");
}

#[test]
fn schedules_need_a_trusted_mezha_and_warn_about_shell_only_keys() {
    let s = setup();
    s.nightly();
    // No mezha on PATH where agents can't write: nothing to schedule. One
    // under TMPDIR is as good as none, and the note says so.
    let distrusted = s.p.tmp.join("bin");
    write(&distrusted.join("mezha"), "#!/bin/sh\nexit 0\n");
    fs::set_permissions(distrusted.join("mezha"), fs::Permissions::from_mode(0o755)).unwrap();
    let path = format!("{}:{}:/usr/bin:/bin", distrusted.display(), s.bin.display());
    let out = s.p.mezha_env(
        &["dream", "--schedule", "launchd"],
        &[("PATH", path.as_str()), ("FAKE_MODE", "write")],
    );
    assert_eq!(out.status.code(), Some(1), "{}", stdout(&out));
    let e = stderr(&out);
    assert!(
        e.contains("no mezha on PATH outside directories agents can write (ignored `mezha` at"),
        "{e}"
    );
    assert!(
        e.contains("cargo install --locked --force --path crates/mezha-cli"),
        "{e}"
    );

    // Another mezha first on PATH: the note says which one the schedule runs.
    write(&s.bin.join("mezha"), "#!/bin/sh\nexit 0\n");
    fs::set_permissions(s.bin.join("mezha"), fs::Permissions::from_mode(0o755)).unwrap();
    s.p.write_spec(&format!(
        "{SPEC}\n[memory]\ndream_schedule = \"cron\"\ndream_cron = \"15 3 * * *\"\n"
    ));
    let config = s.p.home.join(".claude");
    let out = s.cmd(
        &["dream", "--schedule", "cron"],
        "write",
        &[
            ("CLAUDE_CONFIG_DIR", config.to_str().unwrap()),
            ("ANTHROPIC_API_KEY", "sk-ant-test"),
            ("CLAUDE_CODE_USE_BEDROCK", "1"),
        ],
    );
    let (o, e) = (stdout(&out), stderr(&out));
    assert!(out.status.success(), "{o}\n{e}");
    assert!(
        e.contains(&format!(
            "note: the schedule runs {}, not the mezha you ran now",
            s.bin.join("mezha").display()
        )),
        "{e}"
    );
    assert!(
        e.contains("warning: set only in your shell, not in ~/.claude/settings.json: ANTHROPIC_API_KEY, CLAUDE_CODE_USE_BEDROCK."),
        "{e}"
    );
    assert!(o.contains("15 3 * * * env PATH="), "{o}");
    assert!(
        o.contains(&format!("CLAUDE_CONFIG_DIR={}", config.display())),
        "{o}"
    );
    assert!(!o.contains("sk-ant-test"), "a key in the snippet: {o}");
}

#[test]
fn a_git_where_agents_could_put_one_is_skipped_with_a_note() {
    let s = setup();
    let distrusted = s.p.tmp.join("bin");
    write(&distrusted.join("git"), "#!/bin/sh\nexit 0\n");
    fs::set_permissions(distrusted.join("git"), fs::Permissions::from_mode(0o755)).unwrap();
    let path = format!("{}:{}:/usr/bin:/bin", distrusted.display(), s.bin.display());
    let out = s.p.mezha_env(
        &["dream", "--dry-run", "--role", "implementer"],
        &[("PATH", path.as_str()), ("FAKE_MODE", "write")],
    );
    let (o, e) = (stdout(&out), stderr(&out));
    assert!(out.status.success(), "{o}\n{e}");
    assert!(
        e.contains(&format!(
            "note: ignored `git` at {} (",
            distrusted.join("git").display()
        )),
        "{e}"
    );
    assert!(o.contains("Dry run: no dreamer ran"), "{o}");
}

#[test]
fn too_many_branches_of_one_name_is_an_error() {
    let s = setup();
    let head = git_ok(&s.p.root, &s.p.home, &["rev-parse", "HEAD"]);
    let start = now();
    let mut refs = String::new();
    for t in start..start + 5 {
        let stamp = mezha_render::utc_stamp(t);
        refs.push_str(&format!(
            "create refs/heads/mezha/dream-{stamp} {}\n",
            head.trim()
        ));
        for n in 2..100 {
            refs.push_str(&format!(
                "create refs/heads/mezha/dream-{stamp}-{n} {}\n",
                head.trim()
            ));
        }
    }
    let mut child = Command::new("git")
        .args(["update-ref", "--stdin"])
        .current_dir(&s.p.root)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", &s.p.home)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    std::io::Write::write_all(&mut child.stdin.take().unwrap(), refs.as_bytes()).unwrap();
    let created = child.wait_with_output().unwrap();
    assert!(created.status.success(), "{}", stderr(&created));
    let out = s.dream("write", &["--role", "implementer"]);
    assert_eq!(out.status.code(), Some(1), "{}", stdout(&out));
    assert!(
        stderr(&out).contains("too many branches named mezha/dream-"),
        "{}",
        stderr(&out)
    );
    assert_eq!(s.branches().len(), 5 * 99, "nothing was added");
}

#[test]
fn transcripts_too_large_to_read_are_counted_not_read() {
    let s = setup();
    let dir =
        s.p.home
            .join(".claude/projects")
            .join(project_dir_name(&s.p.root.to_string_lossy()));
    // A sparse file beyond the limit: nothing is read from it.
    let big = fs::File::create(dir.join("s-big.jsonl")).unwrap();
    big.set_len(65 << 20).unwrap();
    let out = s.dream("write", &["--dry-run", "--role", "implementer"]);
    let (o, e) = (stdout(&out), stderr(&out));
    assert!(out.status.success(), "{o}\n{e}");
    assert!(
        e.contains("note: 1 transcript(s) were too large to read"),
        "{e}"
    );
    assert!(o.contains("implementer    project  1 run(s)"), "{o}");
}

#[test]
fn runs_that_do_not_fit_one_dream_wait_for_the_next() {
    let s = setup();
    // Sixteen runs with ~12 KB digests each: more than one inbox holds.
    let pad = " lorem ipsum dolor sit amet".repeat(230);
    for n in 0..16 {
        transcript_padded(
            &s.p,
            &s.p.root,
            "implementer",
            &format!("p{n}"),
            n * 10,
            &pad,
        );
    }
    let out = s.dream("write", &["--dry-run", "--role", "implementer"]);
    let (o, e) = (stdout(&out), stderr(&out));
    assert!(out.status.success(), "{o}\n{e}");
    let line = o
        .lines()
        .find(|l| l.contains("left for the next dream"))
        .unwrap_or_else(|| panic!("{o}"));
    assert!(line.starts_with("  implementer    project  "), "{line}");
    let ws = s.workspaces().pop().unwrap();
    let digests = fs::read_dir(ws.join("inbox/implementer")).unwrap().count();
    assert!(digests < 17 && digests > 1, "{digests} digests");
}
