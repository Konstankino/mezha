//! The inbox from fixture transcripts: which runs a project owns, what a
//! digest keeps, and what it redacts. `MEZHA_BLESS=1` rewrites the golden
//! digests.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use mezha_memory::inbox::{self, role_inbox};
use mezha_memory::time::{format_iso, parse_iso};
use mezha_memory::transcripts::{Collected, RunKind, collect, project_dir_name};
use serde_json::{Value, json};

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

fn roles(names: &[&str]) -> BTreeSet<String> {
    names.iter().map(|s| s.to_string()).collect()
}

fn root() -> Vec<PathBuf> {
    vec![PathBuf::from("/Users/test/proj")]
}

#[test]
fn collects_the_projects_runs() {
    let got = collect(
        &fixtures().join("projects"),
        &root(),
        &roles(&["implementer", "explorer"]),
        0,
        None,
    );
    let ids: Vec<(&str, &str, RunKind)> = got
        .runs
        .iter()
        .map(|r| (r.role.as_str(), r.id.as_str(), r.kind))
        .collect();
    // Oldest first; the sibling project and the built-in Explore agent are
    // left out; the worktree's run is in.
    assert_eq!(
        ids,
        [
            ("implementer", "a1", RunKind::Subagent),
            ("explorer", "b2", RunKind::Subagent),
            ("implementer", "s2", RunKind::Session),
            ("implementer", "d4", RunKind::Subagent),
        ]
    );
    assert_eq!(got.sessions, 3);
    assert_eq!(got.skipped_lines, 1);

    let a1 = &got.runs[0];
    assert_eq!(a1.task, "Fix the failing test in crates/x");
    assert_eq!(a1.session, "s1");
    assert_eq!(a1.branch.as_deref(), Some("main"));
    assert!(
        a1.final_text.starts_with("Fixed it.\n## Lessons"),
        "{}",
        a1.final_text
    );
    assert_eq!(a1.failures.len(), 2);
    assert_eq!(a1.failures[0].tool, "Bash");
    assert_eq!(a1.failures[0].input, "cargo test -p x");
    assert_eq!(a1.failures[1].tool, "Edit");
    assert_eq!(
        a1.followups,
        ["No, use cargo nextest. Mail bob@example.com if stuck."]
    );
    // A background run: your next message after its task notification.
    assert_eq!(got.runs[1].followups, ["thanks, now fix it"]);
    // A session started as the agent: its first prompt is the task.
    let s2 = &got.runs[2];
    assert_eq!(s2.task, "Refactor the parser");
    assert_eq!(s2.followups, ["Also add tests"]);
    assert_eq!(s2.final_text, "Added tests.");
}

#[test]
fn since_and_roles_filter() {
    let since = parse_iso("2026-10-08T11:00:00Z").unwrap();
    let got = collect(
        &fixtures().join("projects"),
        &root(),
        &roles(&["implementer"]),
        since,
        None,
    );
    let ids: Vec<&str> = got.runs.iter().map(|r| r.id.as_str()).collect();
    assert_eq!(ids, ["s2", "d4"]);
    let none = collect(
        &fixtures().join("projects"),
        &[PathBuf::from("/elsewhere")],
        &roles(&["implementer"]),
        0,
        None,
    );
    assert!(none.runs.is_empty());
}

#[test]
fn golden_inbox() {
    let got = collect(
        &fixtures().join("projects"),
        &root(),
        &roles(&["implementer"]),
        0,
        None,
    );
    let runs: Vec<_> = got.runs.iter().collect();
    let inbox = role_inbox(&runs, true);
    assert_eq!(inbox.left, 0);
    let golden = fixtures().join("inbox-implementer");
    let bless = std::env::var_os("MEZHA_BLESS").is_some();
    if bless {
        let _ = std::fs::remove_dir_all(&golden);
        std::fs::create_dir_all(&golden).unwrap();
    }
    let mut names = Vec::new();
    for d in &inbox.digests {
        let path = golden.join(&d.file);
        names.push(d.file.clone());
        if bless {
            std::fs::write(&path, &d.text).unwrap();
        }
        let want = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("{}: {e} (run with MEZHA_BLESS=1)", path.display()));
        assert_eq!(d.text, want, "{}", d.file);
    }
    let mut on_disk: Vec<String> = std::fs::read_dir(&golden)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    on_disk.sort();
    names.sort();
    assert_eq!(on_disk, names);

    let a1 = &inbox.digests[0].text;
    // Secrets, hard markers and (with PHI) addresses are redacted; the
    // instruction-like phrase stays as evidence, inside a fence.
    assert!(a1.contains("[mezha: redacted GitHub token]"), "{a1}");
    assert!(a1.contains("[mezha: redacted chat-template token]"), "{a1}");
    assert!(a1.contains("[mezha: redacted bidi control]"), "{a1}");
    assert!(a1.contains("[mezha: redacted email address]"), "{a1}");
    assert!(a1.contains("ignore previous instructions"), "{a1}");
    assert!(!a1.contains("ghp_0123"), "{a1}");
    assert!(a1.contains("## Lessons (from the final message)"), "{a1}");
    assert_eq!(inbox.through(), parse_iso("2026-10-08T12:04:00Z"));
}

#[test]
fn the_role_cap_keeps_the_oldest() {
    let got = collect(
        &fixtures().join("projects"),
        &root(),
        &roles(&["implementer"]),
        0,
        None,
    );
    let mut runs = got.runs.clone();
    for run in &mut runs {
        run.final_text = "x".repeat(inbox::MAX_FINAL);
        run.task = "y".repeat(inbox::MAX_TASK);
    }
    let many: Vec<_> = runs.iter().cycle().take(40).collect();
    let capped = role_inbox(&many, false);
    assert!(capped.left > 0);
    assert_eq!(capped.digests.len() + capped.left, 40);
    let total: usize = capped.digests.iter().map(|d| d.text.len()).sum();
    assert!(total <= inbox::MAX_ROLE);
}

/// A project of its own, with a `projects` directory written by the test.
struct Project {
    _tmp: tempfile::TempDir,
    projects: PathBuf,
    root: PathBuf,
    /// The project's directory under `projects`.
    dir: PathBuf,
}

impl Project {
    fn new() -> Project {
        let tmp = tempfile::tempdir().unwrap();
        let base = fs::canonicalize(tmp.path()).unwrap();
        let root = base.join("proj");
        fs::create_dir_all(&root).unwrap();
        let projects = base.join("projects");
        let dir = projects.join(project_dir_name(&root.to_string_lossy()));
        fs::create_dir_all(&dir).unwrap();
        Project {
            _tmp: tmp,
            projects,
            root,
            dir,
        }
    }

    /// `record` as the session's own, run in the project.
    fn here(&self, mut record: Value) -> Value {
        record["cwd"] = Value::String(self.root.to_string_lossy().into_owned());
        record
    }

    fn write_text(&self, rel: &str, text: &str) -> PathBuf {
        let path = self.dir.join(rel);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, text).unwrap();
        path
    }

    /// Writes `lines` as JSON Lines at `rel` under the project directory.
    fn write(&self, rel: &str, lines: &[Value]) -> PathBuf {
        let text: String = lines.iter().map(|l| format!("{l}\n")).collect();
        self.write_text(rel, &text)
    }

    fn meta(&self, rel: &str, role: &str) {
        self.write(rel, &[json!({"agentType": role})]);
    }

    fn collect(&self, since: i64) -> Collected {
        collect(
            &self.projects,
            std::slice::from_ref(&self.root),
            &roles(&["implementer"]),
            since,
            None,
        )
    }
}

fn at(n: i64) -> String {
    format_iso(1_800_000_000 + n)
}

fn user(n: i64, text: &str) -> Value {
    json!({"type": "user", "uuid": format!("u{n}"), "timestamp": at(n),
           "message": {"role": "user", "content": text}})
}

fn assistant(n: i64, content: Value) -> Value {
    json!({"type": "assistant", "uuid": format!("a{n}"), "timestamp": at(n),
           "message": {"id": format!("m{n}"), "role": "assistant", "content": content}})
}

fn said(n: i64, text: &str) -> Value {
    assistant(n, json!([{"type": "text", "text": text}]))
}

fn tool_result(n: i64, call: &str, output: &str, error: bool) -> Value {
    json!({"type": "user", "uuid": format!("r{n}"), "timestamp": at(n),
           "message": {"role": "user", "content": [
               {"type": "tool_result", "tool_use_id": call, "content": output, "is_error": error}]}})
}

#[test]
fn transcripts_older_than_since_are_not_read() {
    let p = Project::new();
    p.write("s1.jsonl", &[p.here(user(0, "Fix it")), said(1, "Done.")]);
    let got = p.collect(i64::MAX / 2);
    assert_eq!((got.sessions, got.runs.len()), (0, 0));
    let got = p.collect(0);
    assert_eq!((got.sessions, got.runs.len()), (1, 0));
}

#[test]
fn records_with_nothing_to_learn_from_make_no_run() {
    let p = Project::new();
    // A session started as the agent in which nothing was said, with a
    // prompt that has no message, and blank lines between the records.
    let setting = json!({"type": "agent-setting", "agentSetting": "implementer",
                         "uuid": "g1", "timestamp": at(0)});
    let bare = json!({"type": "user", "uuid": "u1", "timestamp": at(1)});
    p.write_text("s1.jsonl", &format!("{}\n\n   \n{bare}\n", p.here(setting)));
    // A subagent that never said anything either.
    p.write(
        "s1/subagents/agent-z1.jsonl",
        &[json!({"type": "progress", "uuid": "p1", "timestamp": at(2)})],
    );
    p.meta("s1/subagents/agent-z1.meta.json", "implementer");
    // Three directories down is found; four down is not.
    let deep = [user(3, "Do the thing"), said(4, "Done.")];
    p.write("s1/subagents/a/b/c/agent-deep.jsonl", &deep);
    p.meta("s1/subagents/a/b/c/agent-deep.meta.json", "implementer");
    p.write("s1/subagents/a/b/c/d/agent-deeper.jsonl", &deep);
    p.meta("s1/subagents/a/b/c/d/agent-deeper.meta.json", "implementer");

    let got = p.collect(0);
    assert_eq!((got.sessions, got.skipped_lines), (1, 0));
    let ids: Vec<(&str, RunKind)> = got.runs.iter().map(|r| (r.id.as_str(), r.kind)).collect();
    assert_eq!(ids, [("deep", RunKind::Subagent)]);
    assert_eq!(got.runs[0].task, "Do the thing");
    assert_eq!(got.runs[0].final_text, "Done.");
}

#[test]
fn failed_calls_show_a_short_input_and_tool_results_are_not_prompts() {
    let p = Project::new();
    p.write(
        "s2.jsonl",
        &[
            p.here(user(0, "Fix it")),
            assistant(
                1,
                json!([{"type": "tool_use", "id": "t1", "name": "Agent", "input": {"prompt": "fix"}}]),
            ),
            json!({"type": "user", "uuid": "r5", "timestamp": at(5),
                   "message": {"role": "user", "content": [
                       {"type": "tool_result", "tool_use_id": "t1", "content": "done"}]},
                   "toolUseResult": {"agentId": "x1", "status": "completed"}}),
            // A tool result without `toolUseResult` isn't your prompt either.
            tool_result(6, "t2", "ok", false),
            user(7, "Now the tests"),
        ],
    );
    let long = "x".repeat(250);
    p.write(
        "s2/subagents/agent-x1.jsonl",
        &[
            user(2, "Run the long command"),
            assistant(
                3,
                json!([{"type": "tool_use", "id": "c1", "name": "Bash", "input": {"command": long}}]),
            ),
            tool_result(3, "c1", "boom", true),
            assistant(
                4,
                json!([{"type": "tool_use", "id": "c2", "name": "Read", "input": {"file_path": "/a"}}]),
            ),
            tool_result(4, "c2", "fine", false),
            said(5, "Done."),
        ],
    );
    p.meta("s2/subagents/agent-x1.meta.json", "implementer");

    let got = p.collect(0);
    assert_eq!(got.runs.len(), 1, "{:?}", got.runs);
    let run = &got.runs[0];
    assert_eq!(run.failures.len(), 1, "{:?}", run.failures);
    assert_eq!(run.failures[0].tool, "Bash");
    assert_eq!(run.failures[0].input, format!("{}…", "x".repeat(200)));
    assert_eq!(run.failures[0].output, "boom");
    assert_eq!(run.followups, ["Now the tests"]);
    assert_eq!(run.final_text, "Done.");
}

#[cfg(unix)]
#[test]
fn unreadable_and_oversized_transcripts_are_skipped() {
    use mezha_memory::transcripts::{Unread, read_transcript};
    use std::os::unix::fs::PermissionsExt;
    let closed = |path: &Path| {
        fs::set_permissions(path, fs::Permissions::from_mode(0o000)).unwrap();
    };
    let huge = |path: &Path| {
        // A sparse file past the limit: never read.
        fs::OpenOptions::new()
            .write(true)
            .open(path)
            .unwrap()
            .set_len((64 << 20) + 1)
            .unwrap();
    };
    let p = Project::new();
    let session = [p.here(user(0, "Fix it")), said(1, "Done.")];
    closed(&p.write("s3.jsonl", &session));
    let big = p.write("s4.jsonl", &session);
    huge(&big);
    p.write("s5.jsonl", &session);
    let run = [user(2, "Do it"), said(3, "Done.")];
    huge(&p.write("s5/subagents/agent-big.jsonl", &run));
    p.meta("s5/subagents/agent-big.meta.json", "implementer");
    closed(&p.write("s5/subagents/agent-locked.jsonl", &run));
    p.meta("s5/subagents/agent-locked.meta.json", "implementer");

    let got = p.collect(0);
    assert_eq!((got.sessions, got.skipped_files), (1, 2));
    assert!(got.runs.is_empty(), "{:?}", got.runs);
    let unread = |path: &Path| read_transcript(path).err();
    assert_eq!(unread(&big), Some(Unread::TooLarge));
    // A directory opens but can't be read; a missing file doesn't open.
    assert_eq!(unread(&p.dir), Some(Unread::Unreadable));
    assert_eq!(
        unread(&p.dir.join("missing.jsonl")),
        Some(Unread::Unreadable)
    );
}
