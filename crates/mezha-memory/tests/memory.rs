//! The inbox from fixture transcripts: which runs a project owns, what a
//! digest keeps, and what it redacts. `MEZHA_BLESS=1` rewrites the golden
//! digests.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use mezha_memory::inbox::{self, role_inbox};
use mezha_memory::time::parse_iso;
use mezha_memory::transcripts::{RunKind, collect};

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
