//! Sessions from fixture transcripts: a session that ran three implementer
//! subagents, a continued session that copied its records and cost, a
//! session still running, and a sibling project that isn't ours.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use mezha_memory::time::format_iso;
use mezha_memory::transcripts::{project_dir_name, project_sources};
use mezha_metrics::sessions::{SessionRow, extract};
use serde_json::{Value, json};

fn sessions() -> Vec<SessionRow> {
    let projects = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/projects");
    let sources = project_sources(&projects, &[PathBuf::from("/Users/test/proj")], None);
    let roles = BTreeSet::from(["implementer".to_string()]);
    sources
        .files
        .iter()
        .filter_map(|f| extract(f, &sources.roots, &roles))
        .collect()
}

#[test]
fn reads_the_projects_sessions() {
    let all = sessions();
    let ids: Vec<&str> = all.iter().map(|s| s.id.as_str()).collect();
    assert_eq!(ids, ["s1", "s2", "s3"]);

    let s1 = &all[0];
    // The /clear command isn't a prompt you typed.
    assert_eq!(s1.prompts, 2);
    assert_eq!(s1.followups(), 1);
    assert_eq!(s1.cost_usd, Some(1.2));
    let runs: Vec<&str> = s1.runs.iter().map(|r| r.id.as_str()).collect();
    assert_eq!(
        runs,
        ["r1", "r2", "r3"],
        "the built-in Explore run is left out"
    );
    // r1 and r2 ran in parallel; r3 came after your second prompt.
    assert_eq!(s1.reruns.get("implementer"), Some(&1));
    // The last record of a message carries its real output count.
    assert_eq!((s1.runs[0].tokens_in, s1.runs[0].tokens_out), (150, 300));
    assert_eq!(s1.runs[1].failures, 1);
    assert!(s1.runs[1].lessons);
    assert_eq!(s1.runs[2].unresolved, 2);

    // A continued session: its own records only, and only what it added
    // to the cost it inherited.
    let s2 = &all[1];
    assert_eq!(s2.prompts, 1);
    let cost = s2.cost_usd.unwrap();
    assert!((cost - 0.3).abs() < 1e-9, "{cost}");
    assert_eq!(s2.start, s2.end);

    // Still running: no cost yet, and no guess.
    assert_eq!(all[2].cost_usd, None);
}

fn at(n: i64) -> String {
    format_iso(1_800_000_000 + n)
}

fn write(path: &Path, lines: &[Value]) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    let text: String = lines.iter().map(|l| format!("{l}\n")).collect();
    fs::write(path, text).unwrap();
}

#[test]
fn subagents_without_times_or_that_cannot_be_read_are_left_out() {
    let tmp = tempfile::tempdir().unwrap();
    let base = fs::canonicalize(tmp.path()).unwrap();
    let root = base.join("proj");
    fs::create_dir_all(&root).unwrap();
    let cwd = root.to_string_lossy().into_owned();
    let dir = base.join("projects").join(project_dir_name(&cwd));
    let file = dir.join("s9.jsonl");
    write(
        &file,
        &[
            json!({"type": "user", "uuid": "u1", "sessionId": "s9", "cwd": cwd, "timestamp": at(0),
                   "message": {"role": "user", "content": "Fix it"}}),
            json!({"type": "assistant", "uuid": "a1", "sessionId": "s9", "timestamp": at(1),
                   "message": {"id": "m1", "role": "assistant", "content": [{"type": "text", "text": "Done."}],
                               "usage": {"input_tokens": 1, "output_tokens": 1}}}),
        ],
    );
    let subagents = dir.join("s9/subagents");
    let agent = |name: &str, lines: &[Value]| -> PathBuf {
        let path = subagents.join(format!("agent-{name}.jsonl"));
        write(&path, lines);
        write(
            &subagents.join(format!("agent-{name}.meta.json")),
            &[json!({"agentType": "implementer"})],
        );
        path
    };
    let run = [
        json!({"type": "user", "uuid": "y1", "timestamp": at(2),
               "message": {"role": "user", "content": "Add a test"}}),
        json!({"type": "assistant", "uuid": "y2", "timestamp": at(3),
               "message": {"id": "m2", "role": "assistant",
                           "content": [{"type": "text", "text": "Done.\n\n## Unresolved\n- one"}],
                           "usage": {"input_tokens": 10, "output_tokens": 5}}}),
    ];
    agent("ok", &run);
    agent(
        "untimed",
        &[json!({"type": "user", "uuid": "x1", "message": {"role": "user", "content": "x"}})],
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let locked = agent("locked", &run);
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o000)).unwrap();
    }

    let roles = BTreeSet::from(["implementer".to_string()]);
    // Roots with forward slashes, as `project_sources` gives them.
    let roots = [cwd.replace('\\', "/")];
    let row = extract(&file, &roots, &roles).unwrap();
    let runs: Vec<(&str, u64, u64, u32)> = row
        .runs
        .iter()
        .map(|r| (r.id.as_str(), r.tokens_in, r.tokens_out, r.unresolved))
        .collect();
    assert_eq!(runs, [("ok", 10, 5, 1)]);
    assert_eq!((row.prompts, row.cost_usd), (1, None));
    assert_eq!(extract(&file, &["/elsewhere".to_string()], &roles), None);
}
