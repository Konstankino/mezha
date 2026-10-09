//! Sessions from fixture transcripts: a session that ran three implementer
//! subagents, a continued session that copied its records and cost, a
//! session still running, and a sibling project that isn't ours.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use mezha_memory::transcripts::project_sources;
use mezha_metrics::sessions::{SessionRow, extract};

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
