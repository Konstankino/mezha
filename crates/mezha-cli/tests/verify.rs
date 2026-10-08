//! `mezha verify` as a binary: its exit codes (0 pass, 1 a check failed,
//! 2 couldn't run) and the JSON report's shape.

mod common;

use std::fs;
use std::process::Command;

use common::{Project, stderr, stdout};
use serde_json::Value;

const SPEC: &str = r#"
[project]
name = "verify"

[policy]
egress_allow = []
permissions_ask = ["git push"]
"#;

fn compiled() -> Project {
    let p = Project::new();
    let git = Command::new("git")
        .args(["init", "-q"])
        .current_dir(&p.root)
        .output()
        .unwrap();
    assert!(git.status.success());
    p.write_spec(SPEC);
    let out = p.mezha(&["compile"]);
    assert!(out.status.success(), "{}", stderr(&out));
    p
}

#[test]
fn without_a_spec_verify_cannot_run() {
    let p = Project::new();
    let out = p.mezha(&["verify"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(stderr(&out).contains("mezha init"), "{}", stderr(&out));
}

#[test]
fn an_invalid_spec_cannot_run_either() {
    let p = Project::new();
    p.write_spec("[project]\nname = \"x\"\n[agent.a]\ntools = []\n");
    let out = p.mezha(&["verify"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(stderr(&out).contains("rule_of_two"), "{}", stderr(&out));
}

#[test]
fn a_clean_project_passes_with_project_only() {
    let p = compiled();
    let out = p.mezha(&["verify", "--project-only"]);
    assert_eq!(out.status.code(), Some(0), "{}", stdout(&out));
    let text = stdout(&out);
    assert!(text.contains("PASS  push-boundary"), "{text}");
    assert!(text.contains("0 failed"), "{text}");
}

#[test]
fn a_hand_edited_settings_file_fails() {
    let p = compiled();
    let path = p.root.join(".claude/settings.json");
    let edited = fs::read_to_string(&path)
        .unwrap()
        .replace("|| exit 2", "|| exit 0");
    fs::write(&path, edited).unwrap();
    let out = p.mezha(&["verify", "--project-only"]);
    assert_eq!(out.status.code(), Some(1), "{}", stdout(&out));
    assert!(
        stdout(&out).contains("FAIL  settings-intact"),
        "{}",
        stdout(&out)
    );
}

#[test]
fn json_report_has_a_stable_shape() {
    let p = compiled();
    let out = p.mezha(&["verify", "--json", "--project-only"]);
    assert_eq!(out.status.code(), Some(0));
    let report: Value = serde_json::from_str(&stdout(&out)).unwrap();
    assert_eq!(report["version"], 1);
    assert_eq!(report["mode"], "project-only");
    assert_eq!(report["hook_protocol"], mezha_hooks::PROTOCOL);
    let ids: Vec<&str> = report["checks"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["id"].as_str().unwrap())
        .collect();
    assert_eq!(
        ids,
        [
            "sandbox",
            "push-boundary",
            "settings-intact",
            "settings-layers",
            "git-hygiene",
            "branch-protection",
            "dreamer",
            "plugin-validate"
        ]
    );
    for check in report["checks"].as_array().unwrap() {
        assert!(["pass", "warn", "fail", "skip"].contains(&check["status"].as_str().unwrap()));
        assert!(
            ["boundary", "integrity", "advisory", "hygiene"]
                .contains(&check["kind"].as_str().unwrap())
        );
    }
    assert_eq!(report["summary"]["fail"], 0);
}
