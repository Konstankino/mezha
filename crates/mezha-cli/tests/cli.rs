//! The CLI as a user drives it: init, compile, diff, apply, approve.

mod common;

use std::fs;

use common::{Project, stderr, stdout};

const SPEC: &str = r#"
[project]
name = "cli"

[policy]
permissions_ask = ["git push"]
"#;

#[test]
fn version_names_the_hook_protocol() {
    let out = Project::new().mezha(&["--version"]);
    assert!(out.status.success());
    assert!(
        stdout(&out).contains(&format!("hook protocol {}", mezha_hooks::PROTOCOL)),
        "{}",
        stdout(&out)
    );
}

#[test]
fn init_writes_a_spec_that_compiles_and_refuses_to_overwrite() {
    let p = Project::new();
    let out = p.mezha(&["init"]);
    assert!(out.status.success(), "{}", stderr(&out));
    let spec = p.read("mezha.toml");
    assert!(spec.contains("name = \"repo\""), "{spec}");
    assert!(spec.contains("permissions_ask = [\"git push\"]"));

    let again = p.mezha(&["init"]);
    assert!(!again.status.success());
    assert!(stderr(&again).contains("already exists"));
    assert_eq!(p.read("mezha.toml"), spec);

    if cfg!(not(windows)) {
        let out = p.mezha(&["compile"]);
        assert!(out.status.success(), "{}", stderr(&out));
    }
}

#[test]
fn an_invalid_spec_writes_nothing() {
    let p = Project::new();
    p.write_spec(
        r#"
[project]
name = "bad"

[agent.researcher]
rule_of_two = ["untrusted_input", "private_data", "external_action"]
"#,
    );
    let out = p.mezha(&["compile"]);
    assert_eq!(out.status.code(), Some(1));
    let err = stderr(&out);
    assert!(err.contains("error: agent.researcher.rule_of_two"), "{err}");
    assert!(err.contains("warning: policy.permissions_ask"), "{err}");
    assert!(err.contains("nothing was written"), "{err}");
    assert!(!p.root.join(".claude").exists());
}

#[test]
fn a_spec_that_does_not_parse_is_an_error() {
    let p = Project::new();
    p.write_spec("[project]\nname = \"x\"\nsurprise = 1\n");
    let out = p.mezha(&["compile"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(stderr(&out).contains("surprise"), "{}", stderr(&out));
}

#[test]
fn compile_is_idempotent() {
    let p = Project::new();
    p.write_spec(SPEC);
    let first = p.mezha(&["compile"]);
    assert!(first.status.success(), "{}", stderr(&first));
    assert!(stdout(&first).contains("create     .claude/settings.json"));
    let second = p.mezha(&["compile"]);
    assert!(second.status.success());
    assert!(
        stdout(&second).contains("up to date"),
        "{}",
        stdout(&second)
    );
}

#[test]
fn hand_edits_stop_compile_show_in_diff_and_apply_backs_them_up() {
    let p = Project::new();
    p.write_spec(SPEC);
    assert!(p.mezha(&["compile"]).status.success());
    let generated = p.read(".claude/settings.json");
    fs::write(p.root.join(".claude/settings.json"), "{ \"hand\": true }\n").unwrap();
    // The spec changes too, so the file needs rewriting.
    p.write_spec(&SPEC.replace("\"git push\"", "\"git push\", \"npm publish\""));

    let out = p.mezha(&["compile"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(stdout(&out).contains("CONFLICT"), "{}", stdout(&out));
    assert_eq!(p.read(".claude/settings.json"), "{ \"hand\": true }\n");

    let diff = p.mezha(&["diff"]);
    assert!(diff.status.success());
    assert!(
        stdout(&diff).contains("-{ \"hand\": true }"),
        "{}",
        stdout(&diff)
    );
    assert!(
        stdout(&diff).contains("+  \"permissions\""),
        "{}",
        stdout(&diff)
    );

    let no_tty = p.mezha(&["apply"]);
    assert!(
        !no_tty.status.success(),
        "apply without a terminal needs --yes"
    );
    assert_eq!(p.read(".claude/settings.json"), "{ \"hand\": true }\n");

    let out = p.mezha(&["apply", "--yes"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(stdout(&out).contains("Backed up"), "{}", stdout(&out));
    assert_ne!(p.read(".claude/settings.json"), generated);
    assert!(p.read(".claude/settings.json").contains("npm publish"));
    let backups: Vec<_> = fs::read_dir(p.root.join(".mezha-backup"))
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.path().is_dir())
        .collect();
    assert_eq!(backups.len(), 1);
    assert_eq!(
        fs::read_to_string(backups[0].path().join(".claude/settings.json")).unwrap(),
        "{ \"hand\": true }\n"
    );
}

#[test]
fn a_hand_written_settings_file_is_not_overwritten() {
    let p = Project::new();
    p.write_spec(SPEC);
    fs::create_dir_all(p.root.join(".claude")).unwrap();
    fs::write(p.root.join(".claude/settings.json"), "{}\n").unwrap();
    let out = p.mezha(&["compile"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        stdout(&out).contains("not written by mezha"),
        "{}",
        stdout(&out)
    );
    assert_eq!(p.read(".claude/settings.json"), "{}\n");
}

#[test]
fn native_windows_is_refused_for_now() {
    let p = Project::new();
    p.write_spec("[project]\nname = \"w\"\nos_mode = \"native-windows\"\n[policy]\npermissions_ask = [\"git push\"]\n");
    let out = p.mezha(&["compile"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(stderr(&out).contains("phase 4"), "{}", stderr(&out));
    assert!(!p.root.join(".claude").exists());
}

#[test]
fn approve_refuses_without_a_terminal_or_inside_claude_code() {
    let p = Project::new();
    let out = p.mezha(&["approve", "--minutes", "5"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        stderr(&out).contains("interactive terminal"),
        "{}",
        stderr(&out)
    );

    let out = p.mezha_env(&["approve"], &[("CLAUDECODE", "1")]);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        stderr(&out).contains("inside Claude Code"),
        "{}",
        stderr(&out)
    );
    assert!(!mezha_broker::approvals::store_dir(&p.home).exists());

    let out = p.mezha_env(&["approve", "--revoke"], &[("CLAUDECODE", "1")]);
    assert_eq!(out.status.code(), Some(1));
}

#[test]
fn approve_status_works_anywhere() {
    let p = Project::new();
    let out = p.mezha_env(&["approve", "--status"], &[("CLAUDECODE", "1")]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(stdout(&out).contains("No active approval"));

    let root = mezha_broker::repo_root(&p.root);
    mezha_broker::approvals::grant(&p.home, &root, 10, common::now()).unwrap();
    let out = p.mezha(&["approve", "--status"]);
    assert!(
        stdout(&out).contains("10 more minute(s)"),
        "{}",
        stdout(&out)
    );
}

#[test]
fn approve_minutes_are_bounded() {
    let p = Project::new();
    for bad in ["0", "1441"] {
        let out = p.mezha(&["approve", "--minutes", bad]);
        assert!(!out.status.success(), "{bad}");
    }
    let out = p.mezha(&["approve", "--status", "--revoke"]);
    assert!(!out.status.success());
}
