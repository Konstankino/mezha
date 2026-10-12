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
tools = ["Read", "WebFetch"]
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

/// Every command that reads the spec stops on its errors before it does
/// anything else, including the ones that would run claude.
#[test]
fn every_command_stops_on_an_invalid_spec() {
    let p = Project::new();
    p.write_spec("[project]\nname = \"bad\"\n\n[agent.a]\ntools = []\n");
    for args in [
        vec!["diff"],
        vec!["metrics"],
        vec!["metrics", "--ab", "tasks.toml", "--yes"],
        vec!["dream"],
        vec!["dream", "--schedule", "launchd"],
        vec!["skill", "eval", "x", "--yes"],
    ] {
        let out = p.mezha(&args);
        assert_eq!(out.status.code(), Some(1), "{args:?}: {}", stdout(&out));
        let err = stderr(&out);
        assert!(
            err.contains("error: agent.a.rule_of_two"),
            "{args:?}: {err}"
        );
        assert!(
            err.contains("has errors; nothing was written"),
            "{args:?}: {err}"
        );
    }
    assert!(!p.root.join(".claude").exists());
}

#[test]
fn render_warnings_are_printed_and_render_problems_stop_compile() {
    let p = Project::new();
    p.write_spec(&format!(
        "{SPEC}\n[skill.notes]\npreset = \"knowledge\"\ndescription = \"The project's notes and naming conventions. Use when naming things.\"\n"
    ));
    fs::create_dir_all(p.root.join("mezha/skills")).unwrap();
    fs::write(p.root.join("mezha/skills/notes.md"), "\n").unwrap();
    let out = p.mezha(&["compile"]);
    assert!(out.status.success(), "{}", stderr(&out));
    let err = stderr(&out);
    assert!(
        err.contains("warning: ") && err.contains("notes.md is empty"),
        "{err}"
    );
    assert!(p.root.join(".claude/skills/notes/SKILL.md").is_file());

    // A body that brings its own frontmatter can't be rendered.
    fs::write(
        p.root.join("mezha/skills/notes.md"),
        "---\nname: notes\n---\nNotes.\n",
    )
    .unwrap();
    let out = p.mezha(&["compile"]);
    assert_eq!(out.status.code(), Some(1), "{}", stdout(&out));
    let err = stderr(&out);
    assert!(
        err.contains("error: .claude/skills/notes/SKILL.md:") && err.contains("starts with `---`"),
        "{err}"
    );
    assert!(err.contains("nothing was written."), "{err}");
}

#[test]
fn notes_about_the_state_file_are_printed() {
    let p = Project::new();
    p.write_spec(SPEC);
    assert!(p.mezha(&["compile"]).status.success());
    let state = p.root.join(".claude/.mezha-state.json");
    // A path mezha doesn't generate is ignored, whoever put it there.
    let mut json: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&state).unwrap()).unwrap();
    json["files"]["secrets.txt"] = serde_json::json!("sha256:0");
    fs::write(&state, json.to_string()).unwrap();
    let out = p.mezha(&["diff"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(
        stderr(&out).contains("note: ignoring `secrets.txt` in .claude/.mezha-state.json"),
        "{}",
        stderr(&out)
    );
    // An unreadable one makes every file on disk look hand-written.
    fs::write(&state, "{not json").unwrap();
    let out = p.mezha(&["diff"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(
        stderr(&out).contains("note: .claude/.mezha-state.json is unreadable ("),
        "{}",
        stderr(&out)
    );
    assert!(
        stdout(&out).contains("unchanged  .claude/settings.json"),
        "{}",
        stdout(&out)
    );
}

#[test]
fn files_no_longer_generated_are_removed_unless_edited_by_hand() {
    let p = Project::new();
    let with_agent = format!(
        "{SPEC}\n[agent.tester]\ndescription = \"Runs the tests.\"\ntools = [\"Read\"]\nrule_of_two = []\n"
    );
    fs::create_dir_all(p.root.join("mezha/agents")).unwrap();
    fs::write(p.root.join("mezha/agents/tester.md"), "Run the tests.\n").unwrap();
    p.write_spec(&with_agent);
    let out = p.mezha(&["compile"]);
    assert!(out.status.success(), "{}", stderr(&out));
    let agent = p.root.join(".claude/agents/tester.md");
    assert!(agent.is_file());

    p.write_spec(SPEC);
    let out = p.mezha(&["compile"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(
        stdout(&out).contains("remove     .claude/agents/tester.md"),
        "{}",
        stdout(&out)
    );
    assert!(stdout(&out).contains("removed 1."), "{}", stdout(&out));
    assert!(!agent.exists());

    // Generated again, then edited by hand: it stays, and says so.
    p.write_spec(&with_agent);
    assert!(p.mezha(&["compile"]).status.success());
    fs::write(&agent, "mine\n").unwrap();
    p.write_spec(SPEC);
    let out = p.mezha(&["compile"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(
        stdout(&out).contains(
            "keep       .claude/agents/tester.md (no longer generated, but changed by hand; left in place)"
        ),
        "{}",
        stdout(&out)
    );
    assert_eq!(p.read(".claude/agents/tester.md"), "mine\n");
}

/// A hook whose stdin can't be read blocks, like any other hook failure.
#[cfg(unix)]
#[test]
fn a_hook_with_unreadable_input_blocks() {
    let p = Project::new();
    let mut cmd = std::process::Command::new(common::BIN);
    cmd.args(["hook", "pretooluse", "--protocol", "2"])
        .current_dir(&p.root)
        .env_clear()
        .env("HOME", &p.home)
        .stdin(fs::File::open(&p.root).unwrap());
    common::pass_through(&mut cmd);
    let out = cmd.output().unwrap();
    assert_eq!(out.status.code(), Some(2), "{}", stderr(&out));
    assert!(
        stderr(&out).contains("mezha: can't read hook input:"),
        "{}",
        stderr(&out)
    );
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
        fs::read_to_string(backups[0].path().join("_claude/settings.json")).unwrap(),
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
