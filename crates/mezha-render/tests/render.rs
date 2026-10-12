//! Rendering and the write engine: the golden settings file, and how
//! compile and apply treat files on disk.

use std::fs;
use std::path::Path;

use mezha_render::{Action, Mode, Rendered, WriteError, is_generated, plan, render, write};

const SETTINGS: &str = ".claude/settings.json";
const STATE: &str = ".claude/.mezha-state.json";

fn golden_dir() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/golden")
}

fn rendered_from(text: &str) -> Rendered {
    let spec = mezha_spec::parse(text).unwrap();
    assert!(!mezha_spec::validate(&spec).has_errors());
    render(&spec, text, Path::new("/nonexistent")).unwrap()
}

fn rendered() -> Rendered {
    rendered_from(&fs::read_to_string(golden_dir().join("mezha.toml")).unwrap())
}

fn actions(root: &Path, r: &Rendered) -> Vec<(String, Action)> {
    plan(root, r)
        .unwrap()
        .changes
        .into_iter()
        .map(|c| (c.path, c.action))
        .collect()
}

/// Regenerate with `MEZHA_BLESS=1 cargo test -p mezha-render --test render`.
#[test]
fn settings_match_the_golden_file() {
    let actual = &rendered().files[SETTINGS];
    let path = golden_dir().join("settings.json");
    if std::env::var_os("MEZHA_BLESS").is_some() {
        fs::write(&path, actual).unwrap();
    }
    let expected = fs::read_to_string(&path).unwrap();
    assert_eq!(
        actual, &expected,
        "golden settings changed; see the doc comment to bless"
    );
}

#[test]
fn only_generated_paths_are_rendered() {
    let r = rendered();
    assert!(r.files.keys().all(|p| is_generated(p)));
}

#[test]
fn sandbox_off_leaves_the_sandbox_key_out() {
    let r = rendered_from(
        "[project]\nname = \"p\"\n[policy]\nsandbox = false\npermissions_ask = [\"git push\"]\n",
    );
    let v: serde_json::Value = serde_json::from_str(&r.files[SETTINGS]).unwrap();
    assert!(v.get("sandbox").is_none());
    assert!(
        v["hooks"]["PreToolUse"][0].get("matcher").is_none(),
        "the gate sees every tool"
    );
}

#[test]
fn native_windows_is_refused_for_now() {
    let text = "[project]\nname = \"p\"\nos_mode = \"native-windows\"\n";
    let spec = mezha_spec::parse(text).unwrap();
    assert_eq!(
        render(&spec, text, Path::new("/nonexistent")).unwrap_err(),
        mezha_render::RenderError::NativeWindows
    );
}

#[test]
fn create_then_unchanged_then_update() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let r = rendered();
    let p = plan(root, &r).unwrap();
    assert_eq!(p.changes[0].action, Action::Create);
    write(root, &p, Mode::Compile, "s").unwrap();
    assert!(root.join(STATE).exists());

    let p = plan(root, &r).unwrap();
    assert!(p.is_noop(), "{p:#?}");

    // A spec change rewrites mezha's own, untouched output.
    let r2 = rendered_from("[project]\nname = \"p\"\n[policy]\npermissions_ask = [\"git push\"]\n");
    assert_eq!(actions(root, &r2), [(SETTINGS.into(), Action::Update)]);
    write(root, &plan(root, &r2).unwrap(), Mode::Compile, "s").unwrap();
    assert_eq!(
        fs::read_to_string(root.join(SETTINGS)).unwrap(),
        r2.files[SETTINGS]
    );
}

#[test]
fn a_hand_edit_is_a_conflict_compile_refuses_and_apply_backs_up() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let r = rendered();
    write(root, &plan(root, &r).unwrap(), Mode::Compile, "s").unwrap();
    fs::write(root.join(SETTINGS), "{ \"hand\": true }\n").unwrap();

    let r2 = rendered_from("[project]\nname = \"p\"\n[policy]\npermissions_ask = [\"git push\"]\n");
    let p = plan(root, &r2).unwrap();
    assert!(matches!(&p.changes[0].action, Action::Conflict(why) if why.contains("by hand")));
    assert!(matches!(
        write(root, &p, Mode::Compile, "s"),
        Err(WriteError::Conflicts)
    ));
    assert_eq!(
        fs::read_to_string(root.join(SETTINGS)).unwrap(),
        "{ \"hand\": true }\n"
    );

    let report = write(root, &p, Mode::Apply, "20270115T080000Z").unwrap();
    let backup = report.backup.unwrap();
    assert!(backup.ends_with(".mezha-backup/20270115T080000Z"));
    // `.claude` becomes `_claude` in backups, so Claude Code doesn't load them.
    assert_eq!(
        fs::read_to_string(backup.join("_claude/settings.json")).unwrap(),
        "{ \"hand\": true }\n"
    );
    assert!(!backup.join(".claude").exists());
    assert_eq!(
        fs::read_to_string(root.join(".mezha-backup/.gitignore")).unwrap(),
        "*\n"
    );
    assert_eq!(
        fs::read_to_string(root.join(SETTINGS)).unwrap(),
        r2.files[SETTINGS]
    );

    // A second backup in the same second gets its own directory.
    fs::write(root.join(SETTINGS), "{}\n").unwrap();
    let report = write(
        root,
        &plan(root, &r).unwrap(),
        Mode::Apply,
        "20270115T080000Z",
    )
    .unwrap();
    assert!(report.backup.unwrap().ends_with("20270115T080000Z-2"));
}

#[test]
fn a_hand_written_settings_file_without_state_is_a_conflict() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    fs::create_dir_all(root.join(".claude")).unwrap();
    fs::write(root.join(SETTINGS), "{}\n").unwrap();
    fs::write(root.join(".claude/settings.local.json"), "{\"mine\":1}\n").unwrap();
    let p = plan(root, &rendered()).unwrap();
    assert!(
        matches!(&p.changes[0].action, Action::Conflict(why) if why.contains("not written by mezha"))
    );
    write(root, &p, Mode::Apply, "s").unwrap();
    assert_eq!(
        fs::read_to_string(root.join(".claude/settings.local.json")).unwrap(),
        "{\"mine\":1}\n",
        "settings.local.json is never touched"
    );
}

#[test]
fn a_lost_state_file_is_recovered_when_content_matches() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let r = rendered();
    write(root, &plan(root, &r).unwrap(), Mode::Compile, "s").unwrap();
    fs::remove_file(root.join(STATE)).unwrap();
    let p = plan(root, &r).unwrap();
    assert_eq!(p.changes[0].action, Action::Unchanged);
    assert!(p.state_changed);
}

#[test]
fn crlf_checkouts_are_not_hand_edits() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let r = rendered();
    write(root, &plan(root, &r).unwrap(), Mode::Compile, "s").unwrap();
    let crlf = r.files[SETTINGS].replace('\n', "\r\n");
    fs::write(root.join(SETTINGS), crlf).unwrap();
    assert_eq!(actions(root, &r), [(SETTINGS.into(), Action::Unchanged)]);
}

#[test]
fn state_paths_outside_the_allowlist_are_ignored() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let r = rendered();
    write(root, &plan(root, &r).unwrap(), Mode::Compile, "s").unwrap();
    fs::write(root.join("victim.txt"), "keep me\n").unwrap();
    let mut state: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(root.join(STATE)).unwrap()).unwrap();
    let print = mezha_render::state::fingerprint("keep me\n");
    state["files"]["victim.txt"] = print.clone().into();
    state["files"]["../outside.txt"] = print.into();
    fs::write(root.join(STATE), state.to_string()).unwrap();

    let p = plan(root, &r).unwrap();
    assert!(p.changes.iter().all(|c| c.path == SETTINGS), "{p:#?}");
    assert_eq!(p.notes.len(), 2);
    write(root, &p, Mode::Compile, "s").unwrap();
    assert!(root.join("victim.txt").exists());
}

#[test]
fn a_newer_state_is_refused() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    fs::create_dir_all(root.join(".claude")).unwrap();
    fs::write(
        root.join(STATE),
        r#"{"state_version":9,"hook_protocol":1,"spec":"","files":{}}"#,
    )
    .unwrap();
    assert!(matches!(
        plan(root, &rendered()),
        Err(WriteError::NewerState(9))
    ));
}

#[cfg(unix)]
#[test]
fn symlinks_are_refused() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("p");
    let elsewhere = tmp.path().join("elsewhere");
    fs::create_dir_all(&root).unwrap();
    fs::create_dir_all(&elsewhere).unwrap();
    std::os::unix::fs::symlink(&elsewhere, root.join(".claude")).unwrap();
    assert!(matches!(
        plan(&root, &rendered()),
        Err(WriteError::Refused { .. })
    ));

    fs::remove_file(root.join(".claude")).unwrap();
    fs::create_dir_all(root.join(".claude")).unwrap();
    std::os::unix::fs::symlink(elsewhere.join("x.json"), root.join(SETTINGS)).unwrap();
    assert!(matches!(
        plan(&root, &rendered()),
        Err(WriteError::Refused { .. })
    ));
}

#[test]
fn credentials_are_withheld_from_the_sandbox_and_the_read_tool() {
    use mezha_render::settings::{CREDENTIAL_ENV, CREDENTIAL_FILES, GIT_GUARD_ENV, read_rule};
    let v: serde_json::Value = serde_json::from_str(&rendered().files[SETTINGS]).unwrap();
    let creds = &v["sandbox"]["credentials"];
    for (path, is_dir) in CREDENTIAL_FILES {
        assert!(
            creds["files"]
                .as_array()
                .unwrap()
                .contains(&serde_json::json!({ "path": path, "mode": "deny" })),
            "{path}"
        );
        let rule = read_rule(path, is_dir);
        assert!(
            v["permissions"]["deny"]
                .as_array()
                .unwrap()
                .contains(&rule.clone().into()),
            "{rule}"
        );
    }
    for name in CREDENTIAL_ENV {
        assert!(
            creds["envVars"]
                .as_array()
                .unwrap()
                .contains(&serde_json::json!({ "name": name, "mode": "deny" })),
            "{name}"
        );
    }
    for (key, value) in GIT_GUARD_ENV {
        assert_eq!(v["env"][key], value, "{key}");
    }

    // Without the sandbox, the Read rules and the git guard rail stay.
    let off = rendered_from(
        "[project]\nname = \"p\"\n[policy]\nsandbox = false\npermissions_ask = [\"git push\"]\n",
    );
    let v: serde_json::Value = serde_json::from_str(&off.files[SETTINGS]).unwrap();
    assert!(
        v["permissions"]["deny"]
            .as_array()
            .unwrap()
            .contains(&"Read(~/.ssh/**)".into())
    );
    assert_eq!(v["env"]["GIT_CONFIG_KEY_0"], "credential.helper");
}

#[test]
fn an_empty_fetch_allow_turns_web_fetch_off() {
    let env = |text: &str| {
        let r = rendered_from(text);
        let v: serde_json::Value = serde_json::from_str(&r.files[SETTINGS]).unwrap();
        v["env"].clone()
    };
    let base = "[project]\nname = \"p\"\n[policy]\npermissions_ask = [\"git push\"]\n";
    let none = env(&format!("{base}fetch_allow = []\n"));
    assert_eq!(none["CLAUDE_CODE_DISABLE_WEB_FETCH"], "1", "{none}");
    let some = env(&format!("{base}fetch_allow = [\"docs.rs\"]\n"));
    assert!(
        some.get("CLAUDE_CODE_DISABLE_WEB_FETCH").is_none(),
        "{some}"
    );
    let open = env(base);
    assert!(
        open.get("CLAUDE_CODE_DISABLE_WEB_FETCH").is_none(),
        "{open}"
    );
}

/// Rendering doesn't validate, so a spec validation would have refused
/// still gets a named error rather than a half-rendered tree.
#[test]
fn invalid_gates_and_fetch_hosts_are_render_errors() {
    use mezha_render::RenderError;
    let fails = |text: &str| {
        let spec = mezha_spec::parse(text).unwrap();
        render(&spec, text, Path::new("/nonexistent")).unwrap_err()
    };
    let gates = fails("[project]\nname = \"p\"\n[policy]\npermissions_ask = [\"git push; rm\"]\n");
    assert!(matches!(gates, RenderError::Gates(_)), "{gates:?}");
    assert!(
        gates
            .to_string()
            .starts_with("policy.permissions_ask: `git push; rm` is not a command prefix"),
        "{gates}"
    );
    let fetch = fails("[project]\nname = \"p\"\n[policy]\nfetch_allow = [\"https://docs.rs\"]\n");
    assert!(matches!(fetch, RenderError::Fetch(_)), "{fetch:?}");
    assert!(
        fetch
            .to_string()
            .starts_with("policy.fetch_allow: `https://docs.rs` is not a host"),
        "{fetch}"
    );
    let windows = RenderError::NativeWindows.to_string();
    assert!(windows.contains("Use WSL2"), "{windows}");
}

#[test]
fn write_errors_say_what_went_wrong_where() {
    let newer = WriteError::NewerState(9).to_string();
    assert_eq!(
        newer,
        format!(
            "{STATE} has state_version 9, newer than this mezha reads ({}); upgrade mezha",
            mezha_render::state::STATE_VERSION
        )
    );
    assert_eq!(
        WriteError::Conflicts.to_string(),
        "conflicting files; nothing was written"
    );
    let io = WriteError::Io {
        path: SETTINGS.into(),
        error: std::io::Error::other("disk gone"),
    };
    assert_eq!(io.to_string(), ".claude/settings.json: disk gone");
    let refused = WriteError::Refused {
        path: SETTINGS.into(),
        reason: "not a regular file".into(),
    };
    assert_eq!(
        refused.to_string(),
        "refusing to write .claude/settings.json: not a regular file"
    );
}

#[test]
fn an_unreadable_state_file_is_noted_and_files_count_as_hand_written() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let r = rendered();
    write(root, &plan(root, &r).unwrap(), Mode::Compile, "s").unwrap();
    fs::write(root.join(STATE), "not json\n").unwrap();
    let r2 = rendered_from("[project]\nname = \"p\"\n[policy]\npermissions_ask = [\"git push\"]\n");
    let p = plan(root, &r2).unwrap();
    assert_eq!(p.notes.len(), 1, "{:?}", p.notes);
    assert!(
        p.notes[0].starts_with(".claude/.mezha-state.json is unreadable ("),
        "{:?}",
        p.notes
    );
    assert!(
        matches!(&p.changes[0].action, Action::Conflict(why) if why.contains("not written by mezha")),
        "{:?}",
        p.changes[0].action
    );
    assert!(p.state_changed);
}

#[test]
fn a_file_no_longer_generated_is_removed_only_when_untouched() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let r = rendered();
    write(root, &plan(root, &r).unwrap(), Mode::Compile, "s").unwrap();
    // The state remembers two rules mezha once wrote: one edited by hand
    // since, one already gone.
    fs::create_dir_all(root.join(".claude/rules")).unwrap();
    fs::write(root.join(".claude/rules/edited.md"), "edited by hand\n").unwrap();
    let mut state: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(root.join(STATE)).unwrap()).unwrap();
    let print = |text: &str| serde_json::Value::from(mezha_render::state::fingerprint(text));
    state["files"][".claude/rules/edited.md"] = print("as mezha wrote it\n");
    state["files"][".claude/rules/gone.md"] = print("gone\n");
    fs::write(root.join(STATE), state.to_string()).unwrap();

    let p = plan(root, &r).unwrap();
    let others: Vec<_> = p.changes.iter().filter(|c| c.path != SETTINGS).collect();
    assert_eq!(others.len(), 1, "{p:#?}");
    assert_eq!(others[0].path, ".claude/rules/edited.md");
    assert!(
        matches!(&others[0].action, Action::KeepRemoved(why) if why.contains("changed by hand")),
        "{:?}",
        others[0].action
    );
    assert!(others[0].new.is_none());
    assert!(p.state_changed, "the state forgets both files");
    assert!(!p.is_noop());

    let report = write(root, &p, Mode::Apply, "s").unwrap();
    assert!(report.written.is_empty(), "{report:?}");
    assert!(report.removed.is_empty(), "{report:?}");
    assert!(report.backup.is_none(), "{report:?}");
    assert_eq!(
        fs::read_to_string(root.join(".claude/rules/edited.md")).unwrap(),
        "edited by hand\n"
    );
    // Afterwards nothing is left to do, and writing that changes nothing.
    let p = plan(root, &r).unwrap();
    assert!(p.is_noop(), "{p:#?}");
    let before = fs::read_to_string(root.join(STATE)).unwrap();
    let report = write(root, &p, Mode::Compile, "s").unwrap();
    assert!(report.written.is_empty(), "{report:?}");
    assert_eq!(fs::read_to_string(root.join(STATE)).unwrap(), before);
}

/// Rendered output with arbitrary paths, for what the fence refuses.
fn custom(files: &[(&str, &str)]) -> Rendered {
    Rendered {
        files: files
            .iter()
            .map(|(p, c)| (p.to_string(), c.to_string()))
            .collect(),
        spec: "sha256:test".into(),
        problems: Vec::new(),
        warnings: Vec::new(),
    }
}

#[test]
fn only_plain_relative_paths_to_regular_files_are_written() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    for bad in ["", "../x", "/abs", "a\\b", "./x", "a/../b"] {
        let err = plan(root, &custom(&[(bad, "x\n")])).unwrap_err();
        assert!(
            matches!(&err, WriteError::Refused { path, reason }
                if path == bad && reason == "not a plain relative path"),
            "{bad:?}: {err}"
        );
    }
    // A directory where the file should be.
    fs::create_dir_all(root.join(SETTINGS)).unwrap();
    let err = plan(root, &rendered()).unwrap_err();
    assert!(
        matches!(&err, WriteError::Refused { reason, .. } if reason == "not a regular file"),
        "{err}"
    );
    fs::remove_dir(root.join(SETTINGS)).unwrap();
    fs::remove_dir(root.join(".claude")).unwrap();
    // A file where a directory should be.
    fs::write(root.join(".claude"), "").unwrap();
    let err = plan(root, &rendered()).unwrap_err();
    assert!(
        matches!(&err, WriteError::Refused { reason, .. } if reason.ends_with(".claude is not a directory")),
        "{err}"
    );
}

#[test]
fn backups_keep_paths_outside_dot_claude_as_they_are() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    fs::write(root.join("notes.md"), "mine\n").unwrap();
    let p = plan(root, &custom(&[("notes.md", "generated\n")])).unwrap();
    assert!(
        matches!(&p.changes[0].action, Action::Conflict(_)),
        "{:?}",
        p.changes[0].action
    );
    let report = write(root, &p, Mode::Apply, "20270101T000000Z").unwrap();
    let backup = report.backup.unwrap();
    assert_eq!(
        fs::read_to_string(backup.join("notes.md")).unwrap(),
        "mine\n"
    );
    assert_eq!(
        fs::read_to_string(root.join("notes.md")).unwrap(),
        "generated\n"
    );
}

#[cfg(unix)]
#[test]
fn io_errors_name_the_file() {
    use std::os::unix::fs::PermissionsExt;
    let mode = |p: &Path, m: u32| fs::set_permissions(p, fs::Permissions::from_mode(m)).unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let r = rendered();
    let io_on =
        |err: &WriteError, path: &str| matches!(err, WriteError::Io { path: p, .. } if p == path);

    // An unreadable settings file can't be compared with the new one.
    fs::create_dir_all(root.join(".claude")).unwrap();
    fs::write(root.join(SETTINGS), "{}\n").unwrap();
    mode(&root.join(SETTINGS), 0o000);
    let err = plan(root, &r).unwrap_err();
    mode(&root.join(SETTINGS), 0o644);
    assert!(io_on(&err, SETTINGS), "{err}");
    assert!(
        err.to_string().starts_with(".claude/settings.json: "),
        "{err}"
    );
    fs::remove_file(root.join(SETTINGS)).unwrap();

    // A read-only .claude can't take the file, and no temporary file stays.
    let p = plan(root, &r).unwrap();
    mode(&root.join(".claude"), 0o500);
    let err = write(root, &p, Mode::Compile, "s").unwrap_err();
    mode(&root.join(".claude"), 0o755);
    assert!(io_on(&err, SETTINGS), "{err}");
    let left: Vec<_> = fs::read_dir(root.join(".claude"))
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert!(left.is_empty(), "{left:?}");

    // A read-only root can't take .claude itself.
    fs::remove_dir(root.join(".claude")).unwrap();
    let p = plan(root, &r).unwrap();
    mode(root, 0o500);
    let err = write(root, &p, Mode::Compile, "s").unwrap_err();
    mode(root, 0o755);
    assert!(io_on(&err, SETTINGS), "{err}");
    assert!(!root.join(".claude").exists());
}

#[test]
fn diffs_are_unified_with_the_project_paths() {
    use mezha_render::{Change, unified_diff};
    let updated = Change {
        path: ".claude/rules/x.md".into(),
        action: Action::Update,
        old: Some("a\r\nb\r\n".into()),
        new: Some("a\nc\n".into()),
    };
    let diff = unified_diff(&updated);
    assert!(
        diff.starts_with("--- a/.claude/rules/x.md\n+++ b/.claude/rules/x.md\n"),
        "{diff}"
    );
    assert!(diff.contains("\n a\n-b\n+c\n"), "{diff}");
    let created = Change {
        path: "x".into(),
        action: Action::Create,
        old: None,
        new: Some("new\n".into()),
    };
    assert!(
        unified_diff(&created).ends_with("@@\n+new\n"),
        "{}",
        unified_diff(&created)
    );
    let removed = Change {
        path: "x".into(),
        action: Action::Remove,
        old: Some("old\n".into()),
        new: None,
    };
    assert!(
        unified_diff(&removed).ends_with("@@\n-old\n"),
        "{}",
        unified_diff(&removed)
    );
}
