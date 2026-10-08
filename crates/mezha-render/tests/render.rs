//! Rendering and the write engine: the golden settings file, and how
//! compile and apply treat files on disk.

use std::fs;
use std::path::Path;

use mezha_render::{Action, GENERATED, Mode, Rendered, WriteError, plan, render, write};

const SETTINGS: &str = ".claude/settings.json";
const STATE: &str = ".claude/.mezha-state.json";

fn golden_dir() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/golden")
}

fn rendered_from(text: &str) -> Rendered {
    let spec = mezha_spec::parse(text).unwrap();
    assert!(!mezha_spec::validate(&spec).has_errors());
    render(&spec, text).unwrap()
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
    assert!(r.files.keys().all(|p| GENERATED.contains(&p.as_str())));
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
        render(&spec, text).unwrap_err(),
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
    assert_eq!(
        fs::read_to_string(backup.join(SETTINGS)).unwrap(),
        "{ \"hand\": true }\n"
    );
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
