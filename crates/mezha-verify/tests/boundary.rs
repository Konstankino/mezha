//! verify must fail when the boundary is broken and pass when it isn't
//! (`mezha-plan.md` phase 1 definition of done). Each scenario compiles a
//! real project, breaks one thing, and runs verify with a fake machine:
//! scratch home and managed directory, no system or global git config, and
//! stand-in `claude`, `bwrap` and `socat` on PATH.

#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use mezha_verify::{Ctx, Options, Platform, Report, Status, verify};
use serde_json::{Value, json};

struct Fixture {
    _tmp: tempfile::TempDir,
    home: PathBuf,
    root: PathBuf,
    managed: PathBuf,
    bin: PathBuf,
    gitconfig: PathBuf,
}

fn spec(egress: &str) -> String {
    format!(
        "[project]\nname = \"boundary\"\n\n[policy]\negress_allow = [{egress}]\npermissions_ask = [\"git push\"]\n"
    )
}

impl Fixture {
    fn new(egress: &str, remote: &str) -> Fixture {
        let tmp = tempfile::tempdir().unwrap();
        let base = fs::canonicalize(tmp.path()).unwrap();
        let home = base.join("home");
        let root = base.join("repo");
        let managed = base.join("managed");
        let bin = base.join("bin");
        for dir in [&home, &root, &managed, &bin] {
            fs::create_dir_all(dir).unwrap();
        }
        let gitconfig = base.join("gitconfig");
        fs::write(&gitconfig, "").unwrap();
        let f = Fixture {
            _tmp: tmp,
            home,
            root,
            managed,
            bin,
            gitconfig,
        };
        f.git(&["init", "-q"]);
        f.git(&["remote", "add", "origin", remote]);
        f.tool("claude", "echo '2.1.285 (Claude Code)'");
        f.tool("bwrap", "exit 0");
        f.tool("socat", "exit 0");
        f.compile(&spec(egress));
        f
    }

    fn tool(&self, name: &str, body: &str) {
        let path = self.bin.join(name);
        fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
    }

    fn git(&self, args: &[&str]) {
        let out = Command::new("git")
            .args(args)
            .current_dir(&self.root)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", &self.gitconfig)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "git {args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    fn compile(&self, text: &str) {
        fs::write(self.root.join("mezha.toml"), text).unwrap();
        let spec = mezha_spec::parse(text).unwrap();
        let rendered = mezha_render::render(&spec, text).unwrap();
        let plan = mezha_render::plan(&self.root, &rendered).unwrap();
        mezha_render::write(&self.root, &plan, mezha_render::Mode::Apply, "t").unwrap();
    }

    fn ctx(&self, platform: Platform) -> Ctx {
        Ctx {
            root: self.root.clone(),
            vars: [
                ("PATH", format!("{}:/usr/bin:/bin", self.bin.display())),
                ("HOME", self.home.display().to_string()),
                ("GIT_CONFIG_NOSYSTEM", "1".into()),
                ("GIT_CONFIG_GLOBAL", self.gitconfig.display().to_string()),
            ]
            .into_iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect(),
            home: Some(self.home.clone()),
            platform,
            managed_dir: Some(self.managed.clone()),
            mezha_exe: None,
        }
    }

    fn verify_on(&self, platform: Platform, opts: Options) -> Report {
        verify(&self.ctx(platform), &opts).unwrap()
    }

    fn verify(&self) -> Report {
        self.verify_on(Platform::Linux, Options::default())
    }

    fn write_json(&self, path: &Path, value: Value) {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, value.to_string()).unwrap();
    }

    fn user_settings(&self, value: Value) {
        self.write_json(&self.home.join(".claude/settings.json"), value);
    }

    fn local_settings(&self, value: Value) {
        self.write_json(&self.root.join(".claude/settings.local.json"), value);
    }

    fn edit_settings(&self, edit: impl FnOnce(&mut Value)) {
        let path = self.root.join(".claude/settings.json");
        let mut v: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        edit(&mut v);
        fs::write(&path, serde_json::to_string_pretty(&v).unwrap()).unwrap();
    }
}

const GITHUB: &str = "https://github.com/o/r.git";

fn status(report: &Report, id: &str) -> Status {
    report.checks.iter().find(|c| c.id == id).unwrap().status
}

fn detail<'a>(report: &'a Report, id: &str) -> &'a str {
    &report.checks.iter().find(|c| c.id == id).unwrap().detail
}

#[test]
fn a_clean_project_passes() {
    let f = Fixture::new("", GITHUB);
    let r = f.verify();
    assert_eq!(r.exit_code(), 0, "{}", r.to_human("x"));
    assert_eq!(
        status(&r, "sandbox"),
        Status::Pass,
        "{}",
        detail(&r, "sandbox")
    );
    assert_eq!(status(&r, "push-boundary"), Status::Pass);
    assert!(detail(&r, "push-boundary").contains("can't reach"));
    assert_eq!(status(&r, "settings-layers"), Status::Pass);
    // No mezha on the fake PATH: warned, not failed.
    assert_eq!(status(&r, "settings-intact"), Status::Warn);
    assert!(detail(&r, "settings-intact").contains("not on PATH"));
}

#[test]
fn scenario_1_sandbox_off_in_local_settings() {
    let f = Fixture::new("", GITHUB);
    f.local_settings(json!({ "sandbox": { "enabled": false } }));
    let r = f.verify();
    assert_eq!(r.exit_code(), 1);
    assert_eq!(status(&r, "sandbox"), Status::Fail);
    assert!(detail(&r, "sandbox").contains("settings.local.json"));
    assert_eq!(status(&r, "push-boundary"), Status::Fail);
}

#[test]
fn scenario_2_hooks_disabled_in_user_settings() {
    let f = Fixture::new("", GITHUB);
    f.user_settings(json!({ "disableAllHooks": true }));
    let r = f.verify();
    assert_eq!(r.exit_code(), 1);
    assert_eq!(status(&r, "settings-layers"), Status::Fail);
    assert!(detail(&r, "settings-layers").contains("disableAllHooks"));
}

#[test]
fn scenario_3_hand_edited_hook_command() {
    let f = Fixture::new("", GITHUB);
    f.edit_settings(|v| {
        v["hooks"]["PreToolUse"][0]["hooks"][0]["command"] = json!("exit 0");
    });
    let r = f.verify();
    assert_eq!(r.exit_code(), 1);
    assert_eq!(status(&r, "settings-intact"), Status::Fail);
    assert!(detail(&r, "settings-intact").contains("edited by hand"));
}

#[test]
fn scenario_4_token_in_the_remote_url_with_github_allowed() {
    let f = Fixture::new(
        "\"github.com\"",
        "https://x:ghp_testtoken@github.com/o/r.git",
    );
    let r = f.verify();
    assert_eq!(r.exit_code(), 1);
    assert_eq!(status(&r, "push-boundary"), Status::Fail);
    assert!(detail(&r, "push-boundary").contains("remote URL"));
    let json = r.to_json();
    assert!(!json.contains("ghp_testtoken"), "secret leaked: {json}");
    assert!(!r.to_human("x").contains("ghp_testtoken"));
}

#[test]
fn scenario_5_excluded_commands_in_user_settings() {
    let f = Fixture::new("", GITHUB);
    f.user_settings(json!({ "sandbox": { "excludedCommands": ["git"] } }));
    let r = f.verify();
    assert_eq!(r.exit_code(), 1);
    assert_eq!(status(&r, "sandbox"), Status::Fail);
    assert!(detail(&r, "sandbox").contains("`git` runs outside the sandbox"));
}

#[test]
fn scenario_6_credentials_block_removed() {
    let f = Fixture::new("\"github.com\"", GITHUB);
    fs::write(f.home.join(".git-credentials"), "https://x:t@github.com\n").unwrap();
    // Withheld, so the file alone doesn't break the boundary.
    assert_eq!(status(&f.verify(), "push-boundary"), Status::Pass);

    f.edit_settings(|v| {
        v["sandbox"].as_object_mut().unwrap().remove("credentials");
    });
    let r = f.verify();
    assert_eq!(r.exit_code(), 1);
    assert_eq!(status(&r, "settings-intact"), Status::Fail);
    assert_eq!(status(&r, "push-boundary"), Status::Fail);
    assert!(detail(&r, "push-boundary").contains(".git-credentials"));
}

#[cfg(target_os = "macos")]
#[test]
fn scenario_7_macos_keychain_with_github_allowed() {
    let f = Fixture::new("\"github.com\"", GITHUB);
    fs::write(&f.gitconfig, "[credential]\n\thelper = osxkeychain\n").unwrap();
    let r = f.verify_on(Platform::MacOs, Options::default());
    assert_eq!(
        status(&r, "push-boundary"),
        Status::Fail,
        "{}",
        detail(&r, "push-boundary")
    );
    assert!(detail(&r, "push-boundary").contains("osxkeychain"));

    // Closing the network restores the boundary even though the keychain is open.
    let closed = Fixture::new("", GITHUB);
    fs::write(&closed.gitconfig, "[credential]\n\thelper = osxkeychain\n").unwrap();
    let r = closed.verify_on(Platform::MacOs, Options::default());
    assert_eq!(
        status(&r, "push-boundary"),
        Status::Pass,
        "{}",
        detail(&r, "push-boundary")
    );
}

#[test]
fn a_webfetch_allow_rule_opens_the_network_too() {
    let f = Fixture::new("", "https://x:tok@github.com/o/r.git");
    assert_eq!(status(&f.verify(), "push-boundary"), Status::Pass);
    f.local_settings(json!({ "permissions": { "allow": ["WebFetch(domain:github.com)"] } }));
    let r = f.verify();
    assert_eq!(
        status(&r, "push-boundary"),
        Status::Fail,
        "{}",
        detail(&r, "push-boundary")
    );
}

#[test]
fn unknown_helpers_make_an_open_network_unverified() {
    let f = Fixture::new("\"github.com\"", GITHUB);
    fs::write(&f.gitconfig, "[credential]\n\thelper = mystery\n").unwrap();
    let r = f.verify();
    assert_eq!(status(&r, "push-boundary"), Status::Warn);
    assert!(detail(&r, "push-boundary").contains("unverified"));
}

#[test]
fn an_admin_required_sandbox_ignores_repository_loosening() {
    let f = Fixture::new("", GITHUB);
    f.local_settings(json!({ "sandbox": { "enabled": false, "excludedCommands": ["git"] } }));
    fs::write(
        f.managed.join("managed-settings.json"),
        json!({ "sandbox": { "allowUnsandboxedCommands": false } }).to_string(),
    )
    .unwrap();
    let r = f.verify();
    assert_eq!(
        status(&r, "sandbox"),
        Status::Pass,
        "{}",
        detail(&r, "sandbox")
    );
}

#[test]
fn project_only_ignores_the_machine() {
    let f = Fixture::new("\"github.com\"", GITHUB);
    f.user_settings(json!({ "disableAllHooks": true }));
    let r = f.verify_on(Platform::Linux, Options { project_only: true });
    assert_eq!(r.mode, "project-only");
    assert_eq!(status(&r, "settings-layers"), Status::Pass);
    assert_eq!(status(&r, "push-boundary"), Status::Warn);
    assert!(detail(&r, "push-boundary").contains("each machine"));
}

#[test]
fn native_windows_and_wsl1_fail_the_sandbox() {
    let f = Fixture::new("", GITHUB);
    for platform in [Platform::Windows, Platform::Wsl1] {
        let r = f.verify_on(platform, Options::default());
        assert_eq!(status(&r, "sandbox"), Status::Fail, "{platform:?}");
        assert_eq!(status(&r, "push-boundary"), Status::Fail, "{platform:?}");
    }
}

#[test]
fn an_old_claude_code_fails() {
    let f = Fixture::new("", GITHUB);
    f.tool("claude", "echo '2.1.200 (Claude Code)'");
    let r = f.verify();
    assert_eq!(status(&r, "sandbox"), Status::Fail);
    assert!(detail(&r, "sandbox").contains("2.1.200"));
}

#[test]
fn a_broken_bwrap_fails_on_linux() {
    let f = Fixture::new("", GITHUB);
    f.tool("bwrap", "exit 1");
    let r = f.verify();
    assert_eq!(status(&r, "sandbox"), Status::Fail);
    assert!(detail(&r, "sandbox").contains("bubblewrap"));
}

#[test]
fn a_missing_spec_cannot_run() {
    let f = Fixture::new("", GITHUB);
    fs::remove_file(f.root.join("mezha.toml")).unwrap();
    let err = verify(&f.ctx(Platform::Linux), &Options::default()).unwrap_err();
    assert!(matches!(err, mezha_verify::CantRun::NoSpec(_)));
}
