//! The settings-driven checks end to end: `sandbox` on each loosening
//! setting and platform, `push-boundary` with a custom sandbox proxy,
//! `settings-layers` on managed locks and overrides, and `project-config`
//! on hooks, approvals and a broken `.mcp.json`.

#![cfg(unix)]

use std::fs;

use mezha_verify::{Options, Platform, Status, verify};
use serde_json::json;

mod checks_common;
use checks_common::{Fixture, GITHUB, detail, expect, expect_detail};

#[test]
fn sandbox_enabled_missing_fails() {
    let f = Fixture::new("", GITHUB);
    f.edit_settings(|v| {
        v["sandbox"].as_object_mut().unwrap().remove("enabled");
    });
    let r = f.verify();
    expect(&r, "sandbox", Status::Fail);
    expect_detail(&r, "sandbox", "sandbox.enabled is not set");
    assert!(
        checks_common::check(&r, "sandbox")
            .fix
            .as_deref()
            .is_some_and(|fix| fix.contains("policy.sandbox = true")),
        "{:?}",
        checks_common::check(&r, "sandbox").fix
    );
    expect(&r, "push-boundary", Status::Fail);
}

#[test]
fn fail_if_unavailable_off_fails() {
    let f = Fixture::new("", GITHUB);
    f.local_settings(json!({ "sandbox": { "failIfUnavailable": false } }));
    let r = f.verify();
    expect(&r, "sandbox", Status::Fail);
    expect_detail(
        &r,
        "sandbox",
        "sandbox.failIfUnavailable is false in .claude/settings.local.json, so commands run unsandboxed when the sandbox can't start",
    );
}

#[test]
fn unsandboxed_retries_fail_unless_an_admin_holds_them_off() {
    let f = Fixture::new("", GITHUB);
    f.local_settings(json!({ "sandbox": { "allowUnsandboxedCommands": true } }));
    let r = f.verify();
    expect(&r, "sandbox", Status::Fail);
    expect_detail(
        &r,
        "sandbox",
        "sandbox.allowUnsandboxedCommands is true in .claude/settings.local.json, so a command can retry outside the sandbox",
    );
    // A user-level false holds against the repository's true.
    f.user_settings(json!({ "sandbox": { "allowUnsandboxedCommands": false } }));
    let r = f.verify();
    expect(&r, "sandbox", Status::Pass);
}

#[test]
fn file_isolation_off_in_user_settings_fails() {
    let f = Fixture::new("", GITHUB);
    f.user_settings(json!({ "sandbox": { "filesystem": { "disabled": true } } }));
    let r = f.verify();
    expect(&r, "sandbox", Status::Fail);
    expect_detail(
        &r,
        "sandbox",
        &format!(
            "sandbox.filesystem.disabled in {} turns off file isolation",
            f.home.join(".claude/settings.json").display()
        ),
    );
    // In the repository it doesn't count: Claude Code ignores it there.
    let f = Fixture::new("", GITHUB);
    f.local_settings(json!({ "sandbox": { "filesystem": { "disabled": true } } }));
    expect(&f.verify(), "sandbox", Status::Pass);
}

#[test]
fn weakening_settings_warn() {
    let f = Fixture::new("", GITHUB);
    f.user_settings(json!({ "sandbox": {
        "enableWeakerNestedSandbox": true,
        "network": { "allowLocalBinding": true }
    } }));
    let r = f.verify();
    expect(&r, "sandbox", Status::Warn);
    let d = detail(&r, "sandbox");
    assert!(
        d.contains("sandbox.enableWeakerNestedSandbox is on in")
            && d.contains("sandbox.network.allowLocalBinding is on in")
            && d.contains("which weakens the sandbox"),
        "{d}"
    );
    assert_eq!(r.exit_code(), 0);
}

#[test]
fn an_unreadable_claude_version_warns() {
    let f = Fixture::new("", GITHUB);
    f.tool("claude", "echo weird");
    let r = f.verify();
    expect(&r, "sandbox", Status::Warn);
    expect_detail(&r, "sandbox", "can't read the Claude Code version `weird`");
    assert_eq!(r.claude_code.as_deref(), Some("weird"));
}

#[test]
fn a_missing_socat_fails_on_linux() {
    let f = Fixture::new("", GITHUB);
    fs::remove_file(f.bin.join("socat")).unwrap();
    let mut ctx = f.ctx(Platform::Linux);
    // Only the stand-ins, so the machine's own socat can't stand in.
    ctx.vars.insert("PATH".into(), f.bin.display().to_string());
    let r = verify(&ctx, &Options::default()).unwrap();
    expect(&r, "sandbox", Status::Fail);
    expect_detail(
        &r,
        "sandbox",
        "bubblewrap or socat is missing, so the sandbox can't start",
    );
}

#[test]
fn a_bwrap_under_the_project_is_ignored() {
    let f = Fixture::new("", GITHUB);
    let planted = f.root.join("target/bin");
    f.tool_in(&planted, "bwrap", "exit 1");
    let mut ctx = f.ctx(Platform::Linux);
    ctx.vars
        .insert("PATH".into(), format!("{}:{}", planted.display(), f.path()));
    let r = verify(&ctx, &Options::default()).unwrap();
    expect(&r, "sandbox", Status::Warn);
    expect_detail(
        &r,
        "sandbox",
        &format!(
            "ignored `bwrap` at {} (inside the project): an agent can put programs there",
            planted.join("bwrap").display()
        ),
    );
    assert!(
        !detail(&r, "sandbox").contains("can't create a sandbox"),
        "the planted bwrap ran: {}",
        detail(&r, "sandbox")
    );
}

#[test]
fn an_unknown_platform_warns() {
    let f = Fixture::new("", GITHUB);
    let r = f.verify_on(Platform::Other, Options::default());
    assert_eq!(r.platform, "other");
    expect(&r, "sandbox", Status::Warn);
    expect_detail(
        &r,
        "sandbox",
        "unknown platform: can't tell whether the sandbox runs",
    );
    // A warning leaves the sandbox in effect for the push verdict.
    expect(&r, "push-boundary", Status::Pass);
}

#[test]
fn a_project_below_the_git_root_warns() {
    let f = Fixture::nested("", GITHUB);
    let r = f.verify();
    expect(&r, "sandbox", Status::Warn);
    expect_detail(
        &r,
        "sandbox",
        &format!(
            "mezha.toml is not at the git root ({}); Claude Code reads project settings only from the directory it starts in",
            f.repo.display()
        ),
    );
    assert!(
        checks_common::check(&r, "sandbox")
            .fix
            .as_deref()
            .is_some_and(|fix| fix.contains(&format!("Start Claude Code in {}", f.root.display()))),
        "{:?}",
        checks_common::check(&r, "sandbox").fix
    );
}

#[test]
fn a_custom_sandbox_proxy_makes_reach_unknown() {
    let f = Fixture::new("\"github.com\"", GITHUB);
    f.user_settings(json!({ "sandbox": { "network": { "httpProxyPort": 8080 } } }));
    let r = f.verify();
    expect(&r, "push-boundary", Status::Pass);
    let d = detail(&r, "push-boundary");
    assert!(
        d.starts_with(&format!(
            "sandboxed commands can reach github.com:443 (a custom sandbox proxy is set in {})",
            f.home.join(".claude/settings.json").display()
        )),
        "{d}"
    );
    assert!(d.contains("but no credential is reachable"), "{d}");
}

#[test]
fn a_broken_settings_file_warns() {
    let f = Fixture::new("", GITHUB);
    fs::write(f.root.join(".claude/settings.local.json"), "not json").unwrap();
    let r = f.verify();
    expect(&r, "settings-layers", Status::Warn);
    let d = detail(&r, "settings-layers");
    assert!(
        d.starts_with(".claude/settings.local.json is not valid JSON (")
            && d.contains("; Claude Code may ignore it or refuse to start"),
        "{d}"
    );
}

#[test]
fn managed_settings_that_disable_hooks_fail() {
    let f = Fixture::new("", GITHUB);
    f.managed_settings(json!({ "disableAllHooks": true }));
    let r = f.verify();
    expect(&r, "settings-layers", Status::Fail);
    expect_detail(
        &r,
        "settings-layers",
        &format!(
            "managed settings ({}) disable all hooks",
            f.managed.join("managed-settings.json").display()
        ),
    );
    assert!(
        checks_common::check(&r, "settings-layers")
            .fix
            .as_deref()
            .is_some_and(|fix| fix.contains("Ask your administrator")),
        "{:?}",
        checks_common::check(&r, "settings-layers").fix
    );

    let f = Fixture::new("", GITHUB);
    f.managed_settings(json!({ "allowManagedHooksOnly": true }));
    let r = f.verify();
    expect(&r, "settings-layers", Status::Fail);
    expect_detail(
        &r,
        "settings-layers",
        "blocks project hooks, mezha's gate included",
    );
}

#[test]
fn claude_config_dir_moves_auto_memory() {
    let f = Fixture::new("", GITHUB);
    let config = f.base.join("config");
    fs::create_dir_all(&config).unwrap();
    let r = f.verify_with(&[("CLAUDE_CONFIG_DIR", &config.display().to_string())]);
    expect(&r, "settings-layers", Status::Warn);
    expect_detail(
        &r,
        "settings-layers",
        "CLAUDE_CONFIG_DIR is set, so auto memory lives outside ~/.claude/projects",
    );
}

#[test]
fn a_git_guard_rail_overridden_locally_warns() {
    let f = Fixture::new("", GITHUB);
    f.local_settings(json!({ "env": { "GIT_TERMINAL_PROMPT": "1" } }));
    let r = f.verify();
    expect(&r, "settings-layers", Status::Warn);
    expect_detail(
        &r,
        "settings-layers",
        "GIT_TERMINAL_PROMPT in .claude/settings.local.json overrides mezha's git guard rail (advisory)",
    );
    // The same value as mezha's own is no override.
    f.local_settings(json!({ "env": { "GIT_TERMINAL_PROMPT": "0" } }));
    expect(&f.verify(), "settings-layers", Status::Pass);
}

#[test]
fn hooks_in_local_settings_warn() {
    let f = Fixture::new("", GITHUB);
    f.local_settings(json!({ "hooks": {
        "PreToolUse": [{ "hooks": [{ "type": "command", "command": "echo x" }] }],
        "Stop": []
    } }));
    let r = f.verify();
    expect(&r, "project-config", Status::Warn);
    expect_detail(
        &r,
        "project-config",
        ".claude/settings.local.json has hooks (PreToolUse, Stop): they run on your machine outside the sandbox",
    );
}

#[test]
fn approved_mcp_servers_are_named() {
    let f = Fixture::new("", GITHUB);
    f.write_json(
        &f.root.join(".mcp.json"),
        json!({ "mcpServers": {
            "tracker": { "command": "npx", "args": ["tracker-mcp"] },
            "notes": { "command": "notes-mcp" },
            "board": { "command": "board-mcp" },
        } }),
    );
    f.user_settings(json!({
        "enabledMcpjsonServers": ["tracker", "board", "notes"],
        "disabledMcpjsonServers": ["board"]
    }));
    let r = f.verify();
    expect(&r, "project-config", Status::Warn);
    expect_detail(
        &r,
        "project-config",
        ".mcp.json defines MCP server(s) board, notes, tracker (approved: notes, tracker)",
    );
}

#[test]
fn an_empty_or_broken_mcp_file() {
    let f = Fixture::new("", GITHUB);
    f.write_json(&f.root.join(".mcp.json"), json!({}));
    let r = f.verify();
    expect(&r, "project-config", Status::Pass);
    assert_eq!(
        detail(&r, "project-config"),
        "no MCP servers, command-running settings or redirecting env"
    );

    fs::write(f.root.join(".mcp.json"), "{not json").unwrap();
    let r = f.verify();
    expect(&r, "project-config", Status::Warn);
    assert_eq!(detail(&r, "project-config"), ".mcp.json is not valid JSON");
}
