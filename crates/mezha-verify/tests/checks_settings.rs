//! `settings-intact` end to end: generated files that are missing, stale
//! or edited, files mezha doesn't manage, and the gate probe against a
//! stand-in `mezha` that answers the hook calls from a script, behaving or
//! not.

#![cfg(unix)]

use std::fs;
use std::path::Path;

use mezha_verify::{Options, Platform, Status, verify};

mod checks_common;
use checks_common::{Fixture, GITHUB, WITH_BASH_AGENT, detail, expect, expect_detail, spec};

/// How the stand-in `mezha` behaves.
#[derive(Clone, Copy)]
struct FakeMezha {
    /// The hook protocol its `--version` claims.
    protocol: u32,
    /// The gate blocks what it should: `git push`, `mezha approve` and a
    /// WebFetch outside `fetch_allow`.
    gate_decides: bool,
    /// The gate writes an audit record for each call it decides.
    audits: bool,
    /// The agent-bash hook lets the in-scope command through.
    agent_decides: bool,
}

impl Default for FakeMezha {
    fn default() -> Self {
        FakeMezha {
            protocol: mezha_hooks::PROTOCOL,
            gate_decides: true,
            audits: true,
            agent_decides: true,
        }
    }
}

/// A stand-in `mezha` in `dir` that logs each hook call's arguments and
/// stdin to `<dir>/mezha.log` and answers as `how` says. Returns the
/// log's path.
fn fake_mezha(f: &Fixture, dir: &Path, how: FakeMezha) -> std::path::PathBuf {
    let log = dir.join("mezha.log");
    // The audit directory for this project, relative to the home the hook
    // runs with (the probe's scratch home).
    let audit_dir =
        mezha_hooks::audit::dir(Path::new("/h"), Some(&mezha_broker::repo_root(&f.root)));
    let audit_rel = audit_dir.strip_prefix("/h").unwrap().display().to_string();
    let audit = if how.audits {
        format!(
            r#"mkdir -p "$HOME/{audit_rel}" && echo '{{"v":1,"type":"admission"}}' >> "$HOME/{audit_rel}/20260101.jsonl""#
        )
    } else {
        String::new()
    };
    f.tool_in(
        dir,
        "mezha",
        &format!(
            r#"if [ "$1" = --version ]; then echo 'mezha 0.0.0-test (hook protocol {protocol})'; exit 0; fi
input=$(cat)
printf 'ARGS %s\nINPUT %s\n' "$*" "$input" >> '{log}'
case "$2" in
  approval-gate)
    {audit}
    case "$input" in
      *'"command":"git push'*|*'"command":"mezha approve'*|*'"tool_name":"WebFetch"'*) exit {block} ;;
    esac
    exit 0 ;;
  agent-bash)
    case "$input" in *mezha-verify-out-of-scope*) exit 2 ;; esac
    exit {in_scope} ;;
esac
echo "unexpected: $*" >&2; exit 9"#,
            protocol = how.protocol,
            log = log.display(),
            block = if how.gate_decides { 2 } else { 0 },
            in_scope = if how.agent_decides { 0 } else { 2 },
        ),
    );
    log
}

#[test]
fn a_missing_generated_file_fails() {
    let f = Fixture::new("", GITHUB);
    f.with_agents();
    fs::remove_file(f.root.join(".claude/agents/helper.md")).unwrap();
    let r = f.verify();
    expect(&r, "settings-intact", Status::Fail);
    expect_detail(&r, "settings-intact", ".claude/agents/helper.md is missing");
    assert_eq!(r.exit_code(), 1);
}

#[test]
fn output_of_an_older_spec_warns() {
    let f = Fixture::new("", GITHUB);
    // mezha.toml changed since the last compile, so the file on disk is
    // mezha's own output, only stale.
    fs::write(f.root.join("mezha.toml"), spec("\"github.com\"")).unwrap();
    let r = f.verify();
    expect(&r, "settings-intact", Status::Warn);
    expect_detail(
        &r,
        "settings-intact",
        ".claude/settings.json is mezha's output from an older mezha.toml",
    );
    assert!(
        !detail(&r, "settings-intact").contains("edited by hand"),
        "{}",
        detail(&r, "settings-intact")
    );
}

#[test]
fn rules_and_commands_in_subdirectories_are_unmanaged() {
    let f = Fixture::new("", GITHUB);
    f.file(".claude/rules/team/style.md", "Use tabs.\n");
    f.file(".claude/commands/ops/deploy.md", "Deploy.\n");
    let r = f.verify();
    expect(&r, "settings-intact", Status::Warn);
    expect_detail(
        &r,
        "settings-intact",
        "not managed by mezha: .claude/commands/ops/deploy.md, .claude/rules/team/style.md",
    );
}

#[test]
fn the_gate_probe_passes_with_a_behaving_mezha() {
    let f = Fixture::new("", GITHUB);
    let log = fake_mezha(&f, &f.bin, FakeMezha::default());
    let r = f.verify();
    expect(&r, "settings-intact", Status::Pass);
    assert_eq!(
        detail(&r, "settings-intact"),
        "match mezha.toml, and the gate blocks a push"
    );
    let log = fs::read_to_string(log).unwrap();
    let calls: Vec<&str> = log.lines().filter(|l| l.starts_with("ARGS")).collect();
    assert_eq!(calls.len(), 3, "{log}");
    for call in &calls {
        assert!(
            call.starts_with(&format!(
                "ARGS hook approval-gate --protocol {} --gate git push",
                mezha_hooks::PROTOCOL
            )),
            "{call}"
        );
    }
    for cmd in [
        "git push origin main",
        "mezha approve --minutes 5",
        "git status",
    ] {
        assert!(log.contains(&format!("\"command\":\"{cmd}\"")), "{log}");
    }
    // The events name the project and a session of their own.
    assert!(log.contains("\"session_id\":\"mezha-verify\""), "{log}");
    assert!(
        log.contains(&format!("\"cwd\":\"{}\"", f.root.display())),
        "{log}"
    );
}

#[test]
fn with_fetch_allow_the_gate_is_probed_with_a_webfetch_too() {
    let f = Fixture::new("", GITHUB);
    f.compile(&format!("{}fetch_allow = [\"docs.rs\"]\n", spec("")));
    let log = fake_mezha(&f, &f.bin, FakeMezha::default());
    let r = f.verify();
    expect(&r, "settings-intact", Status::Pass);
    let log = fs::read_to_string(log).unwrap();
    assert_eq!(log.matches("ARGS hook approval-gate").count(), 4, "{log}");
    assert!(log.contains("--fetch-only --fetch docs.rs"), "{log}");
    assert!(
        log.contains("\"tool_name\":\"WebFetch\"")
            && log.contains("\"url\":\"https://mezha-verify.invalid/\""),
        "{log}"
    );
}

#[test]
fn a_gate_that_lets_a_push_through_fails() {
    let f = Fixture::new("", GITHUB);
    fake_mezha(
        &f,
        &f.bin,
        FakeMezha {
            gate_decides: false,
            ..FakeMezha::default()
        },
    );
    let r = f.verify();
    expect(&r, "settings-intact", Status::Fail);
    expect_detail(
        &r,
        "settings-intact",
        "the gate doesn't behave: `git push origin main` gave exit 0, expected exit 2, `mezha approve --minutes 5` gave exit 0, expected exit 2",
    );
    assert_eq!(r.exit_code(), 1);
}

#[test]
fn a_gate_that_writes_no_audit_record_fails() {
    let f = Fixture::new("", GITHUB);
    fake_mezha(
        &f,
        &f.bin,
        FakeMezha {
            audits: false,
            ..FakeMezha::default()
        },
    );
    let r = f.verify();
    expect(&r, "settings-intact", Status::Fail);
    expect_detail(
        &r,
        "settings-intact",
        "the gate decided 3 calls but wrote 0 audit record(s)",
    );
}

#[test]
fn a_mezha_speaking_another_protocol_warns() {
    let f = Fixture::new("", GITHUB);
    let log = fake_mezha(
        &f,
        &f.bin,
        FakeMezha {
            protocol: mezha_hooks::PROTOCOL + 1,
            ..FakeMezha::default()
        },
    );
    let r = f.verify();
    expect(&r, "settings-intact", Status::Warn);
    expect_detail(
        &r,
        "settings-intact",
        &format!(
            "the `mezha` on PATH speaks a different hook protocol than this one (mezha 0.0.0-test (hook protocol {})), so Claude Code will block every tool call",
            mezha_hooks::PROTOCOL + 1
        ),
    );
    assert!(!log.exists(), "the gate was probed even so");
}

#[test]
fn a_mezha_on_path_that_is_not_this_one_warns() {
    let f = Fixture::new("", GITHUB);
    fake_mezha(&f, &f.bin, FakeMezha::default());
    let mut ctx = f.ctx(Platform::Linux);
    ctx.mezha_exe = Some(f.bin.join("claude"));
    let r = verify(&ctx, &Options::default()).unwrap();
    expect(&r, "settings-intact", Status::Warn);
    expect_detail(
        &r,
        "settings-intact",
        &format!(
            "the `mezha` on PATH ({}) is not the one running verify",
            f.bin.join("mezha").display()
        ),
    );
    // The same binary: nothing to say.
    ctx.mezha_exe = Some(f.bin.join("mezha"));
    let r = verify(&ctx, &Options::default()).unwrap();
    expect(&r, "settings-intact", Status::Pass);
}

#[test]
fn a_mezha_under_the_project_is_ignored() {
    let f = Fixture::new("", GITHUB);
    let planted = f.root.join("node_modules/.bin");
    // Were the planted one asked for its version, its protocol would warn.
    fake_mezha(
        &f,
        &planted,
        FakeMezha {
            protocol: 99,
            ..FakeMezha::default()
        },
    );
    fake_mezha(&f, &f.bin, FakeMezha::default());
    // A bash there is passed over the same way.
    f.tool_in(&planted, "bash", "exit 3");
    let mut ctx = f.ctx(Platform::Linux);
    ctx.vars
        .insert("PATH".into(), format!("{}:{}", planted.display(), f.path()));
    let r = verify(&ctx, &Options::default()).unwrap();
    expect(&r, "settings-intact", Status::Warn);
    // The only findings: the trusted ones answered, and the gate probe
    // passed.
    assert_eq!(
        detail(&r, "settings-intact"),
        format!(
            "ignored `mezha` at {planted}/mezha (inside the project): an agent can put programs there; ignored `bash` at {planted}/bash (inside the project): an agent can put programs there",
            planted = planted.display()
        )
    );
}

#[test]
fn on_native_windows_the_gate_is_not_probed() {
    let f = Fixture::new("", GITHUB);
    // On Windows a program is found through PATHEXT.
    f.tool(
        "mezha.EXE",
        &format!(
            "echo 'mezha 0.0.0-test (hook protocol {})'",
            mezha_hooks::PROTOCOL
        ),
    );
    let r = f.verify_on(Platform::Windows, Options::default());
    assert_eq!(r.platform, "windows");
    expect(&r, "settings-intact", Status::Warn);
    assert_eq!(
        detail(&r, "settings-intact"),
        "the gate probe doesn't run on native Windows yet"
    );
}

#[test]
fn without_bash_the_gate_is_not_probed() {
    let f = Fixture::new("", GITHUB);
    f.with_bash_agent();
    let log = fake_mezha(&f, &f.bin, FakeMezha::default());
    let mut ctx = f.ctx(Platform::Linux);
    // Only the stand-ins: no bash.
    ctx.vars.insert("PATH".into(), f.bin.display().to_string());
    let r = verify(&ctx, &Options::default()).unwrap();
    expect(&r, "settings-intact", Status::Warn);
    expect_detail(
        &r,
        "settings-intact",
        "bash is not on PATH, so the gate wasn't probed",
    );
    assert!(
        !log.exists(),
        "the gate or the agent's hook was probed without bash"
    );
}

impl Fixture {
    /// Compiles `WITH_BASH_AGENT`, writing its body file first.
    fn with_bash_agent(&self) {
        self.body("tester", "Run the tests.\n");
        self.compile(WITH_BASH_AGENT);
    }
}

#[test]
fn an_agents_bash_hook_is_probed_in_and_out_of_scope() {
    let f = Fixture::new("", GITHUB);
    f.with_bash_agent();
    let log = fake_mezha(&f, &f.bin, FakeMezha::default());
    let r = f.verify();
    expect(&r, "settings-intact", Status::Pass);
    let log = fs::read_to_string(log).unwrap();
    let agent_calls: Vec<&str> = log
        .lines()
        .filter(|l| l.starts_with("ARGS hook agent-bash"))
        .collect();
    assert_eq!(agent_calls.len(), 2, "{log}");
    assert!(
        agent_calls
            .iter()
            .all(|c| c.contains("--allow cargo test *")),
        "{agent_calls:?}"
    );
    assert!(log.contains("\"command\":\"cargo test\""), "{log}");
    assert!(
        log.contains("\"command\":\"mezha-verify-out-of-scope\""),
        "{log}"
    );
}

#[test]
fn an_agents_bash_hook_that_blocks_its_own_scope_fails() {
    let f = Fixture::new("", GITHUB);
    f.with_bash_agent();
    fake_mezha(
        &f,
        &f.bin,
        FakeMezha {
            agent_decides: false,
            ..FakeMezha::default()
        },
    );
    let r = f.verify();
    expect(&r, "settings-intact", Status::Fail);
    expect_detail(
        &r,
        "settings-intact",
        "an agent's Bash hook doesn't behave: .claude/agents/tester.md: `cargo test` gave exit 2, expected exit 0",
    );
}
