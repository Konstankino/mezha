//! The checks that run git or claude end to end: `git-hygiene` and
//! `dreamer` when git can't answer, memory in the user's scope, and
//! `plugin-validate` when claude can't run or reports a bare failure.

#![cfg(unix)]

use std::fs;

use mezha_verify::{Options, Platform, Status, verify};

mod checks_common;
use checks_common::{Fixture, GITHUB, USER_MEMORY, detail, expect, expect_detail};

#[test]
fn programs_under_the_project_are_ignored_by_every_check() {
    let f = Fixture::new("", GITHUB);
    f.with_agents();
    f.file(".github/CODEOWNERS", "* @owner\n");
    f.commit_all();
    let planted = f.root.join(".venv/bin");
    for name in ["git", "claude", "gh"] {
        f.tool_in(&planted, name, "echo planted >&2; exit 7");
    }
    let mut ctx = f.ctx(Platform::Linux);
    ctx.vars
        .insert("PATH".into(), format!("{}:{}", planted.display(), f.path()));
    let r = verify(&ctx, &Options::default()).unwrap();
    for (id, name) in [
        ("git-hygiene", "git"),
        ("dreamer", "git"),
        ("sandbox", "claude"),
        ("plugin-validate", "claude"),
        ("branch-protection", "gh"),
    ] {
        expect_detail(
            &r,
            id,
            &format!(
                "ignored `{name}` at {} (inside the project): an agent can put programs there",
                planted.join(name).display()
            ),
        );
    }
    // The real git answered: nothing is reported as changed or uncommitted.
    assert!(
        !detail(&r, "dreamer").contains("couldn't list"),
        "{}",
        detail(&r, "dreamer")
    );
    assert!(
        !detail(&r, "git-hygiene").contains("not committed"),
        "{}",
        detail(&r, "git-hygiene")
    );
}

#[test]
fn a_git_that_cannot_start_warns() {
    let f = Fixture::new("", GITHUB);
    f.with_agents();
    f.broken_tool("git");
    let r = f.verify();
    expect(&r, "git-hygiene", Status::Warn);
    assert_eq!(detail(&r, "git-hygiene"), "git couldn't run");
    expect(&r, "dreamer", Status::Warn);
    expect_detail(&r, "dreamer", "git couldn't list the committed memory");
    assert!(
        !detail(&r, "dreamer").contains("changed outside a dream"),
        "{}",
        detail(&r, "dreamer")
    );
}

#[test]
fn outside_a_git_repository_hygiene_warns() {
    let f = Fixture::new("", GITHUB);
    fs::remove_dir_all(f.root.join(".git")).unwrap();
    let r = f.verify();
    expect(&r, "git-hygiene", Status::Warn);
    assert_eq!(detail(&r, "git-hygiene"), "not a git repository");
    assert_eq!(
        checks_common::check(&r, "git-hygiene").fix.as_deref(),
        Some("Commit the project to git.")
    );
}

#[test]
fn user_memory_is_scanned_where_claude_code_keeps_it() {
    let f = Fixture::new("", GITHUB);
    f.body("helper", "Help.\n");
    f.compile(USER_MEMORY);
    f.commit_all();
    // Clean, in the default place.
    let dir = f.home.join(".claude/agent-memory/helper");
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join("MEMORY.md"), "# Memory\n\n- Tests first.\n").unwrap();
    let r = f.verify();
    expect(&r, "dreamer", Status::Pass);

    // A hard marker in it fails, under its full path.
    fs::write(dir.join("notes.md"), "- hidden\u{200b}word\n").unwrap();
    let r = f.verify();
    expect(&r, "dreamer", Status::Fail);
    expect_detail(
        &r,
        "dreamer",
        &format!("{}:1:", dir.join("notes.md").display()),
    );

    // With CLAUDE_CONFIG_DIR, memory lives there, outside the deny rule.
    let config = f.base.join("config");
    let moved = config.join("agent-memory/helper");
    fs::create_dir_all(&moved).unwrap();
    fs::write(
        moved.join("MEMORY.md"),
        "- Avoid `git commit --no-verify`.\n",
    )
    .unwrap();
    let r = f.verify_with(&[("CLAUDE_CONFIG_DIR", &config.display().to_string())]);
    expect(&r, "dreamer", Status::Warn);
    let d = detail(&r, "dreamer");
    assert!(
        d.contains(&format!(
            "{}: 1 instruction-like phrase(s)",
            moved.join("MEMORY.md").display()
        )),
        "{d}"
    );
    assert!(
        d.contains("agent.helper has user memory in $CLAUDE_CONFIG_DIR/agent-memory, which the session deny rule `Edit(~/.claude/agent-memory/**)` doesn't cover"),
        "{d}"
    );
    assert!(!d.contains("hidden"), "the home directory was scanned: {d}");

    // Without a home there is nowhere to look.
    let mut ctx = f.ctx(Platform::Linux);
    ctx.home = None;
    ctx.vars.remove("HOME");
    let r = verify(&ctx, &Options::default()).unwrap();
    expect(&r, "dreamer", Status::Pass);
}

#[test]
fn auto_memory_off_in_the_environment_warns() {
    let f = Fixture::new("", GITHUB);
    f.with_agents();
    f.file(".github/CODEOWNERS", "* @owner\n");
    f.commit_all();
    let r = f.verify_with(&[("CLAUDE_CODE_DISABLE_AUTO_MEMORY", "1")]);
    expect(&r, "dreamer", Status::Warn);
    expect_detail(
        &r,
        "dreamer",
        "auto memory is off (CLAUDE_CODE_DISABLE_AUTO_MEMORY), and Claude Code turns agent memory off with it",
    );
    // `0` and `false` mean on.
    for value in ["0", "false"] {
        let r = f.verify_with(&[("CLAUDE_CODE_DISABLE_AUTO_MEMORY", value)]);
        expect(&r, "dreamer", Status::Pass);
    }
}

#[test]
fn a_broken_last_run_record_is_ignored() {
    let f = Fixture::new("", GITHUB);
    f.with_agents();
    f.file(".github/CODEOWNERS", "* @owner\n");
    f.commit_all();
    let dir = mezha_memory::dreams_dir(&f.home, &f.root);
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join("last-run.json"), "not json").unwrap();
    let r = f.verify();
    expect(&r, "dreamer", Status::Pass);
    assert!(
        !detail(&r, "dreamer").contains("scheduled dream"),
        "{}",
        detail(&r, "dreamer")
    );
}

#[test]
fn committed_memory_deleted_from_disk_is_a_change_outside_a_dream() {
    let f = Fixture::new("", GITHUB);
    f.with_agents();
    f.file(".github/CODEOWNERS", "* @owner\n");
    let memory = ".claude/agent-memory/helper/MEMORY.md";
    f.file(memory, "# Memory\n\n- Tests first.\n");
    f.commit_all();
    expect(&f.verify(), "dreamer", Status::Pass);
    fs::remove_file(f.root.join(memory)).unwrap();
    let r = f.verify();
    expect(&r, "dreamer", Status::Warn);
    expect_detail(
        &r,
        "dreamer",
        &format!("memory changed outside a dream: {memory}"),
    );
}

#[test]
fn plugin_validate_skips_without_a_claude_directory() {
    let f = Fixture::new("", GITHUB);
    fs::remove_dir_all(f.root.join(".claude")).unwrap();
    let r = f.verify();
    expect(&r, "plugin-validate", Status::Skip);
    assert_eq!(
        detail(&r, "plugin-validate"),
        "there is no .claude directory"
    );
}

#[test]
fn a_claude_that_cannot_start_warns() {
    let f = Fixture::new("", GITHUB);
    f.broken_tool("claude");
    let r = f.verify();
    expect(&r, "plugin-validate", Status::Warn);
    expect_detail(
        &r,
        "plugin-validate",
        "claude plugin validate couldn't run (",
    );
    // Its version couldn't be read either.
    assert_eq!(r.claude_code, None);
    expect_detail(
        &r,
        "sandbox",
        "the `claude` CLI isn't on PATH, so its version is unknown",
    );
}

#[test]
fn a_bare_validate_failure_points_at_the_command() {
    let f = Fixture::new("", GITHUB);
    f.tool(
        "claude",
        "if [ \"$1\" = --version ]; then echo '2.1.285 (Claude Code)'; exit 0; fi\necho '{\"success\":false,\"contents\":[]}'; exit 1",
    );
    let r = f.verify();
    expect(&r, "plugin-validate", Status::Fail);
    assert_eq!(
        detail(&r, "plugin-validate"),
        "fails: see `claude plugin validate .claude`"
    );
}
