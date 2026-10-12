//! `branch-protection` end to end, with the stand-in `gh` answering from
//! recorded cases: remotes that name the same repository, more
//! repositories than are asked about, no `gh` at all, and verdicts that
//! warn or skip.

#![cfg(unix)]

use std::fs;

use mezha_verify::{Options, Platform, Status, verify};

mod checks_common;
use checks_common::{Fixture, GITHUB, detail, expect};

/// A WRITE user without push restrictions (viewerCanPush is true at WRITE).
fn as_writer(_: &str, text: String) -> String {
    text.replace("\"READ\"", "\"WRITE\"")
        .replace("\"viewerCanPush\": false", "\"viewerCanPush\": true")
}

#[test]
fn remotes_naming_the_same_repository_are_asked_once() {
    let f = Fixture::new("", GITHUB);
    f.git(&["remote", "add", "fork", "git@github.com:o/r.git"]);
    f.git(&["remote", "add", "ssh", "ssh://git@ssh.github.com:443/o/r"]);
    f.fake_gh("cli-cli", as_writer);
    let r = f.verify();
    expect(&r, "branch-protection", Status::Pass);
    let d = detail(&r, "branch-protection");
    assert_eq!(d.matches("o/r: ").count(), 1, "{d}");
    assert_eq!(
        d,
        "o/r: `trunk` can't be pushed to directly, and code owners must review"
    );
}

#[test]
fn only_three_repositories_are_asked_about() {
    let f = Fixture::new("", GITHUB);
    for n in 2..=4 {
        f.git(&[
            "remote",
            "add",
            &format!("r{n}"),
            &format!("https://github.com/o/r{n}.git"),
        ]);
    }
    f.fake_gh("cli-cli", as_writer);
    let r = f.verify();
    expect(&r, "branch-protection", Status::Pass);
    let d = detail(&r, "branch-protection");
    assert_eq!(d.matches("can't be pushed to directly").count(), 3, "{d}");
    assert!(d.ends_with("; not checked (only 3 are): o/r4"), "{d}");
}

#[test]
fn without_gh_protection_is_unknown() {
    let f = Fixture::new("", GITHUB);
    fs::remove_file(f.bin.join("gh")).unwrap();
    // Only the stand-ins and a real git, so a gh elsewhere can't stand in.
    f.link_real("git");
    let mut ctx = f.ctx(Platform::Linux);
    ctx.vars.insert("PATH".into(), f.bin.display().to_string());
    let r = verify(&ctx, &Options::default()).unwrap();
    expect(&r, "branch-protection", Status::Warn);
    assert_eq!(
        detail(&r, "branch-protection"),
        "gh isn't installed, so branch protection is unknown"
    );
    assert!(
        checks_common::check(&r, "branch-protection")
            .fix
            .as_deref()
            .is_some_and(|fix| fix.contains("gh auth login")),
        "{:?}",
        checks_common::check(&r, "branch-protection").fix
    );
    assert_eq!(r.exit_code(), 0);
}

#[test]
fn a_hidden_ruleset_leaves_protection_unknown() {
    let f = Fixture::new("", GITHUB);
    f.fake_gh("sandbox-runtime", |file, text| {
        if file.starts_with("ruleset-") && !file.contains("404") {
            "not json".to_string()
        } else {
            as_writer(file, text)
        }
    });
    let r = f.verify();
    expect(&r, "branch-protection", Status::Warn);
    let d = detail(&r, "branch-protection");
    assert!(
        d.starts_with("o/r: protection of `main` is unknown: ruleset 4126768 is hidden from you"),
        "{d}"
    );
}

#[test]
fn a_repository_without_a_default_branch_is_skipped() {
    let f = Fixture::new("", GITHUB);
    f.fake_gh("hello-world", |file, text| match file {
        "graphql.json" => {
            r#"{"data":{"repository":{"viewerPermission":"WRITE","defaultBranchRef":null}}}"#.into()
        }
        _ => text,
    });
    let r = f.verify();
    expect(&r, "branch-protection", Status::Skip);
    assert_eq!(
        detail(&r, "branch-protection"),
        "o/r: the repository has no default branch yet"
    );
}

#[test]
fn a_gh_that_fails_leaves_the_verdict_unknown_with_its_words() {
    let f = Fixture::new("", GITHUB);
    f.tool(
        "gh",
        "echo 'error connecting to api.github.com' >&2; exit 1",
    );
    let r = f.verify();
    expect(&r, "branch-protection", Status::Warn);
    let d = detail(&r, "branch-protection");
    assert!(
        d.contains("the default branch couldn't be read (error connecting to api.github.com)"),
        "{d}"
    );
}
