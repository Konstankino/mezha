//! `git-hygiene`: the generated files are committed (so clones and worktrees
//! get the gate) and personal files are ignored.

use std::time::Duration;

use crate::ctx::Ctx;
use crate::report::{Check, Findings, Kind};
use crate::runner::{Run, run};

const COMMITTED: [&str; 3] = [
    "mezha.toml",
    ".claude/settings.json",
    ".claude/.mezha-state.json",
];
const IGNORED: [&str; 2] = ["CLAUDE.local.md", ".claude/settings.local.json"];

pub fn check(ctx: &Ctx) -> Check {
    let check = Check::new("git-hygiene", "committed and ignored files", Kind::Hygiene);
    let mut f = Findings::default();
    let Some(git) = ctx.which("git") else {
        f.warn("git is not on PATH", None);
        return f.into_check(check, "");
    };
    let git_run = |args: &[&str]| {
        let mut full = vec!["-c", "core.fsmonitor=false"];
        full.extend_from_slice(args);
        run(
            ctx,
            &Run {
                program: &git,
                args: &full,
                cwd: &ctx.root,
                env: &[("GIT_TERMINAL_PROMPT", "0")],
                remove: &[],
                stdin: b"",
                timeout: Duration::from_secs(10),
            },
        )
    };

    let mut args = vec!["ls-files", "-z", "--"];
    args.extend(COMMITTED);
    let Ok(listed) = git_run(&args) else {
        f.warn("git couldn't run", None);
        return f.into_check(check, "");
    };
    if !listed.success() {
        f.warn(
            "not a git repository",
            Some("Commit the project to git.".into()),
        );
        return f.into_check(check, "");
    }
    let tracked: Vec<&str> = listed.stdout.split('\0').collect();
    let missing: Vec<&str> = COMMITTED
        .iter()
        .copied()
        .filter(|p| !tracked.contains(p))
        .collect();
    if !missing.is_empty() {
        f.warn(
            format!(
                "not committed: {}; clones and worktrees start without the gate",
                missing.join(", ")
            ),
            Some(format!("git add {} && git commit", missing.join(" "))),
        );
    }
    for path in IGNORED {
        // 0 = ignored, 1 = not ignored.
        if git_run(&["check-ignore", "-q", "--", path]).is_ok_and(|o| o.code == Some(1)) {
            f.warn(
                format!("{path} is not git-ignored, so personal settings could be committed"),
                Some(format!("Add {path} to .gitignore.")),
            );
        }
    }
    f.into_check(
        check,
        "generated files are committed, personal ones ignored",
    )
}
