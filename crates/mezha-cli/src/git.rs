//! git as mezha's dream and A/B commands run it: the trusted binary, the
//! repository's hooks off, and no config from the environment.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use mezha_memory::scan::escape;
use mezha_verify::Ctx;
use mezha_verify::runner::{self, Run};

/// The commit to start from: `--base`, else `origin/HEAD`, else `HEAD`.
pub fn resolve_base(git: &Git, root: &Path, base: Option<&str>) -> Result<(String, String)> {
    if let Some(base) = base {
        if base.starts_with('-') {
            bail!("--base `{base}` is not a revision");
        }
        let sha = git
            .out(
                root,
                &[
                    "rev-parse",
                    "--verify",
                    "--quiet",
                    &format!("{base}^{{commit}}"),
                ],
            )
            .with_context(|| format!("--base {base} is not a commit"))?;
        return Ok((sha.trim().to_string(), base.to_string()));
    }
    if let Ok(sha) = git.out(
        root,
        &[
            "rev-parse",
            "--verify",
            "--quiet",
            "refs/remotes/origin/HEAD^{commit}",
        ],
    ) {
        let name = git
            .out(
                root,
                &["symbolic-ref", "--short", "refs/remotes/origin/HEAD"],
            )
            .map(|n| n.trim().to_string())
            .unwrap_or_else(|_| "origin/HEAD".into());
        return Ok((sha.trim().to_string(), name));
    }
    let sha = git
        .out(root, &["rev-parse", "--verify", "--quiet", "HEAD^{commit}"])
        .context("the repository has no commits yet")?;
    let name = git
        .out(root, &["symbolic-ref", "--short", "--quiet", "HEAD"])
        .map(|n| n.trim().to_string())
        .unwrap_or_else(|_| "HEAD".into());
    eprintln!("note: no origin/HEAD, so mezha starts from {name}");
    Ok((sha.trim().to_string(), name))
}

/// git with the repository's hooks off and no config from the environment.
/// Not a directory, so git finds no hooks in it.
#[cfg(unix)]
const NO_HOOKS: &str = "/dev/null";
#[cfg(not(unix))]
const NO_HOOKS: &str = "NUL";

pub struct Git<'a> {
    ctx: &'a Ctx,
    program: PathBuf,
    hooks_path: String,
}

impl<'a> Git<'a> {
    /// The trusted git, with `core.hooksPath` pointing where no hook can be:
    /// a path that isn't a directory runs none.
    pub fn new(ctx: &'a Ctx) -> Result<Self> {
        let found = ctx.which_trusted("git");
        if let Some(note) = found.skipped_note("git") {
            eprintln!("note: {note}");
        }
        let program = found
            .path
            .context("git is not on PATH (or only in a directory an agent could write)")?;
        Ok(Git {
            ctx,
            program,
            hooks_path: format!("core.hooksPath={}", NO_HOOKS),
        })
    }

    pub fn run(&self, cwd: &Path, args: &[&str], stdin: &[u8]) -> std::io::Result<runner::Output> {
        let mut full = vec!["-c", &self.hooks_path, "-c", "core.fsmonitor=false"];
        full.extend_from_slice(args);
        runner::run(
            self.ctx,
            &Run {
                program: &self.program,
                args: &full,
                cwd,
                env: &[("GIT_TERMINAL_PROMPT", "0")],
                remove: &[
                    "GIT_CONFIG_COUNT",
                    "GIT_CONFIG_PARAMETERS",
                    "GIT_DIR",
                    "GIT_WORK_TREE",
                    "GIT_INDEX_FILE",
                    "GIT_OBJECT_DIRECTORY",
                ],
                stdin,
                timeout: Duration::from_secs(300),
            },
        )
    }

    /// Stdout of a git command that must succeed.
    pub fn run_ok(&self, cwd: &Path, args: &[&str], stdin: &[u8]) -> Result<String, String> {
        let out = self
            .run(cwd, args, stdin)
            .map_err(|e| format!("git {}: {e}", args.join(" ")))?;
        if !out.success() {
            return Err(format!(
                "git {} failed: {}",
                args.first().unwrap_or(&""),
                escape(out.stderr.trim())
            ));
        }
        Ok(out.stdout)
    }

    pub fn out(&self, cwd: &Path, args: &[&str]) -> Result<String> {
        self.run_ok(cwd, args, b"").map_err(anyhow::Error::msg)
    }

    pub fn worktrees(&self, root: &Path) -> Result<Vec<PathBuf>> {
        let listed = self.out(root, &["worktree", "list", "--porcelain", "-z"])?;
        Ok(listed
            .split('\0')
            .filter_map(|l| l.strip_prefix("worktree "))
            .map(PathBuf::from)
            .filter(|p| p != root)
            .collect())
    }

    pub fn unmerged_dreams(&self, root: &Path, base: &str) -> Result<Vec<String>> {
        let listed = self.out(
            root,
            &[
                "for-each-ref",
                "--format=%(refname:short)",
                "--no-merged",
                base,
                "refs/heads/mezha/",
            ],
        )?;
        Ok(listed
            .lines()
            .filter(|b| b.starts_with("mezha/dream-"))
            .map(str::to_string)
            .collect())
    }

    pub fn fresh_branch(&self, root: &Path, name: &str) -> Result<String> {
        for n in 1..100 {
            let branch = if n == 1 {
                name.to_string()
            } else {
                format!("{name}-{n}")
            };
            let exists = self
                .run(
                    root,
                    &[
                        "rev-parse",
                        "--verify",
                        "--quiet",
                        &format!("refs/heads/{branch}"),
                    ],
                    b"",
                )?
                .success();
            if !exists {
                return Ok(branch);
            }
        }
        bail!("too many branches named {name}")
    }
}
