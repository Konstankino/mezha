//! What the A/B runner and skill evals share: headless Claude Code sessions
//! in throwaway worktrees of the project, with the project's own settings,
//! sandbox and hooks, and checks that run in srt.

use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use mezha_memory::claude::{self, ENV_REMOVE, MIN_CLAUDE_CODE};
use mezha_memory::scan::escape;
use mezha_verify::Ctx;
use mezha_verify::layers::Layers;
use mezha_verify::probe::srt::Srt;
use mezha_verify::runner::{self, Next, Run};
use mezha_verify::scratch::{Scratch, nonce};
use serde_json::Value;

use crate::files::shell_word;
use crate::git::Git;

const IDENTITY: [&str; 4] = ["-c", "user.name=mezha", "-c", "user.email=mezha@localhost"];
/// A run's diff kept for the report, at most.
const MAX_DIFF: usize = 64 * 1024;

/// Refuses where these runs don't belong: inside Claude Code, which they
/// would nest in and spend from, and on native Windows.
pub fn refuse_here(command: &str) -> Result<()> {
    if crate::approve::inside_claude_code(&|k: &str| std::env::var(k).ok()) {
        bail!(
            "{command} refuses to run inside Claude Code: it starts Claude Code sessions and spends money. Run it in your own terminal."
        );
    }
    if cfg!(windows) {
        bail!("{command} runs on macOS, Linux and WSL2");
    }
    Ok(())
}

/// The trusted `claude` and its version, after checking that the
/// project's hooks will find `mezha`.
pub fn find_claude(ctx: &Ctx) -> Result<(PathBuf, String)> {
    let claude = ctx
        .which_trusted("claude")
        .path
        .context("claude is not on PATH (or only in a directory an agent could write)")?;
    let version = claude_version(ctx, &claude)?;
    if ctx.which_trusted("mezha").path.is_none() {
        bail!(
            "mezha isn't on PATH where agents can't write; the project's hooks call it and block every tool call without it"
        );
    }
    Ok((claude, version))
}

fn claude_version(ctx: &Ctx, claude: &Path) -> Result<String> {
    let out = runner::run(
        ctx,
        &Run {
            program: claude,
            args: &["--version"],
            cwd: &ctx.root,
            env: &[("DISABLE_AUTOUPDATER", "1")],
            remove: &ENV_REMOVE,
            stdin: b"",
            timeout: Duration::from_secs(30),
        },
    )?;
    let text = out.stdout.trim();
    let Some(v) = claude::parse_version(text) else {
        bail!(
            "`claude --version` said {}, not a version",
            shell_word(text)
        );
    };
    if v < MIN_CLAUDE_CODE {
        bail!("Claude Code {text} is too old; update it");
    }
    Ok(text.split_whitespace().next().unwrap_or("").to_string())
}

/// srt for checks, unless there are none or you chose to run them
/// unsandboxed.
pub fn find_srt(ctx: &Ctx, checks: bool, unsandboxed: bool) -> Result<Option<Srt>> {
    if !checks || unsandboxed {
        return Ok(None);
    }
    Ok(Some(mezha_verify::probe::srt::find(ctx).map_err(|e| {
        anyhow::anyhow!("{e}\nChecks run code the agent just wrote, so they run in srt. Install it, or pass --unsandboxed-check to run them unsandboxed in your own process.")
    })?))
}

/// Asks before spending up to `ceiling`, unless `yes`. False: you said no.
pub fn confirm_spend(yes: bool, what: &str, ceiling: f64) -> Result<bool> {
    if yes {
        return Ok(true);
    }
    if !std::io::stdin().is_terminal() {
        bail!("the {what} spends up to ${ceiling:.2}; pass --yes to start it without a terminal");
    }
    if !super::confirm("Start?")? {
        println!("Nothing ran.");
        return Ok(false);
    }
    Ok(true)
}

/// One headless session.
pub struct Session<'s> {
    /// The spec agent the session runs as, if any.
    pub agent: Option<&'s str>,
    pub prompt: &'s str,
    pub model: Option<&'s str>,
    pub max_turns: u32,
    pub budget_usd: f64,
    pub timeout: Duration,
}

/// The project, the tools and the base commit the runs share.
pub struct Bench<'a> {
    pub ctx: &'a Ctx,
    pub layers: &'a Layers,
    pub root: &'a Path,
    pub git: &'a Git<'a>,
    pub claude: PathBuf,
    /// Claude Code's version; a session reporting another one stops the run.
    pub version: String,
    pub srt: Option<Srt>,
    pub base: String,
    /// The project's place in the repository: `""` or `sub/dir/`.
    pub prefix: String,
    /// Outside ~/.mezha, where the project's own rules refuse writes.
    pub scratch: Scratch,
}

impl Bench<'_> {
    /// Runs `body` in a fresh worktree of the base, after `prepare` changed
    /// it and a commit with `message` recorded what `prepare` staged, so
    /// every run's HEAD looks the same to the model. Both get the worktree
    /// and the project's directory in it. The worktree is removed
    /// afterwards.
    pub fn in_worktree<T>(
        &self,
        message: &str,
        prepare: impl FnOnce(&Path, &Path) -> Result<()>,
        body: impl FnOnce(&Path, &Path) -> Result<T>,
    ) -> Result<T> {
        let git = self.git;
        // A neutral name: the cwd is in the model's prompt.
        let wt = self.scratch.path().join(format!("run-{}", &nonce()?[..12]));
        let wt_text = wt.to_string_lossy().into_owned();
        git.out(
            self.root,
            &[
                "worktree", "add", "--quiet", "--detach", &wt_text, &self.base,
            ],
        )?;
        let result = self.prepared(&wt, message, prepare, body);
        let _ = git.out(self.root, &["worktree", "remove", "--force", &wt_text]);
        result
    }

    /// [`Self::in_worktree`] in a clone of the repository instead: Claude
    /// Code reads a linked worktree's skills from the main checkout, so a
    /// skill removed from a worktree is still there. The clone borrows the
    /// repository's objects (`--shared`), forgets where it came from, and
    /// keeps its commits to itself. The clone and the directory Claude Code
    /// keeps for it under `~/.claude/projects` are removed afterwards.
    pub fn in_clone<T>(
        &self,
        message: &str,
        prepare: impl FnOnce(&Path, &Path) -> Result<()>,
        body: impl FnOnce(&Path, &Path) -> Result<T>,
    ) -> Result<T> {
        let git = self.git;
        let top = git.out(self.root, &["rev-parse", "--show-toplevel"])?;
        let dir = self.scratch.path().join(format!("run-{}", &nonce()?[..12]));
        let dir_text = dir.to_string_lossy().into_owned();
        git.out(
            self.root,
            &[
                "clone",
                "--quiet",
                "--shared",
                "--no-checkout",
                "--",
                top.trim(),
                &dir_text,
            ],
        )?;
        let result = (|| {
            git.out(&dir, &["remote", "remove", "origin"])?;
            git.out(&dir, &["checkout", "--quiet", "--detach", &self.base])?;
            self.prepared(&dir, message, prepare, body)
        })();
        if let (Some(home), Ok(real)) = (&self.ctx.home, std::fs::canonicalize(&dir)) {
            let project = self.project_in(&real);
            let config = mezha_memory::transcripts::config_dir(
                |k| self.ctx.var(k).map(str::to_string),
                home,
            );
            let _ = std::fs::remove_dir_all(config.join("projects").join(
                mezha_memory::transcripts::project_dir_name(&project.to_string_lossy()),
            ));
        }
        let _ = std::fs::remove_dir_all(&dir);
        result
    }

    /// `prepare`, the commit, and `body`, in a fresh checkout at `dir`.
    fn prepared<T>(
        &self,
        dir: &Path,
        message: &str,
        prepare: impl FnOnce(&Path, &Path) -> Result<()>,
        body: impl FnOnce(&Path, &Path) -> Result<T>,
    ) -> Result<T> {
        // The real path: srt and the session compare paths as the kernel
        // sees them (`/tmp` is `/private/tmp` on macOS).
        let dir = std::fs::canonicalize(dir)?;
        let project = self.project_in(&dir);
        prepare(&dir, &project)?;
        let mut commit = IDENTITY.to_vec();
        commit.extend([
            "commit",
            "--quiet",
            "--no-verify",
            "--allow-empty",
            "-m",
            message,
        ]);
        self.git.out(&dir, &commit)?;
        body(&dir, &project)
    }

    /// The project's directory in a checkout of the repository.
    fn project_in(&self, checkout: &Path) -> PathBuf {
        match self.prefix.trim_end_matches('/') {
            "" => checkout.to_path_buf(),
            prefix => checkout.join(prefix),
        }
    }

    /// Removes what's left of worktrees a stopped run didn't remove.
    pub fn prune(&self) {
        let _ = self.git.out(self.root, &["worktree", "prune"]);
    }

    /// A session with the project's own settings, sandbox and hooks, in
    /// acceptEdits, as in real use. Auto memory stays readable (Claude Code
    /// turns agent memory off with it) but can't be written: every worktree
    /// of the repository shares it, so one run's notes would reach the
    /// next. Every event goes to `on_event`.
    pub fn session(
        &self,
        cwd: &Path,
        s: &Session<'_>,
        mut on_event: impl FnMut(&Value),
    ) -> Result<claude::Outcome> {
        let turns = s.max_turns.to_string();
        let budget = format!("{:.2}", s.budget_usd);
        let no_auto_memory = serde_json::json!({
            "permissions": { "deny": [mezha_render::settings::AUTO_MEMORY_DENY] }
        })
        .to_string();
        let mut args = vec!["-p"];
        if let Some(agent) = s.agent {
            args.extend(["--agent", agent]);
        }
        args.extend([
            "--output-format",
            "stream-json",
            "--verbose",
            "--permission-mode",
            "acceptEdits",
            "--permission-prompts",
            "none",
            "--strict-mcp-config",
            "--max-turns",
            &turns,
            "--max-budget-usd",
            &budget,
            "--no-session-persistence",
            "--settings",
            &no_auto_memory,
        ]);
        if let Some(model) = s.model {
            args.extend(["--model", model]);
        }
        let mut init: Option<Result<(), String>> = None;
        let mut result: Option<Value> = None;
        let out = runner::run_lines(
            self.ctx,
            &Run {
                program: &self.claude,
                args: &args,
                cwd,
                env: &[("DISABLE_AUTOUPDATER", "1")],
                remove: &ENV_REMOVE,
                stdin: s.prompt.as_bytes(),
                timeout: s.timeout,
            },
            |line| {
                let Ok(event) = serde_json::from_str::<Value>(line) else {
                    return Next::Continue;
                };
                match (
                    event.get("type").and_then(Value::as_str),
                    event.get("subtype").and_then(Value::as_str),
                ) {
                    (Some("system"), Some("init")) => {
                        let checked = check_init(&event, s.agent, &self.version);
                        let stop = checked.is_err();
                        init = Some(checked);
                        if stop {
                            return Next::Stop;
                        }
                    }
                    (Some("result"), _) => result = Some(event.clone()),
                    _ => {}
                }
                on_event(&event);
                Next::Continue
            },
        )?;
        match init {
            Some(Ok(())) => {}
            Some(Err(why)) => bail!("{why}"),
            None => bail!(
                "claude didn't report how it started (exit {:?}): {}",
                out.code,
                escape(out.stderr.trim())
            ),
        }
        let minutes = s.timeout.as_secs() / 60;
        Ok(match result {
            Some(event) => claude::read_outcome(&event),
            None if out.timed_out => claude::Outcome {
                failure: Some(format!("it ran longer than {minutes} minutes")),
                subtype: "timeout".into(),
                ..claude::Outcome::default()
            },
            None => claude::Outcome {
                failure: Some(format!("it ended without a result (exit {:?})", out.code)),
                subtype: "no-result".into(),
                ..claude::Outcome::default()
            },
        })
    }

    /// Runs a check in the worktree: in srt with the project's sandbox,
    /// unless you passed --unsandboxed-check.
    pub fn check(&self, cwd: &Path, check: &str, timeout: Duration) -> Result<bool> {
        let path = self.ctx.trusted_path();
        let out = match &self.srt {
            Some(srt) => {
                let settings =
                    mezha_verify::probe::srt::command_settings(self.ctx, self.layers, cwd);
                let file = self.scratch.write_new(
                    &format!("srt-{}.json", &nonce()?[..12]),
                    settings.to_string().as_bytes(),
                )?;
                let file = file.to_string_lossy().into_owned();
                runner::run(
                    self.ctx,
                    &Run {
                        program: &srt.program,
                        args: &["--settings", &file, "-c", check],
                        cwd,
                        env: &[("PATH", &path)],
                        remove: &mezha_verify::probe::srt::NODE_ENV,
                        stdin: b"",
                        timeout,
                    },
                )?
            }
            None => runner::run(
                self.ctx,
                &Run {
                    program: Path::new("/bin/sh"),
                    args: &["-c", check],
                    cwd,
                    env: &[("PATH", &path)],
                    remove: &[],
                    stdin: b"",
                    timeout,
                },
            )?,
        };
        Ok(out.success())
    }

    /// The run's changes in the project, `exclude` pathspecs left out,
    /// written to `to` for reading afterwards.
    pub fn save_diff(&self, wt: &Path, exclude: &[&str], to: &Path) {
        let git = self.git;
        let _ = git.out(wt, &["add", "-A"]);
        let mut args = vec![
            "diff",
            "--cached",
            "--no-color",
            "--no-ext-diff",
            "HEAD",
            "--",
            ".",
        ];
        let exclude: Vec<String> = exclude
            .iter()
            .map(|p| format!(":(exclude){}{p}", self.prefix))
            .collect();
        args.extend(exclude.iter().map(String::as_str));
        let diff = git.out(wt, &args).unwrap_or_default();
        let diff = mezha_memory::inbox::cut(&diff, MAX_DIFF);
        let _ = mezha_memory::write_private(to, diff.as_bytes());
    }
}

/// The session must run in acceptEdits, as `agent` when there is one, on
/// the Claude Code the run started with.
fn check_init(event: &Value, agent: Option<&str>, version: &str) -> Result<(), String> {
    let mode = event.get("permissionMode").and_then(Value::as_str);
    if mode != Some("acceptEdits") {
        return Err(format!(
            "the session runs in permission mode {}, not acceptEdits",
            mode.unwrap_or("(none)")
        ));
    }
    let agents = event.get("agents").and_then(Value::as_array);
    if let Some(agent) = agent
        && agents.is_some_and(|a| !a.iter().any(|n| n.as_str() == Some(agent)))
    {
        return Err(format!(
            "Claude Code doesn't know agent `{agent}` in the worktree; is .claude/agents/{agent}.md committed? (`mezha compile`)"
        ));
    }
    match event.get("claude_code_version").and_then(Value::as_str) {
        Some(v) if v != version => Err(format!(
            "Claude Code changed from {version} to {v} during the run; start again"
        )),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn init_must_show_the_mode_agent_and_version() {
        let ok = json!({"permissionMode": "acceptEdits", "agents": ["implementer"], "claude_code_version": "2.1.285"});
        assert_eq!(check_init(&ok, Some("implementer"), "2.1.285"), Ok(()));
        assert_eq!(check_init(&ok, None, "2.1.285"), Ok(()));
        assert!(check_init(&ok, Some("explorer"), "2.1.285").is_err());
        assert!(
            check_init(&ok, None, "2.1.286")
                .unwrap_err()
                .contains("changed from 2.1.286 to 2.1.285")
        );
        assert!(check_init(&json!({"permissionMode": "default"}), None, "2.1.285").is_err());
    }
}
