//! `mezha approve`: a human grants gated commands for a while.
//!
//! The refusals here are a speed bump, not the boundary: the boundary is
//! that the store sits outside the project, where sandboxed commands can't
//! write.

use std::io::IsTerminal;
use std::path::Path;
use std::process::ExitCode;

use anyhow::{Context, Result, bail};
use mezha_broker::approvals;

/// Why `approve` won't grant or revoke here, if it won't. Only variables
/// Claude Code sets for its own processes count: people export others, such
/// as `CLAUDE_CODE_USE_BEDROCK`, in their shell profile.
pub fn refusal(var: impl Fn(&str) -> Option<String>, stdin_is_tty: bool) -> Option<&'static str> {
    let set = |k: &str| var(k).is_some_and(|v| !v.is_empty());
    if set("CLAUDECODE") || set("CLAUDE_CODE_ENTRYPOINT") {
        return Some(
            "mezha approve refuses to run inside Claude Code: an approval has to come from a \
             human in their own terminal",
        );
    }
    if !stdin_is_tty {
        return Some("mezha approve needs an interactive terminal");
    }
    None
}

pub fn run(path: &Path, minutes: u32, status: bool, revoke: bool) -> Result<ExitCode> {
    let home = mezha_broker::home_dir(|k| std::env::var(k).ok())
        .context("can't find the home directory")?;
    let dir = std::fs::canonicalize(path).with_context(|| path.display().to_string())?;
    let root = mezha_broker::repo_root(&dir);
    let now = super::now();

    if status {
        match approvals::remaining(&home, &root, now) {
            Some(secs) => println!(
                "Approved for {}: {} more minute(s).",
                root.display(),
                secs.div_ceil(60)
            ),
            None => println!("No active approval for {}.", root.display()),
        }
        return Ok(ExitCode::SUCCESS);
    }

    if let Some(why) = refusal(|k| std::env::var(k).ok(), std::io::stdin().is_terminal()) {
        bail!("{why}");
    }
    let sandbox_hint = |e: std::io::Error| {
        let hint = if e.kind() == std::io::ErrorKind::PermissionDenied {
            " (running inside a sandbox?)"
        } else {
            ""
        };
        anyhow::anyhow!("{}: {e}{hint}", approvals::store_dir(&home).display())
    };
    if revoke {
        if approvals::revoke(&home, &root).map_err(sandbox_hint)? {
            println!("Revoked the approval for {}.", root.display());
        } else {
            println!("There was no approval for {}.", root.display());
        }
        return Ok(ExitCode::SUCCESS);
    }
    approvals::grant(&home, &root, minutes, now).map_err(sandbox_hint)?;
    println!(
        "Approved gated commands for {} for {minutes} minute(s). `mezha approve --revoke` ends it early.\n\
         Sandboxed commands still can't reach your credentials, so a push from Claude Code fails by design: push from your own terminal.",
        root.display()
    );
    Ok(ExitCode::SUCCESS)
}

#[cfg(test)]
mod tests {
    use super::refusal;

    fn env<'a>(pairs: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
        move |k| {
            pairs
                .iter()
                .find(|(n, _)| *n == k)
                .map(|(_, v)| v.to_string())
        }
    }

    #[test]
    fn refuses_inside_claude_code() {
        assert!(refusal(env(&[("CLAUDECODE", "1")]), true).is_some());
        assert!(refusal(env(&[("CLAUDE_CODE_ENTRYPOINT", "cli")]), true).is_some());
    }

    #[test]
    fn refuses_without_a_terminal() {
        assert!(refusal(env(&[]), false).is_some());
    }

    #[test]
    fn other_claude_variables_are_fine() {
        assert_eq!(
            refusal(
                env(&[("CLAUDE_CODE_USE_BEDROCK", "1"), ("CLAUDECODE", "")]),
                true
            ),
            None
        );
    }
}
