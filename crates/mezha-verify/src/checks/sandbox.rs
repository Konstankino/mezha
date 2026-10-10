//! `sandbox`: is Claude Code's sandbox in effect for this project, on this
//! machine? Without it nothing below the advisory gate stops a push.

use std::path::Path;
use std::time::Duration;

use serde_json::Value;

use crate::Options;
use crate::ctx::{Ctx, Platform};
use crate::layers::{Layer, Layers};
use crate::report::{Check, Findings, Kind};
use crate::runner::{Run, run};

/// The first Claude Code that honours `sandbox.credentials` deny entries
/// from project settings.
pub const MIN_CLAUDE_CODE: (u32, u32, u32) = (2, 1, 246);

pub struct Outcome {
    pub check: Check,
    /// The sandbox wraps the agent's commands.
    pub in_effect: bool,
}

fn remove_from(layer: &Layer) -> String {
    format!("Remove it from {}.", layer.label)
}

pub fn check(ctx: &Ctx, layers: &Layers, claude: Option<&str>, opts: &Options) -> Outcome {
    let mut f = Findings::default();
    let check = Check::new("sandbox", "Claude Code's sandbox", Kind::Boundary);

    match layers.winner_for_loosening("/sandbox/enabled", &Value::Bool(false)) {
        Some((Value::Bool(true), _)) => {}
        Some((v, layer)) => f.fail(
            format!("sandbox.enabled is {v} in {}", layer.label),
            remove_from(layer),
        ),
        None => f.fail(
            "sandbox.enabled is not set",
            "Set policy.sandbox = true in mezha.toml and run `mezha compile`.",
        ),
    }
    if let Some((Value::Bool(false), layer)) =
        layers.winner_for_loosening("/sandbox/failIfUnavailable", &Value::Bool(false))
    {
        f.fail(
            format!(
                "sandbox.failIfUnavailable is false in {}, so commands run unsandboxed when the sandbox can't start",
                layer.label
            ),
            remove_from(layer),
        );
    }
    // A false from user or managed settings holds against any repository true.
    let held_false = layers
        .every("/sandbox/allowUnsandboxedCommands")
        .any(|(v, l)| v == &Value::Bool(false) && !l.scope.is_repository());
    if !held_false
        && let Some((Value::Bool(true), layer)) =
            layers.winner_for_loosening("/sandbox/allowUnsandboxedCommands", &Value::Bool(true))
    {
        f.fail(
            format!(
                "sandbox.allowUnsandboxedCommands is true in {}, so a command can retry outside the sandbox",
                layer.label
            ),
            remove_from(layer),
        );
    }
    for (entry, layer) in layers.strings("/sandbox/excludedCommands") {
        if layers.loosens(layer) {
            f.fail(
                format!(
                    "`{entry}` runs outside the sandbox (excludedCommands in {})",
                    layer.label
                ),
                remove_from(layer),
            );
        }
    }
    for (v, layer) in layers.every("/sandbox/filesystem/disabled") {
        if v == &Value::Bool(true) && !layer.scope.is_repository() {
            f.fail(
                format!(
                    "sandbox.filesystem.disabled in {} turns off file isolation",
                    layer.label
                ),
                remove_from(layer),
            );
        }
    }
    for key in [
        "/sandbox/enableWeakerNestedSandbox",
        "/sandbox/enableWeakerNetworkIsolation",
        "/sandbox/network/allowAllUnixSockets",
        "/sandbox/network/allowLocalBinding",
    ] {
        if let Some((Value::Bool(true), layer)) =
            layers.winner_for_loosening(key, &Value::Bool(true))
        {
            let name = key.trim_start_matches('/').replace('/', ".");
            f.warn(
                format!("{name} is on in {}, which weakens the sandbox", layer.label),
                Some(remove_from(layer)),
            );
        }
    }

    if !opts.project_only {
        platform(ctx, &mut f);
        if let Some(note) = ctx.which_trusted("claude").skipped_note("claude") {
            f.warn(note, None);
        }
        match claude {
            None => f.warn(
                "the `claude` CLI isn't on PATH, so its version is unknown",
                Some(format!(
                    "Claude Code {}.{}.{} or later honours the credential settings mezha writes.",
                    MIN_CLAUDE_CODE.0, MIN_CLAUDE_CODE.1, MIN_CLAUDE_CODE.2
                )),
            ),
            Some(version) => match parse_version(version) {
                Some(v) if v >= MIN_CLAUDE_CODE => {}
                Some(_) => f.fail(
                    format!(
                        "Claude Code {version} ignores credential settings from the project (needs {}.{}.{})",
                        MIN_CLAUDE_CODE.0, MIN_CLAUDE_CODE.1, MIN_CLAUDE_CODE.2
                    ),
                    "Update Claude Code (`claude update`).",
                ),
                None => f.warn(format!("can't read the Claude Code version `{version}`"), None),
            },
        }
        let git_root = mezha_broker::repo_root(&ctx.root);
        let root = std::fs::canonicalize(&ctx.root).unwrap_or_else(|_| ctx.root.clone());
        if git_root != root {
            f.warn(
                format!(
                    "mezha.toml is not at the git root ({}); Claude Code reads project settings only from the directory it starts in",
                    git_root.display()
                ),
                Some(format!("Start Claude Code in {}.", root.display())),
            );
        }
    }

    let in_effect = f.status() != crate::report::Status::Fail;
    Outcome {
        check: f.into_check(check, "on, strict, and available on this machine"),
        in_effect,
    }
}

fn platform(ctx: &Ctx, f: &mut Findings) {
    match ctx.platform {
        Platform::MacOs => {
            if !Path::new("/usr/bin/sandbox-exec").exists() {
                f.fail(
                    "/usr/bin/sandbox-exec is missing, so the sandbox can't start",
                    "Reinstall macOS command-line tools or check system integrity.",
                );
            }
        }
        Platform::Linux | Platform::Wsl2 => {
            let mut found = |name: &str| {
                let found = ctx.which_trusted(name);
                if let Some(note) = found.skipped_note(name) {
                    f.warn(note, None);
                }
                found.path
            };
            let bwrap = found("bwrap");
            let socat = found("socat");
            let unshare = found("unshare");
            if bwrap.is_none() || socat.is_none() {
                f.fail(
                    "bubblewrap or socat is missing, so the sandbox can't start",
                    "Install them (apt install bubblewrap socat).",
                );
            } else if let Some(bwrap) = bwrap {
                bubblewrap(ctx, &bwrap, unshare.as_deref(), f);
            }
        }
        Platform::Wsl1 => f.fail(
            "WSL1 has no sandbox",
            "Convert the distribution to WSL2 (wsl --set-version <distro> 2).",
        ),
        Platform::Windows => f.fail(
            "native Windows has no sandbox, so every gate is advisory",
            "Run Claude Code (and mezha verify) inside WSL2.",
        ),
        Platform::Other => f.warn(
            "unknown platform: can't tell whether the sandbox runs",
            None,
        ),
    }
}

/// bwrap the way srt starts it: its own user and pid namespaces, the host
/// read-only, a fresh `/proc`.
const BWRAP_ARGS: [&str; 10] = [
    "--unshare-user",
    "--unshare-pid",
    "--die-with-parent",
    "--ro-bind",
    "/",
    "/",
    "--dev",
    "/dev",
    "--proc",
    "/proc",
];

/// Can bwrap start a sandbox here, and can a process inside it still make
/// a user namespace of its own? srt's seccomp helper does that before it
/// applies the filter that blocks unix sockets, and `unshare -r`
/// (util-linux) does the same: a new user namespace, `setgroups` denied,
/// the caller's id mapped. On Ubuntu 24.04 and later the stock
/// `bwrap-userns-restrict` AppArmor profile lets bwrap itself start but
/// strips the capabilities the nested namespace needs, and bwrap 0.9.0
/// clears the bounding set; either way Claude Code's sandbox then fails to
/// start, or runs without the filter.
fn bubblewrap(ctx: &Ctx, bwrap: &Path, unshare: Option<&Path>, f: &mut Findings) {
    let inside = |command: &[&str]| {
        let args: Vec<&str> = BWRAP_ARGS
            .iter()
            .copied()
            .chain(command.iter().copied())
            .collect();
        run(
            ctx,
            &Run {
                program: bwrap,
                args: &args,
                cwd: &ctx.root,
                env: &[],
                remove: &[],
                stdin: b"",
                timeout: Duration::from_secs(5),
            },
        )
        .is_ok_and(|o| o.success())
    };
    if !inside(&["true"]) {
        f.fail(
            "bubblewrap is installed but can't create a sandbox",
            "On Ubuntu 24.04 and later, allow unprivileged user namespaces for bwrap (kernel.apparmor_restrict_unprivileged_userns); in a container, see Claude Code's sandboxing docs.",
        );
        return;
    }
    match unshare {
        None => f.warn(
            "can't tell whether a process inside bubblewrap can make a user namespace of its own, which srt's seccomp filter needs: `unshare` (util-linux) isn't on PATH",
            None,
        ),
        Some(unshare) => {
            let unshare = unshare.to_string_lossy();
            if !inside(&[&unshare, "-r", "true"]) {
                f.fail(
                    "bubblewrap runs, but a process inside it can't make a user namespace of its own, which srt's seccomp filter needs: Claude Code's sandbox won't start, or runs without the filter that blocks unix sockets",
                    "Replace the stock bwrap-userns-restrict AppArmor profile (Ubuntu 24.04 and later) with one that lets bwrap and what it starts create user namespaces, or set kernel.apparmor_restrict_unprivileged_userns=0, which also lowers the host's own hardening.",
                );
            }
        }
    }
}

/// `2.1.285 (Claude Code)` → (2, 1, 285).
pub fn parse_version(text: &str) -> Option<(u32, u32, u32)> {
    let word = text.split_whitespace().next()?;
    let mut parts = word.split('.').map(|p| p.parse::<u32>().ok());
    Some((parts.next()??, parts.next()??, parts.next()??))
}

/// The installed Claude Code version, if `claude` is on PATH.
pub fn claude_version(ctx: &Ctx) -> Option<String> {
    let claude = ctx.which_trusted("claude").path?;
    let out = run(
        ctx,
        &Run {
            program: &claude,
            args: &["--version"],
            cwd: &ctx.root,
            env: &[],
            remove: &[],
            stdin: b"",
            timeout: Duration::from_secs(15),
        },
    )
    .ok()?;
    out.success()
        .then(|| {
            out.stdout
                .split_whitespace()
                .next()
                .unwrap_or("")
                .to_string()
        })
        .filter(|v| !v.is_empty())
}

#[cfg(test)]
mod tests {
    use super::parse_version;

    #[test]
    fn versions() {
        assert_eq!(parse_version("2.1.285 (Claude Code)"), Some((2, 1, 285)));
        assert_eq!(parse_version("2.1.246"), Some((2, 1, 246)));
        assert_eq!(parse_version("weird"), None);
        assert!(parse_version("2.1.245").unwrap() < super::MIN_CLAUDE_CODE);
    }
}
