//! `mezha verify --probe`: side-effect-free probes inside Anthropic's
//! sandbox runtime (`srt`), started with the sandbox settings as mezha
//! reads them, so "an agent can't push" is shown where it can be.
//!
//! - The network leg runs `git push --dry-run URL :mezha-probe-<nonce>`
//!   once per (scheme, host, port). Deleting a ref that doesn't exist
//!   fails before anything is sent, even without `--dry-run`; the error
//!   that names the ref appears only after the server opened a push
//!   session. git runs outside the repository, from a scratch bare
//!   repository with no system or global config, because the project's
//!   `.git/config` is agent-writable and could steer the result.
//! - The credential leg checks which credential files a sandboxed command
//!   can read and which token variables it sees; it prints indices only.
//!
//! Scripts are constants; their inputs come from the environment.

pub mod classify;
pub mod plan;
pub mod srt;

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::creds::{self, Withheld};
use crate::ctx::Ctx;
use crate::gitcfg::GitConfig;
use crate::hosts::Remote;
use crate::layers::Layers;
use crate::runner::{Output, Run, run};
use crate::scratch::{self, Scratch};

pub use classify::Outcome;
pub use plan::Target;

/// The network leg's whole budget, and one run's at most.
const NETWORK_BUDGET: Duration = Duration::from_secs(60);
const RUN_TIMEOUT: Duration = Duration::from_secs(30);

/// Inside srt the script runs under `/bin/sh`, whatever shell srt uses.
const WRAPPER: &str = "exec /bin/sh -c \"$MEZHA_PROBE_SCRIPT\"";

/// The network probe. Inputs: `MEZHA_PROBE_GIT`, `_GIT_DIR`, `_URL`,
/// `_NONCE`, `_FILE` (`never`, or `always` in tests), `_DRY_RUN`
/// (`--dry-run`, or empty in tests), `_CAINFO`, `_CAPATH`.
pub const NETWORK_SCRIPT: &str = r#"unset NO_PROXY no_proxy GIT_CONFIG_COUNT GIT_CONFIG_PARAMETERS GIT_SSH GIT_SSH_VARIANT GIT_PROXY_COMMAND GIT_WORK_TREE GIT_NAMESPACE GIT_EXEC_PATH
for v in $(env | sed -n 's/^\(GIT_TRACE[A-Za-z0-9_]*\)=.*/\1/p'); do unset "$v"; done
GIT_TERMINAL_PROMPT=0 GIT_ASKPASS= SSH_ASKPASS= SSH_ASKPASS_REQUIRE=never LC_ALL=C
GIT_SSH_COMMAND="${GIT_SSH_COMMAND:-ssh} -o BatchMode=yes -o ConnectTimeout=10"
GIT_DIR="$MEZHA_PROBE_GIT_DIR" GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null
export GIT_TERMINAL_PROMPT GIT_ASKPASS SSH_ASKPASS SSH_ASKPASS_REQUIRE LC_ALL GIT_SSH_COMMAND GIT_DIR GIT_CONFIG_NOSYSTEM GIT_CONFIG_GLOBAL
set -- -c protocol.allow=never -c protocol.https.allow=always -c protocol.http.allow=always -c protocol.ssh.allow=always -c "protocol.file.allow=$MEZHA_PROBE_FILE" -c credential.helper= -c core.askPass= -c http.proxyAuthMethod=basic -c core.hooksPath=/dev/null
if [ -n "$MEZHA_PROBE_CAINFO" ]; then set -- "$@" -c "http.sslCAInfo=$MEZHA_PROBE_CAINFO"; fi
if [ -n "$MEZHA_PROBE_CAPATH" ]; then set -- "$@" -c "http.sslCAPath=$MEZHA_PROBE_CAPATH"; fi
"$MEZHA_PROBE_GIT" "$@" push $MEZHA_PROBE_DRY_RUN --no-verify --recurse-submodules=no "$MEZHA_PROBE_URL" ":mezha-probe-$MEZHA_PROBE_NONCE"
echo "MEZHA_PROBE_EXIT=$?" >&2
"#;

/// The credential probe. Inputs: `MEZHA_PROBE_FILES` and
/// `MEZHA_PROBE_VARS`, one per line. Prints `F<i>` for each readable,
/// non-empty file and `V<i>` for each set variable, then a closing marker.
pub const CREDENTIAL_SCRIPT: &str = r#"i=0
printf '%s\n' "$MEZHA_PROBE_FILES" | while IFS= read -r f; do
  if [ -n "$f" ] && [ -f "$f" ]; then
    case "$(head -c 1 "$f" 2>/dev/null | wc -c | tr -d ' ')" in 1) echo "F$i" ;; esac
  fi
  i=$((i+1))
done
j=0
printf '%s\n' "$MEZHA_PROBE_VARS" | while IFS= read -r v; do
  if [ -n "$v" ] && [ -n "$(printenv "$v")" ]; then echo "V$j"; fi
  j=$((j+1))
done
echo MEZHA_PROBE_DONE
"#;

/// srt, its settings in a private scratch directory (removed when this is
/// dropped, however verify ends), and what the settings mask.
pub struct Prepared {
    pub srt: srt::Srt,
    scratch: Scratch,
    settings: PathBuf,
    masked: srt::Masked,
}

impl Prepared {
    pub fn runtime(&self) -> String {
        format!("srt {}", self.srt.version)
    }
}

/// Finds srt, writes its settings and starts it once. An error means
/// `--probe` can't run (exit 2).
pub fn prepare(ctx: &Ctx, layers: &Layers) -> Result<Prepared, String> {
    let srt = srt::find(ctx)?;
    let scratch = Scratch::new("mezha-probe")
        .map_err(|e| format!("couldn't create a private scratch directory: {e}"))?;
    let (value, masked) = srt::settings(ctx, layers);
    let text = serde_json::to_string_pretty(&value).expect("settings serialize");
    let settings = scratch
        .write_new("srt-settings.json", text.as_bytes())
        .map_err(|e| format!("couldn't write srt's settings: {e}"))?;
    srt::start(ctx, &srt, &settings, scratch.path())?;
    Ok(Prepared {
        srt,
        scratch,
        settings,
        masked,
    })
}

/// What the probes showed.
#[derive(Debug, Clone, Default)]
pub struct Facts {
    pub network: Vec<NetResult>,
    /// Push URLs not probed (unsafe characters, or past the limit).
    pub unprobed: Vec<String>,
    /// Credentials a sandboxed command could read or see.
    pub proven: Vec<String>,
    /// Where srt and mezha's reading of the settings disagree.
    pub disagree: Vec<String>,
    /// Credentials the probe can't judge.
    pub unknown: Vec<String>,
    /// The credential leg finished.
    pub creds_checked: bool,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetResult {
    pub target: Target,
    pub outcome: Outcome,
}

/// How a probe script starts.
enum Launcher<'a> {
    Srt(&'a Prepared),
    /// Under `/bin/sh` with no sandbox, for tests.
    Direct,
}

/// Runs both legs.
pub fn run_all(
    ctx: &Ctx,
    prepared: &Prepared,
    git: Option<&GitConfig>,
    withheld: &Withheld,
) -> Facts {
    let mut facts = Facts {
        notes: vec![
            "the credential probe ran without the settings' `env` block, which Claude Code adds inside the sandbox".into(),
        ],
        ..Facts::default()
    };
    let launcher = Launcher::Srt(prepared);
    let urls = git.map(GitConfig::push_urls).unwrap_or_default();
    let (targets, unprobed) = plan::targets(&urls);
    facts.unprobed = unprobed;
    match ctx.which_trusted("git").path {
        Some(git_exe) => {
            let ca = git.map(trusted_ca).unwrap_or_default();
            facts.network = network(
                ctx,
                &launcher,
                &git_exe,
                prepared.scratch.path(),
                &targets,
                &ca,
                TestHook::default(),
            )
            .into_iter()
            .map(|(result, _)| result)
            .collect();
        }
        None if !targets.is_empty() => facts
            .notes
            .push("git isn't on PATH, so the network wasn't probed".into()),
        None => {}
    }
    credentials(
        ctx,
        &launcher,
        prepared.scratch.path(),
        git,
        withheld,
        &prepared.masked,
        &mut facts,
    );
    facts
}

/// `http.sslCAInfo` and `http.sslCAPath` from system and global config
/// only: the repository's own config is agent-writable.
fn trusted_ca(git: &GitConfig) -> (Option<String>, Option<String>) {
    let get = |key: &str| {
        git.entries
            .iter()
            .rev()
            .find(|e| e.key == key && matches!(e.scope.as_str(), "system" | "global"))
            .and_then(|e| e.value.clone())
            .filter(|v| !v.is_empty())
    };
    (get("http.sslcainfo"), get("http.sslcapath"))
}

fn launch(
    ctx: &Ctx,
    launcher: &Launcher<'_>,
    cwd: &Path,
    script: &str,
    vars: &[(&str, &str)],
    timeout: Duration,
) -> std::io::Result<Output> {
    let path = ctx.trusted_path();
    let remove: Vec<&str> = ctx
        .vars
        .keys()
        .map(String::as_str)
        .filter(|k| {
            k.starts_with("MEZHA_PROBE_") || k.starts_with("GIT_TRACE") || srt::NODE_ENV.contains(k)
        })
        .collect();
    let mut env: Vec<(&str, &str)> = vec![("PATH", &path), ("MEZHA_PROBE_SCRIPT", script)];
    env.extend_from_slice(vars);
    match launcher {
        Launcher::Srt(prepared) => {
            let settings = prepared.settings.to_string_lossy();
            run(
                ctx,
                &Run {
                    program: &prepared.srt.program,
                    args: &["--settings", &settings, "-c", WRAPPER],
                    cwd,
                    env: &env,
                    remove: &remove,
                    stdin: b"",
                    timeout,
                },
            )
        }
        Launcher::Direct => run(
            ctx,
            &Run {
                program: Path::new("/bin/sh"),
                args: &["-c", script],
                cwd,
                env: &env,
                remove: &remove,
                stdin: b"",
                timeout,
            },
        ),
    }
}

/// One probe per target within [`NETWORK_BUDGET`], each with what it
/// printed.
fn network(
    ctx: &Ctx,
    launcher: &Launcher<'_>,
    git: &Path,
    scratch: &Path,
    targets: &[Target],
    ca: &(Option<String>, Option<String>),
    test_hook: TestHook,
) -> Vec<(NetResult, String)> {
    if targets.is_empty() {
        return Vec::new();
    }
    let inconclusive = |why: &str| {
        targets
            .iter()
            .map(|t| {
                let outcome = Outcome::Inconclusive(why.to_string());
                (
                    NetResult {
                        target: t.clone(),
                        outcome,
                    },
                    String::new(),
                )
            })
            .collect()
    };
    let Ok(nonce) = scratch::nonce() else {
        return inconclusive("no randomness for the probe's name");
    };
    let git_dir = scratch.join("probe.git");
    if !init_bare(ctx, git, scratch, &git_dir) {
        return inconclusive("couldn't create a scratch repository");
    }
    let git_text = git.to_string_lossy();
    let git_dir_text = git_dir.to_string_lossy();
    let file = if test_hook.allow_file {
        "always"
    } else {
        "never"
    };
    let dry_run = if test_hook.real_push { "" } else { "--dry-run" };
    let started = Instant::now();
    let mut results = Vec::new();
    for target in targets {
        let left = NETWORK_BUDGET.saturating_sub(started.elapsed());
        let mut printed = String::new();
        let outcome = if left < Duration::from_secs(5) {
            Outcome::Inconclusive("the probe ran out of time".into())
        } else {
            let vars = [
                ("MEZHA_PROBE_GIT", git_text.as_ref()),
                ("MEZHA_PROBE_GIT_DIR", git_dir_text.as_ref()),
                ("MEZHA_PROBE_URL", target.url.as_str()),
                ("MEZHA_PROBE_NONCE", nonce.as_str()),
                ("MEZHA_PROBE_FILE", file),
                ("MEZHA_PROBE_DRY_RUN", dry_run),
                ("MEZHA_PROBE_CAINFO", ca.0.as_deref().unwrap_or("")),
                ("MEZHA_PROBE_CAPATH", ca.1.as_deref().unwrap_or("")),
            ];
            match launch(
                ctx,
                launcher,
                scratch,
                NETWORK_SCRIPT,
                &vars,
                left.min(RUN_TIMEOUT),
            ) {
                Ok(out) => {
                    printed = format!("{}\n{}", out.stdout, out.stderr);
                    if out.timed_out {
                        Outcome::Inconclusive("the probe timed out".into())
                    } else {
                        classify::classify(&printed, &nonce, target.scheme, ctx.platform)
                    }
                }
                Err(e) => Outcome::Inconclusive(format!("the probe couldn't start ({e})")),
            }
        };
        let result = NetResult {
            target: target.clone(),
            outcome,
        };
        results.push((result, printed));
    }
    results
}

/// `git init --bare` outside the sandbox and outside the project, with no
/// templates and no system or global config.
fn init_bare(ctx: &Ctx, git: &Path, cwd: &Path, dir: &Path) -> bool {
    let dir = dir.to_string_lossy();
    run(
        ctx,
        &Run {
            program: git,
            args: &["init", "--bare", "--quiet", "--template=", &dir],
            cwd,
            env: &[
                ("GIT_CONFIG_NOSYSTEM", "1"),
                ("GIT_CONFIG_GLOBAL", "/dev/null"),
            ],
            remove: &[
                "GIT_DIR",
                "GIT_CONFIG_COUNT",
                "GIT_CONFIG_PARAMETERS",
                "GIT_TEMPLATE_DIR",
            ],
            stdin: b"",
            timeout: Duration::from_secs(10),
        },
    )
    .is_ok_and(|o| o.success())
}

/// The network probe run with no sandbox of its own, for `--inside`,
/// where Claude Code's sandbox is already around this process.
pub(crate) fn network_here(
    ctx: &Ctx,
    targets: &[Target],
    git: Option<&GitConfig>,
) -> Vec<NetResult> {
    let inconclusive = |why: &str| {
        targets
            .iter()
            .map(|t| NetResult {
                target: t.clone(),
                outcome: Outcome::Inconclusive(why.to_string()),
            })
            .collect()
    };
    let Some(git_exe) = ctx.which_trusted("git").path else {
        return inconclusive("git isn't on PATH");
    };
    let Ok(scratch) = Scratch::new("mezha-inside") else {
        return inconclusive("no scratch directory");
    };
    let ca = git.map(trusted_ca).unwrap_or_default();
    network(
        ctx,
        &Launcher::Direct,
        &git_exe,
        scratch.path(),
        targets,
        &ca,
        TestHook::default(),
    )
    .into_iter()
    .map(|(result, _)| result)
    .collect()
}

/// A credential file that exists outside the sandbox.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialFile {
    pub path: PathBuf,
    pub label: String,
}

/// Credential files a push could use that exist outside the sandbox: ssh
/// keys, gh's hosts file (wherever it was moved), git's credential stores,
/// `.netrc`, hub's and glab's config, a `store` helper's file, and the
/// targets of symlinks among them.
pub fn credential_files(ctx: &Ctx, git: Option<&GitConfig>) -> Vec<CredentialFile> {
    let mut files: Vec<CredentialFile> = Vec::new();
    for path in credential_paths(ctx, git) {
        let text = path.to_string_lossy();
        if text.contains('\n') || !path.is_file() || files.iter().any(|f| f.path == path) {
            continue;
        }
        let label = label(ctx, &path);
        files.push(CredentialFile { path, label });
    }
    files
}

/// `~/x` for a path under home, else the path.
pub fn label(ctx: &Ctx, path: &Path) -> String {
    match ctx.home.as_ref().and_then(|h| path.strip_prefix(h).ok()) {
        Some(rest) => format!("~/{}", rest.display()),
        None => path.display().to_string(),
    }
}

/// Every place [`credential_files`] looks, whether or not something is
/// there (inside the sandbox a withheld file can look absent).
pub fn credential_paths(ctx: &Ctx, git: Option<&GitConfig>) -> Vec<PathBuf> {
    let mut paths: Vec<PathBuf> = Vec::new();
    if let Some(ssh) = ctx.expand("~/.ssh") {
        let mut keys: Vec<PathBuf> = std::fs::read_dir(&ssh)
            .into_iter()
            .flatten()
            .flatten()
            .map(|e| e.path())
            .filter(|p| {
                let name = p
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default();
                (name.starts_with("id_") && !name.ends_with(".pub")) || name.ends_with(".pem")
            })
            .collect();
        keys.sort();
        paths.extend(keys);
    }
    paths.extend(creds::gh_hosts_path(ctx));
    for p in [
        "~/.git-credentials",
        "~/.config/git/credentials",
        "~/.netrc",
        "~/.config/hub",
        "~/.config/glab-cli/config.yml",
    ] {
        paths.extend(ctx.expand(p));
    }
    if let Some(xdg) = ctx.var("XDG_CONFIG_HOME") {
        for sub in ["git/credentials", "hub", "glab-cli/config.yml"] {
            paths.push(Path::new(xdg).join(sub));
        }
    }
    if let Some(cfg) = git {
        for helper in cfg.helpers() {
            if let Some(file) = creds::store_helper_file(&helper) {
                paths.extend(ctx.expand(&file));
            }
        }
    }
    let targets: Vec<PathBuf> = paths
        .iter()
        .filter(|p| std::fs::symlink_metadata(p).is_ok_and(|m| m.file_type().is_symlink()))
        .filter_map(|p| std::fs::canonicalize(p).ok())
        .collect();
    paths.extend(targets);
    paths
}

fn valid_var(name: &str) -> bool {
    let mut chars = name.chars();
    chars
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// The credential leg: what a sandboxed command can read and see, compared
/// with what mezha's reading of the settings withholds.
fn credentials(
    ctx: &Ctx,
    launcher: &Launcher<'_>,
    cwd: &Path,
    git: Option<&GitConfig>,
    withheld: &Withheld,
    masked: &srt::Masked,
    facts: &mut Facts,
) {
    let files = credential_files(ctx, git);
    let vars: Vec<String> = creds::forge_token_vars(ctx)
        .into_iter()
        .filter(|v| valid_var(v))
        .collect();
    let file_list: Vec<String> = files
        .iter()
        .map(|f| f.path.to_string_lossy().into_owned())
        .collect();
    let file_list = file_list.join("\n");
    let var_list = vars.join("\n");
    let out = launch(
        ctx,
        launcher,
        cwd,
        CREDENTIAL_SCRIPT,
        &[
            ("MEZHA_PROBE_FILES", &file_list),
            ("MEZHA_PROBE_VARS", &var_list),
        ],
        RUN_TIMEOUT,
    );
    let Some(seen) = out
        .ok()
        .filter(|o| !o.timed_out)
        .and_then(|o| read_indices(&o.stdout))
    else {
        facts.notes.push(
            "the credential probe didn't finish, so credentials were judged from the settings only"
                .into(),
        );
        return;
    };
    facts.creds_checked = true;
    let fold = ctx.platform.folds_case();
    let masked_paths = Withheld {
        paths: masked.paths.clone(),
        ..Withheld::default()
    };
    for (i, file) in files.iter().enumerate() {
        let readable = seen.contains(&format!("F{i}"));
        let withheld_here = withheld.covers(&file.path, fold);
        if readable && masked_paths.covers(&file.path, fold) {
            facts.unknown.push(format!(
                "{} (masked in the settings; srt can't mask)",
                file.label
            ));
        } else if readable {
            facts.proven.push(file.label.clone());
            if withheld_here {
                facts.disagree.push(format!(
                    "{} is withheld by mezha's reading but readable in srt",
                    file.label
                ));
            }
        } else if !withheld_here && std::fs::metadata(&file.path).is_ok_and(|m| m.len() > 0) {
            facts.disagree.push(format!(
                "{} isn't withheld by mezha's reading but srt kept it out",
                file.label
            ));
        }
    }
    for (i, var) in vars.iter().enumerate() {
        let set = seen.contains(&format!("V{i}"));
        if set && masked.env.contains(var) {
            facts
                .unknown
                .push(format!("{var} (masked in the settings; srt can't mask)"));
        } else if set {
            facts.proven.push(format!("environment variable {var}"));
            if withheld.covers_env(var) {
                facts.disagree.push(format!(
                    "{var} is withheld by mezha's reading but set in srt"
                ));
            }
        } else if !withheld.covers_env(var) {
            facts.disagree.push(format!(
                "{var} isn't withheld by mezha's reading but srt removed it"
            ));
        }
    }
}

/// The `F<i>`/`V<i>` lines, if the closing marker came.
fn read_indices(stdout: &str) -> Option<Vec<String>> {
    let lines: Vec<&str> = stdout.lines().map(str::trim).collect();
    lines.contains(&"MEZHA_PROBE_DONE").then(|| {
        lines
            .iter()
            .filter(|l| {
                let mut chars = l.chars();
                l.len() > 1
                    && matches!(chars.next(), Some('F' | 'V'))
                    && chars.all(|c| c.is_ascii_digit())
            })
            .map(|l| l.to_string())
            .collect()
    })
}

/// Test-only knobs for [`network_direct`]; production leaves both off.
#[doc(hidden)]
#[derive(Debug, Clone, Copy, Default)]
pub struct TestHook {
    /// Allow `file://`, so a local repository can stand in for a server.
    pub allow_file: bool,
    /// Drop `--dry-run`, to show a real run changes nothing either.
    pub real_push: bool,
}

/// The network probe's script run directly, without srt (tests only).
/// Returns the outcome and what the script printed.
#[doc(hidden)]
pub fn network_direct(ctx: &Ctx, url: &str, test_hook: TestHook) -> (Outcome, String) {
    let remote = Remote::parse(url);
    let target = Target {
        scheme: remote.scheme,
        endpoint: crate::hosts::Endpoint {
            host: remote.host,
            port: remote.port,
        },
        url: url.to_string(),
    };
    let Some(git) = ctx.which_trusted("git").path else {
        return (Outcome::Inconclusive("no git".into()), String::new());
    };
    let Ok(scratch) = Scratch::new("mezha-probe-test") else {
        return (Outcome::Inconclusive("no scratch".into()), String::new());
    };
    let results = network(
        ctx,
        &Launcher::Direct,
        &git,
        scratch.path(),
        &[target],
        &(None, None),
        test_hook,
    );
    results.into_iter().next().map_or(
        (Outcome::Inconclusive("no result".into()), String::new()),
        |(r, printed)| (r.outcome, printed),
    )
}

/// The credential probe's script run directly, without srt (tests only).
#[doc(hidden)]
pub fn credentials_direct(ctx: &Ctx, git: Option<&GitConfig>, withheld: &Withheld) -> Facts {
    let mut facts = Facts::default();
    let Ok(scratch) = Scratch::new("mezha-probe-test") else {
        return facts;
    };
    credentials(
        ctx,
        &Launcher::Direct,
        scratch.path(),
        git,
        withheld,
        &srt::Masked::default(),
        &mut facts,
    );
    facts
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn indices_need_the_closing_marker() {
        assert_eq!(
            read_indices("F0\nV2\nMEZHA_PROBE_DONE\n"),
            Some(vec!["F0".into(), "V2".into()])
        );
        assert_eq!(read_indices("F0\n"), None);
        assert_eq!(
            read_indices("Fx\nF1 extra\nV\nMEZHA_PROBE_DONE\n"),
            Some(Vec::new())
        );
    }

    #[test]
    fn variable_names() {
        assert!(valid_var("GH_TOKEN"));
        assert!(valid_var("_x1"));
        assert!(!valid_var("1X"));
        assert!(!valid_var("A-B"));
        assert!(!valid_var("$(id)"));
    }
}
