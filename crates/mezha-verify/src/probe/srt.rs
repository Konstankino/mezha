//! The sandbox runtime: finding a trusted `srt`, checking its version, and
//! translating the effective Claude Code settings into srt's settings.

use std::path::{Path, PathBuf};
use std::time::Duration;

use serde_json::{Value, json};

use crate::ctx::Ctx;
use crate::layers::Layers;
use crate::runner::{Output, Run, run};

/// The first srt whose CLI and settings the probe was written against.
pub const MIN_VERSION: (u32, u32, u32) = (0, 0, 79);
pub const INSTALL: &str = "npm i -g @anthropic-ai/sandbox-runtime@0.0.79 (needs Node 22.12 or later; on Linux also bubblewrap, socat and ripgrep)";

/// Variables that would change how `node` (and so srt) behaves.
pub const NODE_ENV: [&str; 2] = ["NODE_OPTIONS", "NODE_PATH"];

#[derive(Debug, Clone)]
pub struct Srt {
    pub program: PathBuf,
    pub version: String,
}

/// A trusted `srt` that is new enough and not already running around us.
pub fn find(ctx: &Ctx) -> Result<Srt, String> {
    if ctx.var("SANDBOX_RUNTIME").is_some() {
        return Err("SANDBOX_RUNTIME is set: verify is already running inside srt, which can't start inside itself on macOS. Run `mezha verify --probe` from your own terminal.".into());
    }
    let found = ctx.which_trusted("srt");
    let Some(program) = found.path else {
        let mut why = format!("srt (Anthropic's sandbox runtime) isn't installed: {INSTALL}");
        if let Some(note) = found.skipped_note("srt") {
            why.push_str(&format!("; {note}"));
        }
        return Err(why);
    };
    let out = srt_run(ctx, &program, &["--version"], Duration::from_secs(20))
        .map_err(|e| format!("srt couldn't run: {e}"))?;
    let text = format!("{} {}", out.stdout, out.stderr);
    let version = parse_version(&text)
        .ok_or_else(|| format!("can't read srt's version from `{}`", text.trim()))?;
    if version < MIN_VERSION {
        return Err(format!(
            "srt {}.{}.{} is too old for --probe: {INSTALL}",
            version.0, version.1, version.2
        ));
    }
    Ok(Srt {
        program,
        version: format!("{}.{}.{}", version.0, version.1, version.2),
    })
}

/// Starts srt once with the settings and a command that only prints, so a
/// missing dependency shows up as "couldn't run" rather than as a probe
/// result.
pub fn start(ctx: &Ctx, srt: &Srt, settings: &Path, cwd: &Path) -> Result<(), String> {
    let settings = settings.to_string_lossy();
    let out = run(
        ctx,
        &Run {
            program: &srt.program,
            args: &["--settings", &settings, "-c", "echo MEZHA_SRT_OK"],
            cwd,
            env: &[("PATH", &ctx.trusted_path())],
            remove: &NODE_ENV,
            stdin: b"",
            timeout: Duration::from_secs(30),
        },
    )
    .map_err(|e| format!("srt couldn't run: {e}"))?;
    if out.stdout.lines().any(|l| l.trim() == "MEZHA_SRT_OK") {
        return Ok(());
    }
    let why = out
        .stderr
        .lines()
        .chain(out.stdout.lines())
        .find(|l| !l.trim().is_empty())
        .map_or_else(
            || {
                if out.timed_out {
                    "it timed out".to_string()
                } else {
                    "it printed nothing".to_string()
                }
            },
            |l| l.trim().chars().take(200).collect(),
        );
    Err(format!("srt can't start a sandbox here: {why}"))
}

fn srt_run(ctx: &Ctx, program: &Path, args: &[&str], timeout: Duration) -> std::io::Result<Output> {
    let cwd = std::env::temp_dir();
    run(
        ctx,
        &Run {
            program,
            args,
            cwd: &cwd,
            env: &[("PATH", &ctx.trusted_path())],
            remove: &NODE_ENV,
            stdin: b"",
            timeout,
        },
    )
}

/// The first `x.y.z` (maybe after a `v`) in the text.
pub fn parse_version(text: &str) -> Option<(u32, u32, u32)> {
    text.split(|c: char| c.is_whitespace() || c == ',' || c == '(' || c == ')')
        .find_map(|word| {
            let word = word.strip_prefix('v').unwrap_or(word);
            let mut parts = word.split('.');
            let v = (
                parts.next()?.parse().ok()?,
                parts.next()?.parse().ok()?,
                parts.next()?.parse().ok()?,
            );
            parts.next().is_none().then_some(v)
        })
}

/// Credentials the settings mask rather than deny. srt isn't asked to
/// mask them, so what the probe sees there proves nothing.
#[derive(Debug, Clone, Default)]
pub struct Masked {
    pub paths: Vec<PathBuf>,
    pub env: Vec<String>,
}

/// srt settings for the effective Claude Code settings, as mezha reads
/// them: the hosts sandboxed commands may reach (`WebFetch(domain:...)`
/// allow rules included), the denied hosts, the read denials and the
/// credential `deny` entries. Writes are all refused: probes write nothing.
pub fn settings(ctx: &Ctx, layers: &Layers) -> (Value, Masked) {
    let mut allowed: Vec<String> = layers
        .strings("/sandbox/network/allowedDomains")
        .into_iter()
        .filter(|(_, l)| layers.loosens(l))
        .map(|(s, _)| s.trim().to_string())
        .collect();
    allowed.extend(
        layers
            .strings("/permissions/allow")
            .into_iter()
            .filter(|(_, l)| layers.loosens(l))
            .filter_map(|(rule, _)| {
                rule.strip_prefix("WebFetch(domain:")?
                    .strip_suffix(')')
                    .map(|d| d.trim().to_string())
            }),
    );
    let denied: Vec<String> = layers
        .strings("/sandbox/network/deniedDomains")
        .into_iter()
        .map(|(s, _)| s.trim().to_string())
        .collect();
    let disabled = layers
        .every("/sandbox/filesystem/disabled")
        .any(|(v, l)| v == &Value::Bool(true) && !l.scope.is_repository());
    let path_text = |p: &str| ctx.resolve(p).map(|p| p.to_string_lossy().into_owned());
    let deny_read: Vec<String> = if disabled {
        Vec::new()
    } else {
        layers
            .strings("/sandbox/filesystem/denyRead")
            .into_iter()
            .filter_map(|(p, _)| path_text(p))
            .collect()
    };
    let mut files = Vec::new();
    let mut env_vars = Vec::new();
    let mut masked = Masked::default();
    for (entry, _) in layers.every("/sandbox/credentials/files") {
        for item in entry.as_array().into_iter().flatten() {
            let Some(path) = item["path"].as_str().and_then(path_text) else {
                continue;
            };
            match item["mode"].as_str() {
                Some("deny") if !disabled => files.push(json!({ "path": path, "mode": "deny" })),
                Some("mask") => masked.paths.push(PathBuf::from(path)),
                _ => {}
            }
        }
    }
    for (entry, _) in layers.every("/sandbox/credentials/envVars") {
        for item in entry.as_array().into_iter().flatten() {
            let Some(name) = item["name"].as_str() else {
                continue;
            };
            match item["mode"].as_str() {
                Some("deny") => env_vars.push(json!({ "name": name, "mode": "deny" })),
                Some("mask") => masked.env.push(name.to_string()),
                _ => {}
            }
        }
    }
    dedup(&mut allowed);
    let value = json!({
        "network": {
            "allowedDomains": allowed,
            "deniedDomains": denied,
        },
        "filesystem": {
            "denyRead": deny_read,
            "allowWrite": [],
            "denyWrite": [],
        },
        "credentials": {
            "files": files,
            "envVars": env_vars,
        },
    });
    (value, masked)
}

/// srt settings for running a command the way a session's sandbox would:
/// [`settings`], plus writes to `cwd` (a worktree of the project), the temp
/// directory and the effective `sandbox.filesystem.allowWrite`, minus
/// `denyWrite`. Project-relative paths are resolved against `cwd`. The
/// A/B runner uses it for checks, which run code an agent just wrote.
pub fn command_settings(ctx: &Ctx, layers: &Layers, cwd: &Path) -> Value {
    let (mut value, _) = settings(ctx, layers);
    let here = Ctx {
        root: cwd.to_path_buf(),
        ..ctx.clone()
    };
    let resolved = |pointer: &str| -> Vec<String> {
        layers
            .strings(pointer)
            .into_iter()
            .filter_map(|(p, _)| here.resolve(p))
            .map(|p| p.to_string_lossy().into_owned())
            .collect()
    };
    let mut allow = vec![
        cwd.to_string_lossy().into_owned(),
        std::env::temp_dir().to_string_lossy().into_owned(),
    ];
    allow.extend(resolved("/sandbox/filesystem/allowWrite"));
    dedup(&mut allow);
    value["filesystem"]["allowWrite"] = json!(allow);
    value["filesystem"]["denyWrite"] = json!(resolved("/sandbox/filesystem/denyWrite"));
    value
}

fn dedup(list: &mut Vec<String>) {
    let mut seen = std::collections::BTreeSet::new();
    list.retain(|s| seen.insert(s.clone()));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ctx::Platform;
    use crate::layers::{Layer, Scope};

    #[test]
    fn versions() {
        assert_eq!(parse_version("0.0.79\n"), Some((0, 0, 79)));
        assert_eq!(parse_version("srt v0.1.2"), Some((0, 1, 2)));
        assert_eq!(
            parse_version("sandbox-runtime 0.0.80 (node 22)"),
            Some((0, 0, 80))
        );
        assert_eq!(parse_version("node 22 1.2"), None);
        assert!(parse_version("0.0.78").unwrap() < MIN_VERSION);
    }

    /// The project layer is mezha's own rendered settings; a user layer
    /// adds a WebFetch rule, a mask entry, a denied host and a read denial.
    #[test]
    fn settings_golden() {
        let project: Value = serde_json::from_str(include_str!(
            "../../../mezha-render/tests/golden/settings.json"
        ))
        .unwrap();
        let user = json!({
            "permissions": { "allow": ["WebFetch(domain:docs.rs)", "WebFetch(domain:crates.io)"] },
            "sandbox": {
                "network": { "deniedDomains": ["evil.example"] },
                "filesystem": { "denyRead": ["~/private"], "allowWrite": ["~/.cache"] },
                "credentials": {
                    "files": [{ "path": "~/.config/tool/token", "mode": "mask" }],
                    "envVars": [{ "name": "MY_GITHUB_PAT", "mode": "mask" }]
                }
            }
        });
        let layers = Layers {
            layers: vec![
                Layer {
                    scope: Scope::User,
                    label: "user".into(),
                    value: user,
                },
                Layer {
                    scope: Scope::Project,
                    label: "project".into(),
                    value: project,
                },
            ],
            ..Layers::default()
        };
        let ctx = Ctx {
            root: PathBuf::from("/work/repo"),
            vars: Default::default(),
            home: Some(PathBuf::from("/home/u")),
            platform: Platform::Linux,
            managed_dir: None,
            mezha_exe: None,
            agent_writable: Vec::new(),
        };
        let (value, masked) = settings(&ctx, &layers);
        let text = serde_json::to_string_pretty(&value).unwrap() + "\n";
        let golden = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/golden/srt-settings.json");
        if std::env::var_os("MEZHA_BLESS").is_some() {
            std::fs::create_dir_all(golden.parent().unwrap()).unwrap();
            std::fs::write(&golden, &text).unwrap();
        }
        assert_eq!(
            text,
            std::fs::read_to_string(&golden).unwrap(),
            "run with MEZHA_BLESS=1 to update"
        );
        assert_eq!(masked.paths, [PathBuf::from("/home/u/.config/tool/token")]);
        assert_eq!(masked.env, ["MY_GITHUB_PAT"]);
        assert!(!text.contains("\"mask\""));
        assert!(!text.contains(".cache"), "allowWrite isn't passed on");
    }

    fn ctx() -> Ctx {
        Ctx {
            root: PathBuf::from("/work/repo"),
            vars: Default::default(),
            home: Some(PathBuf::from("/home/u")),
            platform: Platform::Linux,
            managed_dir: None,
            mezha_exe: None,
            agent_writable: Vec::new(),
        }
    }

    fn user_layers(value: Value) -> Layers {
        Layers {
            layers: vec![Layer {
                scope: Scope::User,
                label: "user".into(),
                value,
            }],
            ..Layers::default()
        }
    }

    /// Entries srt can't use are left out: a disabled filesystem sandbox
    /// drops the read and file denials, and an entry without a path or
    /// name, or with a mode that is neither deny nor mask, is skipped.
    #[test]
    fn settings_leave_out_what_srt_cannot_use() {
        let layers = user_layers(json!({
            "sandbox": {
                "filesystem": { "disabled": true, "denyRead": ["~/private"] },
                "credentials": {
                    "files": [
                        { "path": "~/.netrc", "mode": "deny" },
                        { "mode": "deny" },
                        { "path": "~/.x", "mode": "allow" }
                    ],
                    "envVars": [
                        { "name": "GH_TOKEN", "mode": "deny" },
                        { "mode": "deny" },
                        { "name": "X", "mode": "allow" }
                    ]
                }
            }
        }));
        let (value, masked) = settings(&ctx(), &layers);
        assert_eq!(value["filesystem"]["denyRead"], json!([]), "{value}");
        assert_eq!(value["credentials"]["files"], json!([]), "{value}");
        assert_eq!(
            value["credentials"]["envVars"],
            json!([{ "name": "GH_TOKEN", "mode": "deny" }]),
            "{value}"
        );
        assert!(
            masked.paths.is_empty() && masked.env.is_empty(),
            "{masked:?}"
        );
    }

    #[test]
    fn command_settings_add_the_writable_paths() {
        let layers = user_layers(json!({
            "sandbox": {
                "filesystem": {
                    "allowWrite": ["~/.cache", "build", "//opt/out", "build"],
                    "denyWrite": ["secrets"]
                }
            }
        }));
        let cwd = Path::new("/work/tree");
        let value = command_settings(&ctx(), &layers, cwd);
        let temp = std::env::temp_dir().to_string_lossy().into_owned();
        assert_eq!(
            value["filesystem"]["allowWrite"],
            json!([
                "/work/tree",
                temp,
                "/home/u/.cache",
                "/work/tree/build",
                "/opt/out"
            ]),
            "{value}"
        );
        assert_eq!(
            value["filesystem"]["denyWrite"],
            json!(["/work/tree/secrets"]),
            "{value}"
        );
        assert_eq!(value["network"]["allowedDomains"], json!([]), "{value}");
    }
}
