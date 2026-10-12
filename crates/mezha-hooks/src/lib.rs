//! Claude Code gates that fail closed.
//!
//! Claude Code treats any hook exit code other than 0 and 2 as a
//! non-blocking error and lets the tool call through. So the generated
//! command ends in `|| exit 2` (a missing binary or a crash blocks), and
//! [`run`] itself only ever answers 0 ("no objection") or 2 ("blocked",
//! reason on stderr). It never answers "allow", so the project's
//! permission rules still apply to everything it lets through.

pub mod agent_bash;
mod approval_gate;
pub mod audit;
pub mod dream_guard;
pub mod matcher;
mod paths;
pub mod shell;

use std::collections::HashMap;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::{Path, PathBuf};

use mezha_spec::{BashPattern, CommandPrefix, HostPattern};

/// The hook protocol mezha writes into the commands it generates, passed
/// with `--protocol`. Bump it whenever a hook gains or changes an argument,
/// or a new hook appears: an older mezha then refuses the command with a
/// message that names the mismatch, instead of tripping over an argument it
/// has never seen (ADR-0002).
///
/// 1. The approval gate, `agent-bash` and `dream-guard`.
/// 2. The gate's `--fetch-only` and `--fetch` (`policy.fetch_allow`) and the
///    `audit-outcome` hook.
pub const PROTOCOL: u32 = 2;

/// The oldest protocol this mezha still runs, so settings compiled by an
/// older mezha keep working until the next `mezha compile`.
pub const OLDEST_PROTOCOL: u32 = 1;

/// Hook input larger than this is refused.
pub const MAX_INPUT: usize = 1 << 20;

/// The hooks this binary implements.
pub const HOOKS: [&str; 4] = [
    approval_gate::NAME,
    agent_bash::NAME,
    dream_guard::NAME,
    audit::NAME,
];

/// What the hook prints to stderr and exits with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    pub code: i32,
    pub stderr: String,
}

impl Outcome {
    pub fn allow() -> Self {
        Outcome {
            code: 0,
            stderr: String::new(),
        }
    }

    pub fn block(reason: impl Into<String>) -> Self {
        let mut stderr = reason.into();
        if !stderr.ends_with('\n') {
            stderr.push('\n');
        }
        Outcome { code: 2, stderr }
    }

    pub fn is_block(&self) -> bool {
        self.code == 2
    }
}

/// The process environment and clock, passed in so hooks stay testable.
#[derive(Debug, Clone, Default)]
pub struct Env {
    vars: HashMap<String, String>,
    /// Unix seconds.
    pub now: u64,
    /// Unix milliseconds, for the audit log.
    pub now_ms: u64,
}

impl Env {
    pub fn new<K: Into<String>, V: Into<String>>(
        vars: impl IntoIterator<Item = (K, V)>,
        now: u64,
    ) -> Self {
        Env {
            vars: vars
                .into_iter()
                .map(|(k, v)| (k.into(), v.into()))
                .collect(),
            now,
            now_ms: now * 1000,
        }
    }

    pub fn from_process() -> Self {
        let elapsed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        Env {
            now_ms: elapsed.as_millis() as u64,
            ..Env::new(
                std::env::vars_os()
                    .filter_map(|(k, v)| Some((k.into_string().ok()?, v.into_string().ok()?))),
                elapsed.as_secs(),
            )
        }
    }

    /// A variable's value; empty counts as unset.
    pub fn var(&self, key: &str) -> Option<&str> {
        self.vars
            .get(key)
            .map(String::as_str)
            .filter(|v| !v.is_empty())
    }
}

/// The command Claude Code runs for the approval gate. With `fetch`,
/// WebFetch may reach only those hosts.
pub fn command_line(gates: &[CommandPrefix], fetch: Option<&[HostPattern]>) -> String {
    let mut line = format!("mezha hook {} --protocol {PROTOCOL}", approval_gate::NAME);
    for gate in gates {
        // CommandPrefix words never contain quotes, so '...' is safe.
        line.push_str(&format!(" --gate '{gate}'"));
    }
    if let Some(hosts) = fetch {
        line.push_str(" --fetch-only");
        for host in hosts {
            // Host patterns are letters, digits, `-`, `.` and `*`.
            line.push_str(&format!(" --fetch '{host}'"));
        }
    }
    line.push_str(" || exit 2");
    line
}

/// The command Claude Code runs after each tool call, for the audit log.
pub fn audit_command() -> String {
    format!("mezha hook {} --protocol {PROTOCOL} || exit 2", audit::NAME)
}

/// The command an agent's frontmatter runs to keep its Bash within `scopes`.
pub fn agent_bash_command(scopes: &[BashPattern]) -> String {
    let mut line = format!("mezha hook {} --protocol {PROTOCOL}", agent_bash::NAME);
    for scope in scopes {
        // BashPattern words never contain quotes, so '...' is safe.
        line.push_str(&format!(" --allow '{scope}'"));
    }
    line.push_str(" || exit 2");
    line
}

/// The command a dream's `--settings` file runs before each of the
/// dreamer's tool calls. It names the running binary by its absolute path,
/// so neither PATH nor a protocol mismatch can get in the way.
pub fn dream_guard_command(exe: &Path, read: &[&Path], write: &Path) -> Result<String, String> {
    let mut line = format!(
        "{} hook {} --protocol {PROTOCOL}",
        sh_quote(exe)?,
        dream_guard::NAME
    );
    for dir in read {
        line.push_str(&format!(" --read {}", sh_quote(dir)?));
    }
    line.push_str(&format!(" --write {} || exit 2", sh_quote(write)?));
    Ok(line)
}

/// A path in single quotes for bash.
fn sh_quote(path: &Path) -> Result<String, String> {
    let text = path
        .to_str()
        .ok_or_else(|| format!("{} is not valid UTF-8", path.display()))?;
    if text.contains(['\n', '\r', '\0']) {
        return Err(format!("{} contains a line break", text.escape_debug()));
    }
    Ok(format!("'{}'", text.replace('\'', r"'\''")))
}

/// Runs `mezha hook <argv...>` on the event in `input`. A panic blocks too.
pub fn run(argv: &[String], input: &[u8], env: &Env) -> Outcome {
    catch_unwind(AssertUnwindSafe(|| dispatch(argv, input, env))).unwrap_or_else(|_| {
        Outcome::block("mezha: the hook crashed, so the call is blocked (fail-closed)")
    })
}

fn dispatch(argv: &[String], input: &[u8], env: &Env) -> Outcome {
    let Some((name, args)) = argv.split_first() else {
        return Outcome::block("mezha hook: no hook name given");
    };
    let mut gates = Vec::new();
    let mut scopes = Vec::new();
    let mut read: Vec<PathBuf> = Vec::new();
    let mut write: Option<PathBuf> = None;
    let mut fetch_only = false;
    let mut fetch: Vec<HostPattern> = Vec::new();
    // The protocol first: a newer mezha's command may hold arguments this
    // one has never heard of, and the mismatch is what to report.
    let protocol = match args
        .iter()
        .position(|a| a == "--protocol")
        .and_then(|i| args.get(i + 1))
    {
        None => return Outcome::block("mezha hook: no --protocol given; run `mezha compile`"),
        Some(value) => match value.parse::<u32>() {
            Err(_) => return Outcome::block(format!("mezha hook: bad --protocol `{value}`")),
            Ok(p) if p > PROTOCOL => {
                return Outcome::block(format!(
                    "mezha: these settings were compiled by a newer mezha (hook protocol {p}), \
                     and this one runs protocol {OLDEST_PROTOCOL} to {PROTOCOL}. Install the \
                     mezha the project uses (`cargo install --locked --force --path \
                     crates/mezha-cli` in its repository); until then every call is blocked \
                     (fail-closed)."
                ));
            }
            Ok(p) if p < OLDEST_PROTOCOL => {
                return Outcome::block(format!(
                    "mezha: these settings were compiled for hook protocol {p}, older than this \
                     mezha runs. Run `mezha compile`; until then every call is blocked \
                     (fail-closed)."
                ));
            }
            Ok(p) => p,
        },
    };
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        if arg == "--fetch-only" {
            fetch_only = true;
            continue;
        }
        match (arg.as_str(), args.next()) {
            ("--fetch", Some(value)) => match HostPattern::parse(value) {
                Ok(host) => fetch.push(host),
                Err(e) => return Outcome::block(format!("mezha hook: bad --fetch: {e}")),
            },
            ("--protocol", Some(_)) => {}
            ("--gate", Some(value)) => match CommandPrefix::parse(value) {
                Ok(gate) => gates.push(gate),
                Err(e) => return Outcome::block(format!("mezha hook: bad --gate: {e}")),
            },
            ("--allow", Some(value)) => match BashPattern::parse(value) {
                Ok(scope) => scopes.push(scope),
                Err(e) => {
                    return Outcome::block(format!("mezha hook: bad --allow `{value}`: {e}"));
                }
            },
            ("--read" | "--write", Some(value)) => {
                let dir = PathBuf::from(value);
                if !dir.is_absolute() {
                    return Outcome::block(format!("mezha hook: {arg} `{value}` is not absolute"));
                }
                if arg == "--read" {
                    read.push(dir);
                } else if write.replace(dir).is_some() {
                    return Outcome::block("mezha hook: --write given twice");
                }
            }
            (other, _) => {
                return Outcome::block(format!(
                    "mezha hook: unexpected argument `{other}`: the hook command was edited, or \
                     another mezha compiled it with the same protocol. Check that `mezha \
                     --version` is the mezha the project uses, then run `mezha compile`."
                ));
            }
        }
    }
    // Each hook takes its own flags; any other flag means the command was
    // edited or generated by another mezha.
    let fetching = fetch_only || !fetch.is_empty();
    if protocol < 2 && (fetching || name == audit::NAME) {
        return Outcome::block(format!(
            "mezha hook: {name} with these arguments needs hook protocol 2, but the command says {protocol}; run `mezha compile`"
        ));
    }
    let foreign = match name.as_str() {
        approval_gate::NAME => {
            !scopes.is_empty() || !read.is_empty() || write.is_some() || (!fetch_only && fetching)
        }
        agent_bash::NAME => !gates.is_empty() || !read.is_empty() || write.is_some() || fetching,
        dream_guard::NAME => !gates.is_empty() || !scopes.is_empty() || fetching,
        audit::NAME => {
            !gates.is_empty()
                || !scopes.is_empty()
                || !read.is_empty()
                || write.is_some()
                || fetching
        }
        _ => false,
    };
    if foreign {
        return Outcome::block(format!(
            "mezha hook: {name} got another hook's arguments; run `mezha compile` to regenerate it"
        ));
    }
    match name.as_str() {
        approval_gate::NAME => {
            approval_gate::run(&gates, fetch_only.then_some(&fetch[..]), input, env)
        }
        agent_bash::NAME => agent_bash::run(&scopes, input),
        dream_guard::NAME => dream_guard::run(&read, write.as_deref(), input),
        audit::NAME => audit::outcome(input, env),
        other => Outcome::block(format!("mezha hook: unknown hook `{other}`")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(args: &[&str]) -> Vec<String> {
        args.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn command_line_is_fail_closed() {
        let gates = [
            CommandPrefix::parse("git push").unwrap(),
            CommandPrefix::parse("terraform apply").unwrap(),
        ];
        assert_eq!(
            command_line(&gates, None),
            "mezha hook approval-gate --protocol 2 --gate 'git push' --gate 'terraform apply' || exit 2"
        );
    }

    #[test]
    fn bad_arguments_block() {
        let env = Env::default();
        for args in [
            argv(&[]),
            argv(&["approval-gate"]),
            argv(&["approval-gate", "--protocol", "3"]),
            argv(&["approval-gate", "--protocol", "0"]),
            argv(&["audit-outcome", "--protocol", "1"]),
            argv(&["approval-gate", "--protocol", "1", "--fetch-only"]),
            argv(&["approval-gate", "--protocol", "x"]),
            argv(&["approval-gate", "--protocol"]),
            argv(&["approval-gate", "--protocol", "1", "--gate", "git push; rm"]),
            argv(&["approval-gate", "--protocol", "1", "--extra"]),
            argv(&["other-hook", "--protocol", "1"]),
            argv(&["approval-gate", "--protocol", "1", "--write", "/tmp/x"]),
            argv(&["agent-bash", "--protocol", "1", "--gate", "git push"]),
            argv(&[
                "dream-guard",
                "--protocol",
                "1",
                "--gate",
                "git push",
                "--write",
                "/tmp/x",
            ]),
            argv(&["dream-guard", "--protocol", "1", "--write", "relative"]),
            argv(&[
                "dream-guard",
                "--protocol",
                "1",
                "--write",
                "/a",
                "--write",
                "/b",
            ]),
            argv(&["dream-guard", "--protocol", "1"]),
        ] {
            let out = run(&args, b"{}", &env);
            assert!(out.is_block(), "{args:?}: {out:?}");
        }
    }

    #[test]
    fn a_block_reason_ends_in_exactly_one_newline() {
        assert_eq!(Outcome::block("why").stderr, "why\n");
        assert_eq!(Outcome::block("why\n").stderr, "why\n");
        assert!(Outcome::block("why").is_block());
        assert!(!Outcome::allow().is_block());
    }

    #[test]
    fn bad_option_values_name_the_option() {
        let env = Env::default();
        let out = run(
            &argv(&[
                "approval-gate",
                "--protocol",
                "2",
                "--fetch-only",
                "--fetch",
                "docs.rs:443",
            ]),
            b"{}",
            &env,
        );
        assert!(
            out.stderr
                .starts_with("mezha hook: bad --fetch: `docs.rs:443` is not a host"),
            "{out:?}"
        );
        let out = run(
            &argv(&["agent-bash", "--protocol", "2", "--allow", "cargo te*t"]),
            b"{}",
            &env,
        );
        assert!(
            out.stderr
                .starts_with("mezha hook: bad --allow `cargo te*t`: `te*t`"),
            "{out:?}"
        );
    }

    #[test]
    fn agent_bash_takes_its_scopes_from_the_command_line() {
        let env = Env::default();
        let args = argv(&[
            "agent-bash",
            "--protocol",
            "2",
            "--allow",
            "cargo test *",
            "--allow",
            "git status",
        ]);
        let event = |command: &str| {
            format!(
                r#"{{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{{"command":"{command}"}}}}"#
            )
        };
        assert_eq!(
            run(&args, event("cargo test -p x").as_bytes(), &env),
            Outcome::allow()
        );
        assert_eq!(
            run(&args, event("git status").as_bytes(), &env),
            Outcome::allow()
        );
        let out = run(&args, event("cargo build").as_bytes(), &env);
        assert!(
            out.stderr.contains(
                "`cargo build` isn't one of this agent's commands (cargo test *, git status)"
            ),
            "{out:?}"
        );
    }

    #[test]
    fn the_process_environment_carries_the_clock() {
        let env = Env::from_process();
        assert!(env.now >= 1_700_000_000, "{}", env.now);
        assert_eq!(env.now_ms / 1000, env.now, "{}", env.now_ms);
        assert_eq!(env.var("MEZHA_NO_SUCH_VARIABLE_FOR_TESTS"), None);
    }

    #[test]
    fn protocols() {
        let tmp = tempfile::tempdir().unwrap();
        let env = Env::new([("HOME", tmp.path().to_str().unwrap())], 1_800_000_000);
        let event = br#"{"hook_event_name":"PreToolUse","tool_name":"Read","tool_input":{}}"#;
        // Settings an older mezha compiled keep working.
        let out = run(
            &argv(&["approval-gate", "--protocol", "1", "--gate", "git push"]),
            event,
            &env,
        );
        assert_eq!(out, Outcome::allow());
        // A newer mezha's command is refused for what it is, before any
        // argument this one doesn't know.
        let out = run(
            &argv(&["approval-gate", "--protocol", "3", "--future-flag", "x"]),
            event,
            &env,
        );
        assert!(
            out.stderr
                .contains("compiled by a newer mezha (hook protocol 3)"),
            "{out:?}"
        );
        assert!(out.stderr.contains("--force"), "{out:?}");
        let out = run(
            &argv(&["approval-gate", "--protocol", "2", "--future-flag", "x"]),
            event,
            &env,
        );
        assert!(
            out.stderr
                .contains("the hook command was edited, or another mezha"),
            "{out:?}"
        );
        let out = run(
            &argv(&["approval-gate", "--protocol", "1", "--fetch-only"]),
            event,
            &env,
        );
        assert!(out.stderr.contains("needs hook protocol 2"), "{out:?}");
    }
}
