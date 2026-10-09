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
pub mod matcher;
pub mod shell;

use std::collections::HashMap;
use std::panic::{AssertUnwindSafe, catch_unwind};

use mezha_spec::{BashPattern, CommandPrefix};

/// The hook protocol. The generated command passes it with `--protocol`; any
/// other number means the settings and the binary disagree, and the call is
/// blocked until `mezha compile` regenerates them.
pub const PROTOCOL: u32 = 1;

/// Hook input larger than this is refused.
pub const MAX_INPUT: usize = 1 << 20;

/// The hooks this binary implements.
pub const HOOKS: [&str; 2] = [approval_gate::NAME, agent_bash::NAME];

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
        }
    }

    pub fn from_process() -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        Env::new(
            std::env::vars_os()
                .filter_map(|(k, v)| Some((k.into_string().ok()?, v.into_string().ok()?))),
            now,
        )
    }

    /// A variable's value; empty counts as unset.
    pub fn var(&self, key: &str) -> Option<&str> {
        self.vars
            .get(key)
            .map(String::as_str)
            .filter(|v| !v.is_empty())
    }
}

/// The command Claude Code runs for the approval gate.
pub fn command_line(gates: &[CommandPrefix]) -> String {
    let mut line = format!("mezha hook {} --protocol {PROTOCOL}", approval_gate::NAME);
    for gate in gates {
        // CommandPrefix words never contain quotes, so '...' is safe.
        line.push_str(&format!(" --gate '{gate}'"));
    }
    line.push_str(" || exit 2");
    line
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
    let mut protocol = None;
    let mut gates = Vec::new();
    let mut scopes = Vec::new();
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        match (arg.as_str(), args.next()) {
            ("--protocol", Some(value)) => match value.parse::<u32>() {
                Ok(n) => protocol = Some(n),
                Err(_) => return Outcome::block(format!("mezha hook: bad --protocol `{value}`")),
            },
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
            (other, _) => {
                return Outcome::block(format!(
                    "mezha hook: unexpected argument `{other}`; run `mezha compile` to regenerate the hook"
                ));
            }
        }
    }
    match protocol {
        None => return Outcome::block("mezha hook: no --protocol given; run `mezha compile`"),
        Some(p) if p != PROTOCOL => {
            return Outcome::block(format!(
                "mezha: this hook was generated for hook protocol {p}, but this mezha speaks \
                 protocol {PROTOCOL}. Run `mezha compile` with the mezha the project uses; \
                 until then every call is blocked (fail-closed)."
            ));
        }
        Some(_) => {}
    }
    match name.as_str() {
        approval_gate::NAME => approval_gate::run(&gates, input, env),
        agent_bash::NAME => agent_bash::run(&scopes, input),
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
            command_line(&gates),
            "mezha hook approval-gate --protocol 1 --gate 'git push' --gate 'terraform apply' || exit 2"
        );
    }

    #[test]
    fn bad_arguments_block() {
        let env = Env::default();
        for args in [
            argv(&[]),
            argv(&["approval-gate"]),
            argv(&["approval-gate", "--protocol", "2"]),
            argv(&["approval-gate", "--protocol", "x"]),
            argv(&["approval-gate", "--protocol"]),
            argv(&["approval-gate", "--protocol", "1", "--gate", "git push; rm"]),
            argv(&["approval-gate", "--protocol", "1", "--extra"]),
            argv(&["other-hook", "--protocol", "1"]),
        ] {
            let out = run(&args, b"{}", &env);
            assert!(out.is_block(), "{args:?}: {out:?}");
        }
    }
}
