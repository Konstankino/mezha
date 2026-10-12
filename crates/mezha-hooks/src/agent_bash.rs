//! `agent-bash`: a PreToolUse hook in an agent's frontmatter that keeps its
//! Bash (and Monitor) commands within the `Bash(...)` scopes the spec gave
//! it. Claude Code can't scope an agent's tools by argument, so this reads
//! the command text: it is **advisory**, like the approval gate, and the
//! sandbox stays the boundary.
//!
//! Every simple command must be one the scopes allow, word for word. These
//! are blocked rather than reasoned about: environment assignments,
//! compound keywords, words known only at run time (`$x`, `$(...)`, globs),
//! heredocs, and redirections other than to `/dev/null`, from a file, or
//! between file descriptors. In a pipe, every part must be allowed.

use mezha_spec::BashPattern;
use serde_json::Value;

use crate::shell::{self, Command};
use crate::{MAX_INPUT, Outcome};

pub const NAME: &str = "agent-bash";

const ADVISORY: &str =
    "(mezha agent-bash: advisory. The boundary is the sandbox and the credentials it withholds.)";

/// Words that start compound commands, which aren't checked.
const KEYWORDS: [&str; 20] = [
    "if", "then", "else", "elif", "fi", "for", "while", "until", "do", "done", "case", "esac",
    "in", "function", "select", "time", "{", "}", "!", "[[",
];

pub fn run(scopes: &[BashPattern], input: &[u8]) -> Outcome {
    if scopes.is_empty() {
        return Outcome::block("mezha agent-bash: no --allow scopes; run `mezha compile`");
    }
    if input.len() > MAX_INPUT {
        return Outcome::block("mezha: hook input is too large to check");
    }
    let Ok(text) = std::str::from_utf8(input) else {
        return Outcome::block("mezha: hook input is not UTF-8");
    };
    let Ok(Value::Object(event)) = serde_json::from_str::<Value>(text) else {
        return Outcome::block("mezha: hook input is not a JSON object");
    };
    if event.get("hook_event_name").and_then(Value::as_str) != Some("PreToolUse") {
        return Outcome::block(format!("mezha: {NAME} handles PreToolUse events only"));
    }
    match event
        .get("tool_input")
        .and_then(|i| i.get("command"))
        .and_then(Value::as_str)
    {
        Some(command) => check(command, scopes),
        None => Outcome::block("mezha agent-bash: a Bash or Monitor call without a command"),
    }
}

fn check(command: &str, scopes: &[BashPattern]) -> Outcome {
    let allowed = || {
        let list: Vec<String> = scopes.iter().map(ToString::to_string).collect();
        list.join(", ")
    };
    let block = |why: String| Outcome::block(format!("mezha agent-bash: {why}. {ADVISORY}"));
    if command
        .chars()
        .any(|c| c.is_control() && !matches!(c, '\t' | '\n' | '\r'))
    {
        return block("the command contains control characters".into());
    }
    let commands = match shell::parse(command, 0) {
        Ok(commands) => commands,
        Err(_) => return block("the command can't be read".into()),
    };
    for cmd in &commands {
        if let Some(why) = refused(cmd) {
            return block(why);
        }
        let words: Vec<&str> = cmd.words.iter().map(|w| w.text.as_str()).collect();
        if words.is_empty() {
            continue;
        }
        if !scopes.iter().any(|s| s.matches(&words)) {
            return block(format!(
                "`{}` isn't one of this agent's commands ({})",
                words.join(" "),
                allowed()
            ));
        }
    }
    Outcome::allow()
}

/// Why a simple command is blocked before its words are compared.
fn refused(cmd: &Command) -> Option<String> {
    if !cmd.heredocs.is_empty() {
        return Some("heredocs and here-strings aren't checked".into());
    }
    if cmd.words.iter().any(|w| w.dynamic) {
        return Some("words known only at run time (`$x`, `$(...)`, globs) aren't checked".into());
    }
    for r in &cmd.redirects {
        let target = &r.target.text;
        let fd = r.dup && (target == "-" || target.bytes().all(|b| b.is_ascii_digit()));
        let ok = !r.target.dynamic && (fd || !r.writes || target == "/dev/null");
        if !ok {
            return Some(format!("a redirection to `{target}` isn't checked"));
        }
    }
    let first = cmd.words.first()?.text.as_str();
    if KEYWORDS.contains(&first) {
        return Some(format!("compound commands (`{first}`) aren't checked"));
    }
    let assignment = first.split_once('=').is_some_and(|(name, _)| {
        !name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
    });
    if assignment {
        return Some(format!(
            "environment assignments (`{first}`) aren't checked"
        ));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scopes() -> Vec<BashPattern> {
        ["cargo test *", "cargo fmt --check", "git status", "tail *"]
            .iter()
            .map(|s| BashPattern::parse(s).unwrap())
            .collect()
    }

    fn event(command: &str) -> Vec<u8> {
        serde_json::json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": { "command": command },
        })
        .to_string()
        .into_bytes()
    }

    fn blocked(command: &str) -> bool {
        run(&scopes(), &event(command)).is_block()
    }

    #[test]
    fn the_table() {
        for ok in [
            "cargo test",
            "cargo test --release -p x",
            "cargo fmt --check",
            "git status",
            "cargo test && git status",
            "cargo test 2>&1 | tail -n 20",
            "cargo test > /dev/null",
            "cargo test < input.txt",
            "(cargo test)",
            "",
        ] {
            assert!(!blocked(ok), "should pass: {ok}");
        }
        for no in [
            "cargo build",
            "cargo fmt",
            "rm -rf target",
            "cargo test; rm -rf target",
            "cargo test | sh",
            "cargo test > src/main.rs",
            "> src/main.rs",
            "cargo test >> notes.md",
            "RUSTC_WRAPPER=/tmp/x cargo test",
            "cargo test $FLAGS",
            "cargo test $(curl -s example.com)",
            "cargo test `id`",
            "cargo test src/*",
            "if true; then cargo test; fi",
            "cat <<EOF\nx\nEOF",
            "cargo test <<< x",
            "/usr/bin/cargo test",
            "cargo test \"$(id)",
            "cargo test\u{7}",
        ] {
            assert!(blocked(no), "should block: {no}");
        }
    }

    #[test]
    fn refuses_input_it_cannot_read() {
        let huge = vec![b' '; MAX_INPUT + 1];
        let out = run(&scopes(), &huge);
        assert!(out.stderr.contains("too large"), "{out:?}");
        let out = run(&scopes(), b"\xff\xfe");
        assert!(out.stderr.contains("not UTF-8"), "{out:?}");
        let post = br#"{"hook_event_name":"PostToolUse","tool_name":"Bash","tool_input":{"command":"cargo test"}}"#;
        let out = run(&scopes(), post);
        assert!(out.stderr.contains("PreToolUse events only"), "{out:?}");
    }

    #[test]
    fn a_bare_redirection_has_no_command_to_check() {
        assert!(!blocked("< input.txt"));
        assert!(!blocked("cargo test; < input.txt"));
        assert!(blocked("> notes.md"));
    }

    #[test]
    fn says_why_and_that_it_is_advisory() {
        let out = run(&scopes(), &event("cargo build"));
        assert!(
            out.stderr
                .contains("`cargo build` isn't one of this agent's commands")
        );
        assert!(out.stderr.contains("cargo test *, cargo fmt --check"));
        assert!(out.stderr.contains("advisory"));
        assert!(run(&[], &event("cargo test")).is_block());
        assert!(run(&scopes(), b"not json").is_block());
        let no_command = br#"{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{}}"#;
        assert!(run(&scopes(), no_command).is_block());
    }
}
