//! Finds gated commands in a command line. Advisory by design: it catches
//! the forms an agent usually writes, and errs towards blocking.
//!
//! Rather than modelling wrappers such as `sudo`, `env`, `xargs` or
//! `find -exec`, it looks at every word of every simple command: a word
//! naming the gate's program, followed (after options) by the gate's
//! remaining words, is a hit. That makes `echo git push` a hit too, which is
//! the accepted price. Shell scripts passed as strings (`sh -c`, `eval`,
//! heredocs fed to a shell) are read recursively. Input the reader can't
//! parse falls back to a coarse word search.

use std::collections::{BTreeSet, VecDeque};

use mezha_spec::CommandPrefix;

use crate::shell::{self, Command, MAX_DEPTH, ParseError, Word};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Hit {
    /// The gate at this index in the list passed in.
    Gate(usize),
    /// The agent is running `mezha approve` itself.
    SelfApproval,
    /// Nested too deeply to read.
    TooDeep,
}

/// Shells whose `-c` argument, or heredoc, is itself a command line.
const SHELLS: [&str; 5] = ["sh", "bash", "zsh", "dash", "ksh"];

/// Global options that take a separate value, for programs gates often name.
/// For other programs an option without `=` may or may not take one, and
/// both readings are tried.
const VALUE_OPTIONS: [(&str, &[&str]); 5] = [
    (
        "git",
        &[
            "-C",
            "-c",
            "--git-dir",
            "--work-tree",
            "--namespace",
            "--config-env",
            "--super-prefix",
        ],
    ),
    (
        "docker",
        &[
            "-c",
            "--context",
            "-H",
            "--host",
            "-l",
            "--log-level",
            "--config",
            "--tlscacert",
            "--tlscert",
            "--tlskey",
        ],
    ),
    (
        "kubectl",
        &[
            "-n",
            "--namespace",
            "--context",
            "--cluster",
            "--user",
            "--kubeconfig",
            "-s",
            "--server",
            "--token",
            "--as",
            "--as-group",
            "--as-uid",
            "--request-timeout",
            "--cache-dir",
            "--certificate-authority",
            "--client-certificate",
            "--client-key",
            "--tls-server-name",
            "-v",
        ],
    ),
    (
        "helm",
        &[
            "-n",
            "--namespace",
            "--kube-context",
            "--kubeconfig",
            "--kube-apiserver",
            "--kube-as-user",
            "--kube-as-group",
            "--kube-ca-file",
            "--kube-token",
            "--registry-config",
            "--repository-cache",
            "--repository-config",
            "--burst-limit",
            "--qps",
        ],
    ),
    (
        "npm",
        &[
            "-w",
            "--workspace",
            "--prefix",
            "--registry",
            "--userconfig",
            "--globalconfig",
            "--cache",
            "--loglevel",
            "--otp",
        ],
    ),
];

/// The first gate (or self-approval) that `command` runs, if any.
pub fn scan(command: &str, gates: &[CommandPrefix]) -> Option<Hit> {
    scan_at(command, gates, 0)
}

fn scan_at(src: &str, gates: &[CommandPrefix], depth: usize) -> Option<Hit> {
    if depth > MAX_DEPTH {
        return Some(Hit::TooDeep);
    }
    match shell::parse(src, depth) {
        Err(ParseError::TooDeep) => Some(Hit::TooDeep),
        Err(ParseError::Unterminated(_)) => coarse(src, gates),
        Ok(commands) => commands.iter().find_map(|c| scan_command(c, gates, depth)),
    }
}

fn scan_command(cmd: &Command, gates: &[CommandPrefix], depth: usize) -> Option<Hit> {
    let words = &cmd.words;
    for (i, word) in words.iter().enumerate() {
        let name = program_name(word);
        let after = &words[i + 1..];
        for (g, gate) in gates.iter().enumerate() {
            let hit = match &name {
                Some(n) => n == gate.program() && follows(after, gate.program(), gate.rest(), true),
                // `$x push`: the program is unknown, so a literal match on
                // the rest of the gate is enough.
                None => {
                    !gate.rest().is_empty() && follows(after, gate.program(), gate.rest(), false)
                }
            };
            if hit {
                return Some(Hit::Gate(g));
            }
        }
        let Some(name) = name else { continue };
        if name == "mezha"
            && follows(after, "mezha", &["approve".to_string()], false)
            && !after.iter().any(|w| w.text == "--status")
        {
            return Some(Hit::SelfApproval);
        }
        if SHELLS.contains(&name.as_str())
            && let Some(script) = shell_script(after)
            && let Some(hit) = scan_at(script, gates, depth + 1)
        {
            return Some(hit);
        }
        if name == "eval" {
            let script: Vec<&str> = after.iter().map(|w| w.text.as_str()).collect();
            if let Some(hit) = scan_at(&script.join(" "), gates, depth + 1) {
                return Some(hit);
            }
        }
    }
    let runs_shell = words
        .iter()
        .filter_map(program_name)
        .any(|n| SHELLS.contains(&n.as_str()));
    cmd.heredocs.iter().find_map(|doc| {
        if runs_shell {
            scan_at(&doc.body, gates, depth + 1)
        } else if !doc.quoted {
            // An unquoted body expands `$(...)`; read it coarsely.
            coarse(&doc.body, gates)
        } else {
            None
        }
    })
}

/// The program a word names: its last path segment, without `.exe`, in
/// lowercase (`GIT` runs git on a case-insensitive file system). `None` when
/// the word is only known at run time.
fn program_name(word: &Word) -> Option<String> {
    if word.dynamic {
        return None;
    }
    Some(base_name(&word.text))
}

fn base_name(text: &str) -> String {
    let last = text.rsplit(['/', '\\']).next().unwrap_or(text);
    let lower = last.to_ascii_lowercase();
    match lower.strip_suffix(".exe") {
        Some(stem) => stem.to_string(),
        None => lower,
    }
}

#[derive(Clone, Copy)]
enum Takes {
    Value,
    NoValue,
    Maybe,
}

fn takes_value(program: &str, option: &str) -> Takes {
    if option.contains('=') {
        return Takes::NoValue;
    }
    match VALUE_OPTIONS.iter().find(|(p, _)| *p == program) {
        Some((_, options)) if options.contains(&option) => Takes::Value,
        Some(_) => Takes::NoValue,
        None => Takes::Maybe,
    }
}

/// Whether `words` (what follows the program) go on with `rest`, skipping
/// options. Every reading of ambiguous options is tried; `dynamic` lets a
/// run-time word stand for any expected word.
fn follows<S: AsRef<str>>(words: &[Word], program: &str, rest: &[S], dynamic: bool) -> bool {
    if rest.is_empty() {
        return true;
    }
    let mut queue = VecDeque::from([(0usize, 0usize)]);
    let mut seen = BTreeSet::new();
    while let Some((j, k)) = queue.pop_front() {
        if k == rest.len() {
            return true;
        }
        if j >= words.len() || !seen.insert((j, k)) {
            continue;
        }
        let word = &words[j];
        let text = word.text.as_str();
        if word.dynamic {
            if dynamic {
                queue.push_back((j + 1, k + 1));
            }
            queue.push_back((j + 1, k));
        } else if text == "--" {
            queue.push_back((j + 1, k));
        } else if text.len() > 1 && text.starts_with('-') {
            match takes_value(program, text) {
                Takes::Value => queue.push_back((j + 2, k)),
                Takes::NoValue => queue.push_back((j + 1, k)),
                Takes::Maybe => {
                    queue.push_back((j + 1, k));
                    queue.push_back((j + 2, k));
                }
            }
        } else if text == rest[k].as_ref() {
            queue.push_back((j + 1, k + 1));
        }
    }
    false
}

/// The script of `sh -c script` (any option cluster containing `c`), or
/// `None` when the shell reads a file or stdin.
fn shell_script(args: &[Word]) -> Option<&str> {
    let mut command_mode = false;
    let mut i = 0;
    while let Some(arg) = args.get(i) {
        i += 1;
        if arg.dynamic {
            return None;
        }
        let text = arg.text.as_str();
        if text == "--" || text.starts_with("--") {
            continue;
        }
        if text.len() > 1 && (text.starts_with('-') || text.starts_with('+')) {
            command_mode |= text.starts_with('-') && text.contains('c');
            if text.contains('o') {
                i += 1; // `-o pipefail`: the option name is not the script
            }
            continue;
        }
        return command_mode.then_some(text);
    }
    None
}

/// The fallback for text the reader can't parse: with quotes and
/// backslashes removed, does any line name a gate's program followed, in
/// order, by the gate's other words?
fn coarse(text: &str, gates: &[CommandPrefix]) -> Option<Hit> {
    let cleaned: String = text
        .chars()
        .filter(|c| !matches!(c, '\'' | '"' | '\\'))
        .collect();
    for line in cleaned.lines() {
        let tokens: Vec<String> = line
            .split(|c: char| c.is_whitespace() || ";&|()<>{}`$=".contains(c))
            .filter(|t| !t.is_empty())
            .map(base_name)
            .collect();
        for (g, gate) in gates.iter().enumerate() {
            if in_order(&tokens, gate.program(), gate.rest()) {
                return Some(Hit::Gate(g));
            }
        }
        if in_order(&tokens, "mezha", &["approve".to_string()])
            && !tokens.iter().any(|t| t == "--status")
        {
            return Some(Hit::SelfApproval);
        }
    }
    None
}

fn in_order(tokens: &[String], program: &str, rest: &[String]) -> bool {
    tokens.iter().enumerate().any(|(i, t)| {
        if t != program {
            return false;
        }
        let mut wanted = rest.iter();
        let mut next = wanted.next();
        for token in &tokens[i + 1..] {
            if next.is_some_and(|w| w == token) {
                next = wanted.next();
            }
        }
        next.is_none()
    })
}
