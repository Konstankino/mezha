//! The dream guard: the PreToolUse hook of a `mezha dream` run. The dreamer
//! may read the worktree and its staged memory, and write only flat
//! Markdown files in the staged memory directory. Every other tool blocks.
//!
//! It is *advisory*, like every hook: the boundary is Claude Code's
//! `--restricted` mode with `dontAsk` and a single allow rule, and the
//! review mezha runs on the staged bytes after the dreamer exits.

use std::path::{Path, PathBuf};

use serde_json::{Map, Value};

use crate::paths::{resolve, within};
use crate::{MAX_INPUT, Outcome};

pub const NAME: &str = "dream-guard";

const ADVISORY: &str = "(mezha dream guard: advisory. The boundary is Claude Code's restricted mode and mezha's review of the staged memory.)";

/// mezha writes this file in every memory directory; the dreamer may not.
const CHANGELOG: &str = "changelog.md";

/// Decides one tool call of the dreamer. `read` are the directories it may
/// read (the worktree); `write` is the staged memory directory, which it may
/// also read.
pub fn run(read: &[PathBuf], write: Option<&Path>, input: &[u8]) -> Outcome {
    let Some(write) = write else {
        return Outcome::block("mezha hook: dream-guard needs --write; rerun `mezha dream`");
    };
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
    let Some(tool) = event.get("tool_name").and_then(Value::as_str) else {
        return Outcome::block("mezha: PreToolUse event without tool_name");
    };
    let empty = Map::new();
    let input = event
        .get("tool_input")
        .and_then(Value::as_object)
        .unwrap_or(&empty);
    let cwd = event
        .get("cwd")
        .and_then(Value::as_str)
        .filter(|c| !c.is_empty())
        .map(PathBuf::from);
    let write = resolve(write);
    let mut readable: Vec<PathBuf> = read.iter().map(|d| resolve(d)).collect();
    readable.push(write.clone());

    let decision = match tool {
        "Read" => {
            required(input, "file_path").and_then(|p| check_read(p, cwd.as_deref(), &readable))
        }
        "Grep" | "Glob" => {
            let pattern_key = if tool == "Glob" { "pattern" } else { "glob" };
            match input.get(pattern_key).and_then(Value::as_str) {
                Some(pattern) if escapes(pattern) => Err(format!(
                    "{tool} {pattern_key} `{pattern}` is absolute or climbs out with `..`"
                )),
                _ => {
                    let path = input
                        .get("path")
                        .and_then(Value::as_str)
                        .filter(|p| !p.is_empty());
                    match (path, cwd.as_deref()) {
                        (Some(p), _) => check_read(p, cwd.as_deref(), &readable),
                        (None, Some(dir)) => check_read(&dir.to_string_lossy(), None, &readable),
                        (None, None) => Err(format!("{tool} without a path or a cwd")),
                    }
                }
            }
        }
        "Edit" | "Write" | "MultiEdit" => {
            required(input, "file_path").and_then(|p| check_write(p, cwd.as_deref(), &write))
        }
        other => Err(format!(
            "the dreamer may use only Read, Grep, Glob, Edit and Write, not {other}"
        )),
    };
    match decision {
        Ok(()) => Outcome::allow(),
        Err(why) => Outcome::block(format!("mezha: {why}.\n{ADVISORY}")),
    }
}

fn required<'a>(input: &'a Map<String, Value>, key: &str) -> Result<&'a str, String> {
    input
        .get(key)
        .and_then(Value::as_str)
        .filter(|p| !p.is_empty())
        .ok_or_else(|| format!("the call has no {key}"))
}

/// The path as given, made absolute against `cwd`, refusing `.` and `..`
/// components outright: folding them before resolving symlinks would let
/// `link/../x` mean something else on disk.
fn absolute(path: &str, cwd: Option<&Path>) -> Result<PathBuf, String> {
    if path
        .split(['/', '\\'])
        .any(|part| part == "." || part == "..")
    {
        return Err(format!("`{path}` has a `.` or `..` component"));
    }
    let path = Path::new(path);
    if path.is_absolute() {
        return Ok(path.to_path_buf());
    }
    match cwd {
        Some(dir) => Ok(dir.join(path)),
        None => Err(format!(
            "`{}` is relative and the event has no cwd",
            path.display()
        )),
    }
}

fn check_read(path: &str, cwd: Option<&Path>, readable: &[PathBuf]) -> Result<(), String> {
    let full = resolve(&absolute(path, cwd)?);
    if readable.iter().any(|dir| within(&full, dir)) {
        Ok(())
    } else {
        Err(format!(
            "`{path}` is outside the worktree and the staged memory, so the dreamer may not read it"
        ))
    }
}

fn check_write(path: &str, cwd: Option<&Path>, write: &Path) -> Result<(), String> {
    let full = resolve(&absolute(path, cwd)?);
    let flat = full
        .parent()
        .is_some_and(|parent| within(parent, write) && within(write, parent));
    if !flat {
        return Err(format!(
            "`{path}` is not directly in the staged memory directory {}",
            write.display()
        ));
    }
    let name = full
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    if name.eq_ignore_ascii_case(CHANGELOG) {
        return Err("CHANGELOG.md is written by mezha, not the dreamer".into());
    }
    if !memory_file_name(&name) {
        return Err(format!(
            "`{name}` is not a memory file name: use letters, digits, `.`, `_` or `-`, ending in .md"
        ));
    }
    Ok(())
}

/// `MEMORY.md` or a topic file such as `db-migrations.md`.
fn memory_file_name(name: &str) -> bool {
    let Some(stem) = name.strip_suffix(".md") else {
        return false;
    };
    let mut chars = stem.chars();
    chars.next().is_some_and(|c| c.is_ascii_alphanumeric())
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

/// A glob that could match outside its base directory.
fn escapes(pattern: &str) -> bool {
    pattern.starts_with(['/', '\\', '~'])
        || pattern.get(1..3) == Some(":\\")
        || pattern.get(1..3) == Some(":/")
        || pattern.split(['/', '\\']).any(|part| part == "..")
}
