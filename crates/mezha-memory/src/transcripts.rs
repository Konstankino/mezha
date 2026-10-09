//! Claude Code's session transcripts, read leniently. The format is
//! internal and changes between versions, so anything unexpected is skipped,
//! never an error. Files are only opened for reading, so their times stay
//! as they were.
//!
//! Layout (Claude Code 2.1.285): `<config>/projects/<dir>/<session>.jsonl`
//! for a session, and `<dir>/<session>/subagents/[<group>/]agent-<id>.jsonl`
//! plus `agent-<id>.meta.json` for each subagent it started. `<dir>` is the
//! session's working directory, mangled by [`project_dir_name`].

use std::collections::{BTreeSet, HashSet};
use std::fs;
use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

use serde_json::Value;

use crate::time::parse_iso;

/// Lines longer than this are skipped.
const MAX_LINE: usize = 4 << 20;
/// Transcripts larger than this are skipped.
const MAX_FILE: u64 = 64 << 20;
/// How deep subagent files may sit under `subagents/`.
const MAX_DEPTH: usize = 3;
/// Later messages of yours kept for a session started as an agent.
const MAX_FOLLOWUPS: usize = 3;
/// A failed call's input, as shown in a digest.
const MAX_INPUT: usize = 200;
/// Claude Code keeps this much of a project directory's name.
const NAME_MAX: usize = 200;

/// Where Claude Code keeps its state: `$CLAUDE_CONFIG_DIR`, else `~/.claude`.
pub fn config_dir(var: impl Fn(&str) -> Option<String>, home: &Path) -> PathBuf {
    match var("CLAUDE_CONFIG_DIR").filter(|v| !v.is_empty()) {
        Some(dir) => PathBuf::from(dir),
        None => home.join(".claude"),
    }
}

/// The directory name Claude Code gives a working directory under
/// `projects/`: every UTF-16 unit outside `[A-Za-z0-9]` becomes `-`, and a
/// name over 200 characters is cut and gets a hash of the path. The
/// mapping loses information, so it is only ever computed forwards.
pub fn project_dir_name(path: &str) -> String {
    let name: String = path
        .encode_utf16()
        .map(|unit| match u8::try_from(unit) {
            Ok(b) if b.is_ascii_alphanumeric() => b as char,
            _ => '-',
        })
        .collect();
    if name.len() <= NAME_MAX {
        return name;
    }
    let mut hash: i32 = 0;
    for unit in path.encode_utf16() {
        hash = hash.wrapping_mul(31).wrapping_add(i32::from(unit));
    }
    format!("{}-{}", &name[..NAME_MAX], base36(i64::from(hash).abs()))
}

fn base36(mut n: i64) -> String {
    const DIGITS: &[u8] = b"0123456789abcdefghijklmnopqrstuvwxyz";
    if n == 0 {
        return "0".into();
    }
    let mut out = Vec::new();
    while n > 0 {
        out.push(DIGITS[(n % 36) as usize]);
        n /= 36;
    }
    out.reverse();
    String::from_utf8(out).unwrap_or_default()
}

/// One run of a role: a subagent, or a whole session started as that agent
/// (`claude --agent <role>`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Run {
    pub role: String,
    /// The subagent's id, or the session id for a session run.
    pub id: String,
    pub session: String,
    pub kind: RunKind,
    /// Unix seconds of the first and last record.
    pub start: i64,
    pub end: i64,
    pub branch: Option<String>,
    /// What the agent was asked to do.
    pub task: String,
    /// The agent's last message.
    pub final_text: String,
    pub failures: Vec<Failure>,
    /// What you said next: your next prompt in the parent session after a
    /// subagent finished, or your later prompts in a session run.
    pub followups: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunKind {
    Subagent,
    Session,
}

/// A tool call that failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Failure {
    pub tool: String,
    /// A short form of the input: the command, the path, or compact JSON.
    pub input: String,
    pub output: String,
}

#[derive(Debug, Default)]
pub struct Collected {
    /// Oldest first.
    pub runs: Vec<Run>,
    /// Sessions of this project that were read.
    pub sessions: usize,
    /// Lines that weren't JSON objects or were too long.
    pub skipped_lines: usize,
    /// Transcripts over the size limit, not read.
    pub skipped_files: usize,
}

/// The runs of `roles` that ended after `since`, from the sessions whose
/// working directory was inside one of `roots` (the project and its
/// worktrees). `projects` is `<config>/projects`; `dir_override` is
/// `$CLAUDE_CODE_PROJECT_DIR_NAME` when Claude Code would honour it.
pub fn collect(
    projects: &Path,
    roots: &[PathBuf],
    roles: &BTreeSet<String>,
    since: i64,
    dir_override: Option<&str>,
) -> Collected {
    let mut out = Collected::default();
    let sources = project_sources(projects, roots, dir_override);
    let mut seen = HashSet::new();
    for file in &sources.files {
        session(file, &sources.roots, roles, since, &mut seen, &mut out);
    }
    out.runs.sort_by(|a, b| (a.end, &a.id).cmp(&(b.end, &b.id)));
    out
}

/// Where a project's sessions may be.
#[derive(Debug, Clone, Default)]
pub struct Sources {
    /// Candidate session files (`<dir>/<session>.jsonl`), sorted.
    pub files: Vec<PathBuf>,
    /// The spellings of the roots a record's `cwd` must fall within.
    pub roots: Vec<String>,
}

/// The session files in the project directories of `roots` (and their
/// subdirectories, such as worktrees under `.claude/worktrees`). A file is
/// only a candidate: [`in_roots`] decides from its records.
pub fn project_sources(projects: &Path, roots: &[PathBuf], dir_override: Option<&str>) -> Sources {
    let mut roots_text: Vec<String> = Vec::new();
    for root in roots {
        roots_text.push(path_text(root));
        if let Ok(canonical) = fs::canonicalize(root) {
            roots_text.push(path_text(&canonical));
        }
    }
    roots_text.sort();
    roots_text.dedup();
    let prefixes: Vec<String> = roots_text
        .iter()
        .map(|r| {
            let name = project_dir_name(r);
            name[..name.len().min(NAME_MAX)].to_string()
        })
        .collect();
    let mut files = Vec::new();
    for dir in sorted_entries(projects) {
        let Some(name) = dir.file_name().map(|n| n.to_string_lossy().into_owned()) else {
            continue;
        };
        let wanted = dir_override == Some(name.as_str())
            || prefixes
                .iter()
                .any(|p| name == *p || name.starts_with(&format!("{p}-")));
        if !wanted || !dir.is_dir() {
            continue;
        }
        files.extend(
            sorted_entries(&dir)
                .into_iter()
                .filter(|f| f.extension().is_some_and(|e| e == "jsonl") && f.is_file()),
        );
    }
    Sources {
        files,
        roots: roots_text,
    }
}

/// True when one of the records ran with its `cwd` inside one of `roots`.
pub fn in_roots(records: &[Value], roots: &[String]) -> bool {
    records.iter().any(|r| {
        r.get("cwd")
            .and_then(Value::as_str)
            .is_some_and(|cwd| roots.iter().any(|root| within(cwd, root)))
    })
}

/// The subagent transcripts a session started, with their roles.
pub fn subagent_files(session_file: &Path) -> Vec<(PathBuf, Option<String>)> {
    let mut found = Vec::new();
    walk_subagents(
        &session_file.with_extension("").join("subagents"),
        0,
        &mut found,
    );
    found
        .into_iter()
        .map(|path| {
            let role = meta_role(&path);
            (path, role)
        })
        .collect()
}

/// One session file and the subagents it started.
fn session(
    file: &Path,
    roots: &[String],
    roles: &BTreeSet<String>,
    since: i64,
    seen: &mut HashSet<(String, String)>,
    out: &mut Collected,
) {
    let Some(sid) = file.file_stem().map(|s| s.to_string_lossy().into_owned()) else {
        return;
    };
    let subagents: Vec<(PathBuf, String)> = subagent_files(file)
        .into_iter()
        .filter_map(|(path, role)| {
            let role = role?;
            roles.contains(&role).then_some((path, role))
        })
        .collect();
    let newest = subagents
        .iter()
        .map(|(p, _)| mtime(p))
        .chain([mtime(file)])
        .max()
        .unwrap_or(0);
    if newest < since {
        return;
    }
    let Some(parent) = read_records(file, out) else {
        return;
    };
    if !in_roots(&parent, roots) {
        return;
    }
    out.sessions += 1;

    // A session started as one of the roles is a run of its own.
    let setting = parent
        .iter()
        .rev()
        .find(|r| r.get("type").and_then(Value::as_str) == Some("agent-setting"))
        .and_then(|r| r.get("agentSetting").and_then(Value::as_str));
    if let Some(role) = setting.filter(|r| roles.contains(*r)) {
        let main: Vec<&Value> = parent
            .iter()
            .filter(|r| r.get("isSidechain").and_then(Value::as_bool) != Some(true))
            .collect();
        let prompts: Vec<String> = main.iter().filter_map(|r| human_text(r)).collect();
        if let Some(mut run) = build(&main, role, &sid, &sid, RunKind::Session) {
            if let Some((first, rest)) = prompts.split_first() {
                run.task = first.clone();
                run.followups = rest.iter().take(MAX_FOLLOWUPS).cloned().collect();
            }
            if run.end > since && seen.insert((run.role.clone(), run.id.clone())) {
                out.runs.push(run);
            }
        }
    }

    for (path, role) in subagents {
        let Some(records) = read_records(&path, out) else {
            continue;
        };
        let refs: Vec<&Value> = records.iter().collect();
        let id = path
            .file_stem()
            .and_then(|s| s.to_str())
            .and_then(|s| s.strip_prefix("agent-"))
            .unwrap_or_default()
            .to_string();
        let Some(mut run) = build(&refs, &role, &id, &sid, RunKind::Subagent) else {
            continue;
        };
        if run.end <= since || !seen.insert((run.role.clone(), run.id.clone())) {
            continue;
        }
        run.followups = followup(&parent, &id).into_iter().collect();
        out.runs.push(run);
    }
}

/// A run from its records, or `None` when they hold nothing to learn from.
fn build(records: &[&Value], role: &str, id: &str, session: &str, kind: RunKind) -> Option<Run> {
    let times: Vec<i64> = records
        .iter()
        .filter_map(|r| r.get("timestamp").and_then(Value::as_str))
        .filter_map(parse_iso)
        .collect();
    let (start, end) = (*times.iter().min()?, *times.iter().max()?);
    let task = records
        .iter()
        .find(|r| r.get("type").and_then(Value::as_str) == Some("user"))
        .map(|r| content_text(message_content(r)))
        .unwrap_or_default();
    let branch = records
        .iter()
        .find_map(|r| r.get("gitBranch").and_then(Value::as_str))
        .filter(|b| !b.is_empty())
        .map(str::to_string);

    let final_text = final_text(records);
    let failures = failures(records);
    if task.is_empty() && final_text.is_empty() && failures.is_empty() {
        return None;
    }
    Some(Run {
        role: role.to_string(),
        id: id.to_string(),
        session: session.to_string(),
        kind,
        start,
        end,
        branch,
        task,
        final_text,
        failures,
        followups: Vec::new(),
    })
}

/// The agent's last message: the text blocks of the last assistant message
/// that has text (one message is split into records sharing `message.id`).
pub fn final_text(records: &[&Value]) -> String {
    // The last assistant message with text; its blocks share `message.id`.
    let mut final_id: Option<&str> = None;
    for r in records {
        if r.get("type").and_then(Value::as_str) == Some("assistant")
            && !content_text(message_content(r)).is_empty()
        {
            final_id = r
                .pointer("/message/id")
                .and_then(Value::as_str)
                .or(Some(""));
        }
    }
    match final_id {
        Some(mid) => records
            .iter()
            .filter(|r| r.get("type").and_then(Value::as_str) == Some("assistant"))
            .filter(|r| {
                r.pointer("/message/id")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    == mid
            })
            .map(|r| content_text(message_content(r)))
            .filter(|t| !t.is_empty())
            .collect::<Vec<_>>()
            .join("\n"),
        None => String::new(),
    }
}

/// The tool calls that failed: a result marked `is_error`, or one whose
/// `toolUseResult` is an error string.
pub fn failures(records: &[&Value]) -> Vec<Failure> {
    let mut calls = std::collections::HashMap::new();
    let mut failures = Vec::new();
    for r in records {
        let Some(blocks) = message_content(r).as_array() else {
            continue;
        };
        for block in blocks {
            match block.get("type").and_then(Value::as_str) {
                Some("tool_use") => {
                    if let Some(tid) = block.get("id").and_then(Value::as_str) {
                        calls.insert(tid.to_string(), block);
                    }
                }
                Some("tool_result") => {
                    let flagged = block.get("is_error").and_then(Value::as_bool) == Some(true)
                        || r.get("toolUseResult")
                            .and_then(Value::as_str)
                            .is_some_and(|t| t.starts_with("Error"));
                    if !flagged {
                        continue;
                    }
                    let call = block
                        .get("tool_use_id")
                        .and_then(Value::as_str)
                        .and_then(|tid| calls.get(tid));
                    failures.push(Failure {
                        tool: call
                            .and_then(|c| c.get("name").and_then(Value::as_str))
                            .unwrap_or("unknown")
                            .to_string(),
                        input: call.map(|c| short_input(c)).unwrap_or_default(),
                        output: content_text(block.get("content").unwrap_or(&Value::Null)),
                    });
                }
                _ => {}
            }
        }
    }
    failures
}

/// Your next prompt in the parent session after subagent `id` finished:
/// after the tool result that carries its id (a foreground run), or the
/// task notification that names it (a background run).
fn followup(parent: &[Value], id: &str) -> Option<String> {
    let tag = format!("<task-id>{id}</task-id>");
    let done = parent.iter().position(|r| {
        let result = r.get("toolUseResult");
        let finished = result
            .and_then(|t| t.get("agentId"))
            .and_then(Value::as_str)
            == Some(id)
            && result.and_then(|t| t.get("status")).and_then(Value::as_str)
                != Some("async_launched");
        finished
            || (r.get("type").and_then(Value::as_str) == Some("user")
                && content_text(message_content(r)).contains(&tag))
    })?;
    parent[done + 1..].iter().find_map(human_text)
}

/// The text of a prompt a person typed: not a tool result, a command's
/// output, a notification, a summary or other text Claude Code adds.
pub fn human_text(record: &Value) -> Option<String> {
    let flag = |key: &str| record.get(key).and_then(Value::as_bool) == Some(true);
    if record.get("type").and_then(Value::as_str) != Some("user")
        || flag("isMeta")
        || flag("isCompactSummary")
        || flag("isSidechain")
        || record.get("toolUseResult").is_some()
    {
        return None;
    }
    if let Some(kind) = record.pointer("/origin/kind").and_then(Value::as_str)
        && kind != "human"
    {
        return None;
    }
    let content = message_content(record);
    if content.as_array().is_some_and(|blocks| {
        blocks
            .iter()
            .any(|b| b.get("type").and_then(Value::as_str) == Some("tool_result"))
    }) {
        return None;
    }
    let text = content_text(content);
    let trimmed = text.trim_start();
    const ADDED: [&str; 10] = [
        "<command-name>",
        "<command-message>",
        "<command-args>",
        "<local-command-",
        "<task-notification>",
        "<system-reminder>",
        "[Request interrupted",
        "Another Claude session sent a message:",
        "Base directory for this skill:",
        "Caveat: The messages below",
    ];
    if trimmed.is_empty() || ADDED.iter().any(|p| trimmed.starts_with(p)) {
        return None;
    }
    Some(text)
}

pub fn message_content(record: &Value) -> &Value {
    record.pointer("/message/content").unwrap_or(&Value::Null)
}

/// The text of message content: a string, or the text blocks of an array.
pub fn content_text(content: &Value) -> String {
    match content {
        Value::String(s) => s.clone(),
        Value::Array(blocks) => blocks
            .iter()
            .filter_map(|b| match b.get("type").and_then(Value::as_str) {
                Some("text") => b.get("text").and_then(Value::as_str).map(str::to_string),
                Some("image") => Some("[image]".into()),
                _ => None,
            })
            .filter(|t| !t.is_empty())
            .collect::<Vec<_>>()
            .join("\n"),
        _ => String::new(),
    }
}

fn short_input(call: &Value) -> String {
    let input = call.get("input").unwrap_or(&Value::Null);
    let text = ["command", "file_path", "path", "pattern", "url"]
        .iter()
        .find_map(|k| input.get(*k).and_then(Value::as_str).map(str::to_string))
        .unwrap_or_else(|| input.to_string());
    match text.char_indices().nth(MAX_INPUT) {
        Some((i, _)) => format!("{}…", &text[..i]),
        None => text,
    }
}

/// The records of one transcript, deduplicated by `uuid` (resumed and
/// forked sessions copy earlier records in). `None` when it can't be read.
fn read_records(path: &Path, out: &mut Collected) -> Option<Vec<Value>> {
    match read_transcript(path) {
        Ok(t) => {
            out.skipped_lines += t.skipped_lines;
            Some(t.records)
        }
        Err(Unread::TooLarge) => {
            out.skipped_files += 1;
            None
        }
        Err(Unread::Unreadable) => None,
    }
}

/// A transcript's records, deduplicated by `uuid`.
#[derive(Debug, Clone, Default)]
pub struct Transcript {
    pub records: Vec<Value>,
    /// Lines that weren't JSON objects or were too long.
    pub skipped_lines: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unread {
    TooLarge,
    Unreadable,
}

/// Reads one transcript leniently. Resumed and forked sessions copy earlier
/// records in, so a record whose `uuid` was seen is skipped.
pub fn read_transcript(path: &Path) -> Result<Transcript, Unread> {
    let file = fs::File::open(path).map_err(|_| Unread::Unreadable)?;
    if file.metadata().map_err(|_| Unread::Unreadable)?.len() > MAX_FILE {
        return Err(Unread::TooLarge);
    }
    let mut reader = BufReader::new(file.take(MAX_FILE));
    let mut out = Transcript::default();
    let mut uuids = HashSet::new();
    let mut line = Vec::new();
    loop {
        line.clear();
        match reader.read_until(b'\n', &mut line) {
            Ok(0) => break,
            Ok(_) => {}
            Err(_) => return Err(Unread::Unreadable),
        }
        if line.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        let value = (line.len() <= MAX_LINE)
            .then(|| serde_json::from_slice::<Value>(&line).ok())
            .flatten();
        let Some(value @ Value::Object(_)) = value else {
            out.skipped_lines += 1;
            continue;
        };
        if let Some(uuid) = value.get("uuid").and_then(Value::as_str)
            && !uuids.insert(uuid.to_string())
        {
            continue;
        }
        out.records.push(value);
    }
    Ok(out)
}

/// The role in a subagent's `.meta.json`: `customAgentType` for a teammate,
/// otherwise `agentType`.
fn meta_role(transcript: &Path) -> Option<String> {
    let meta = transcript.with_extension("meta.json");
    let text = fs::read_to_string(meta).ok()?;
    let value: Value = serde_json::from_str(&text).ok()?;
    ["customAgentType", "agentType"]
        .iter()
        .find_map(|k| value.get(*k).and_then(Value::as_str))
        .filter(|r| !r.is_empty())
        .map(str::to_string)
}

fn walk_subagents(dir: &Path, depth: usize, out: &mut Vec<PathBuf>) {
    if depth > MAX_DEPTH {
        return;
    }
    for entry in sorted_entries(dir) {
        let Ok(meta) = fs::symlink_metadata(&entry) else {
            continue;
        };
        let name = entry
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        if meta.is_dir() {
            walk_subagents(&entry, depth + 1, out);
        } else if meta.is_file() && name.starts_with("agent-") && name.ends_with(".jsonl") {
            out.push(entry);
        }
    }
}

fn sorted_entries(dir: &Path) -> Vec<PathBuf> {
    let mut entries: Vec<PathBuf> = fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.path())
        .collect();
    entries.sort();
    entries
}

fn mtime(path: &Path) -> i64 {
    fs::metadata(path)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map_or(0, |d| d.as_secs() as i64)
}

fn path_text(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

/// True when `path` is `root` or inside it.
fn within(path: &str, root: &str) -> bool {
    let path = path.replace('\\', "/");
    let root = root.trim_end_matches('/');
    path == root || path.starts_with(&format!("{root}/"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn project_dir_names() {
        assert_eq!(
            project_dir_name("/Users/dev/Projects/mezha"),
            "-Users-dev-Projects-mezha"
        );
        // A Cyrillic letter is one UTF-16 unit, an emoji two.
        assert_eq!(project_dir_name("/tmp/x/проєкт 🦀.d"), "-tmp-x-----------d");
        // Values computed with Claude Code's own functions.
        let long = format!(
            "/Users/dev/{}проєкт 🦀",
            "very-long-directory-name/".repeat(9)
        );
        assert_eq!(
            project_dir_name(&long),
            "-Users-dev-very-long-directory-name-very-long-directory-name-very-long-directory-name-very-long-directory-name-very-long-directory-name-very-long-directory-name-very-long-directory-name-very-long-dire-pi1u95"
        );
    }

    #[test]
    fn within_roots() {
        assert!(within("/a/b", "/a/b"));
        assert!(within("/a/b/c", "/a/b/"));
        assert!(!within("/a/bc", "/a/b"));
    }
}
