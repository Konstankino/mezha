//! The audit log (OWASP AST09, "bilateral receipts"): the approval gate
//! appends an admission record for every tool call it sees, before the call
//! runs, and the `audit-outcome` hook appends how the call ended. Both carry
//! the same `attempt_id`, derived from the fields named in `preimage`, so
//! anyone can recompute the join.
//!
//! Records hold digests, not content: tool input can carry secrets or PHI,
//! and the session transcript keeps the content anyway. Files are
//! `~/.mezha/audit/<sha256(repo root)>/<YYYYMMDD>.jsonl`, appended with one
//! write per record and no lock, so a slow disk can't stall the hook into
//! Claude Code's timeout, which would let the call through.
//!
//! The log is protected by the boundary that protects approvals: sandboxed
//! commands can't write `~/.mezha`, and a deny rule and the gate keep the
//! file tools out. It is evidence against the agent, not against you: any
//! process of yours outside the sandbox can edit it, so it isn't signed.

use std::io::{self, Write};
use std::path::{Path, PathBuf};

use mezha_broker::{approvals, sha256_hex, utc_stamp};
use serde_json::{Map, Value, json};

use crate::{Env, Outcome};

pub const NAME: &str = "audit-outcome";

/// The record format.
const VERSION: u32 = 1;

/// Where a project's audit log lives; events without a project directory
/// go to `no-project`.
pub fn dir(home: &Path, root: Option<&Path>) -> PathBuf {
    let audit = approvals::mezha_home(home).join("audit");
    match root {
        Some(root) => audit.join(approvals::root_hash(root)),
        None => audit.join("no-project"),
    }
}

/// The fields an attempt's id is derived from.
const PREIMAGE: [&str; 2] = ["session_id", "tool_use_id"];

/// `sha256:<hex>` of the event's `session_id` and `tool_use_id`, joined
/// with a NUL; of the whole event when either is missing.
fn attempt_id(event: &Map<String, Value>, raw: &[u8]) -> (String, Value) {
    let field = |k: &str| event.get(k).and_then(Value::as_str);
    match (field(PREIMAGE[0]), field(PREIMAGE[1])) {
        (Some(session), Some(call)) => (
            format!(
                "sha256:{}",
                sha256_hex(format!("{session}\0{call}").as_bytes())
            ),
            json!(PREIMAGE),
        ),
        _ => (format!("sha256:{}", sha256_hex(raw)), json!(["event"])),
    }
}

/// The parts of an event every record repeats.
fn common(kind: &str, event: &Map<String, Value>, raw: &[u8], env: &Env) -> Map<String, Value> {
    let (id, preimage) = attempt_id(event, raw);
    let mut r = Map::new();
    r.insert("v".into(), json!(VERSION));
    r.insert("type".into(), json!(kind));
    r.insert("attempt_id".into(), json!(id));
    r.insert("preimage".into(), preimage);
    // `prompt_id` ties every call to the user prompt that started it, and
    // `agent_id` to the subagent run that made it.
    for key in [
        "session_id",
        "prompt_id",
        "tool_use_id",
        "agent_id",
        "agent_type",
        "tool_name",
    ] {
        if let Some(v) = event.get(key).filter(|v| v.is_string()) {
            r.insert(key.into(), v.clone());
        }
    }
    r.insert("ts_ms".into(), json!(env.now_ms));
    r
}

/// The admission record for a PreToolUse event the gate decided on.
pub fn admission(
    event: &Map<String, Value>,
    raw: &[u8],
    env: &Env,
    root: Option<&Path>,
    outcome: &Outcome,
) -> Value {
    let mut r = common("admission", event, raw, env);
    let input = event.get("tool_input").cloned().unwrap_or(Value::Null);
    r.insert(
        "input_sha256".into(),
        json!(format!(
            "sha256:{}",
            sha256_hex(input.to_string().as_bytes())
        )),
    );
    r.insert(
        "decision".into(),
        json!(if outcome.is_block() { "block" } else { "pass" }),
    );
    if outcome.is_block() {
        r.insert("reason".into(), json!(outcome.stderr.trim_end()));
    }
    r.insert("policy".into(), policy(root));
    Value::Object(r)
}

/// The policy in force: the spec fingerprint `mezha compile` recorded.
fn policy(root: Option<&Path>) -> Value {
    let Some(root) = root else {
        return Value::Null;
    };
    std::fs::read_to_string(root.join(".claude/.mezha-state.json"))
        .ok()
        .and_then(|t| serde_json::from_str::<Value>(&t).ok())
        .and_then(|s| s.get("spec").filter(|v| v.is_string()).cloned())
        .unwrap_or(Value::Null)
}

/// Appends `record` as one line to today's file.
pub fn append(home: &Path, root: Option<&Path>, now: u64, record: &Value) -> io::Result<()> {
    let dir = dir(home, root);
    create_private_dir(&approvals::mezha_home(home))?;
    create_private_dir(&approvals::mezha_home(home).join("audit"))?;
    create_private_dir(&dir)?;
    let day = &utc_stamp(now)[..8];
    let mut options = std::fs::OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(dir.join(format!("{day}.jsonl")))?;
    let mut line = record.to_string();
    line.push('\n');
    // One write, so concurrent hooks don't interleave inside a record.
    file.write_all(line.as_bytes())
}

fn create_private_dir(dir: &Path) -> io::Result<()> {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(dir)
}

/// The `audit-outcome` hook, on PostToolUse and PostToolUseFailure. The
/// tool has already run, so nothing here blocks: a record that can't be
/// written is reported on stderr and is missing from the log, where its
/// admission without an outcome shows the gap.
pub fn outcome(input: &[u8], env: &Env) -> Outcome {
    let Ok(Value::Object(event)) = serde_json::from_slice::<Value>(input) else {
        return Outcome::allow();
    };
    let state = match event.get("hook_event_name").and_then(Value::as_str) {
        Some("PostToolUse") => "committed",
        Some("PostToolUseFailure") => "failed",
        _ => return Outcome::allow(),
    };
    let Some(home) = mezha_broker::home_dir(|k| env.var(k).map(str::to_string)) else {
        return Outcome::allow();
    };
    let root = crate::approval_gate::project_dir(env, &event).map(|p| mezha_broker::repo_root(&p));
    let mut r = common("outcome", &event, input, env);
    r.insert("terminal_state".into(), json!(state));
    if event.get("is_interrupt") == Some(&Value::Bool(true)) {
        r.insert("interrupted".into(), json!(true));
    }
    // The Agent tool's result names the subagent run it started, whose
    // calls carry it as `agent_id`: the link from a subagent's records back
    // to the call that spawned it. Claude Code gives hooks no parent
    // reference before the call runs, so it can't be in the admission.
    if matches!(
        event.get("tool_name").and_then(Value::as_str),
        Some("Agent" | "Task")
    ) && let Some(id) = event
        .get("tool_response")
        .and_then(|r| r.get("agentId"))
        .and_then(Value::as_str)
    {
        r.insert("spawned_agent_id".into(), json!(id));
    }
    match append(&home, root.as_deref(), env.now, &Value::Object(r)) {
        Ok(()) => Outcome::allow(),
        Err(e) => Outcome {
            code: 0,
            stderr: format!("mezha: couldn't write the audit log: {e}\n"),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attempt_ids_are_recomputable() {
        let event: Map<String, Value> =
            serde_json::from_value(json!({"session_id": "s", "tool_use_id": "t"})).unwrap();
        let (id, preimage) = attempt_id(&event, b"ignored");
        assert_eq!(id, format!("sha256:{}", sha256_hex(b"s\0t")));
        assert_eq!(preimage, json!(["session_id", "tool_use_id"]));
        let (id, preimage) = attempt_id(&Map::new(), b"{}");
        assert_eq!(id, format!("sha256:{}", sha256_hex(b"{}")));
        assert_eq!(preimage, json!(["event"]));
    }
}
