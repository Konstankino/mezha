//! What one Claude Code session of the project says about how work went:
//! its cost, how often you came back to it, and what each agent run did.
//! Only the session's own records count: a resumed or forked session
//! copies the earlier session's records (and its cost) in under the old
//! session id.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::Path;
use std::time::UNIX_EPOCH;

use mezha_memory::markdown::{heading_section, item_count};
use mezha_memory::time::parse_iso;
use mezha_memory::transcripts::{
    failures, final_text, human_text, in_roots, read_transcript, subagent_files,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SessionRow {
    pub v: u64,
    pub id: String,
    pub start: i64,
    pub end: i64,
    pub branch: Option<String>,
    /// Claude Code's estimate for this session alone; `None` when the
    /// session wrote none (still running, or crashed).
    pub cost_usd: Option<f64>,
    /// Prompts you typed.
    pub prompts: u32,
    pub runs: Vec<RunRow>,
    /// Per role: runs that started after one of your prompts that came
    /// after the role's previous run ended.
    pub reruns: BTreeMap<String, u32>,
    /// The transcript as read, so an unchanged one isn't read again.
    pub source_mtime: i64,
    pub source_size: u64,
}

impl SessionRow {
    /// Your prompts after the first: a per-session rework proxy.
    pub fn followups(&self) -> u32 {
        self.prompts.saturating_sub(1)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RunRow {
    pub role: String,
    pub id: String,
    pub start: i64,
    pub end: i64,
    /// Input tokens, cache reads and writes included.
    pub tokens_in: u64,
    pub tokens_out: u64,
    pub failures: u32,
    pub lessons: bool,
    /// Items in the run's last `## Unresolved` section.
    pub unresolved: u32,
}

/// The transcript's modification time and size.
pub fn source_stamp(file: &Path) -> (i64, u64) {
    std::fs::metadata(file)
        .map(|m| {
            let mtime = m
                .modified()
                .ok()
                .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                .map_or(0, |d| d.as_secs() as i64);
            (mtime, m.len())
        })
        .unwrap_or((0, 0))
}

/// The session in `file`, if it belongs to the project (`roots`), counting
/// the subagent runs of `roles`.
pub fn extract(file: &Path, roots: &[String], roles: &BTreeSet<String>) -> Option<SessionRow> {
    let sid = file.file_stem()?.to_string_lossy().into_owned();
    let transcript = read_transcript(file).ok()?;
    if !in_roots(&transcript.records, roots) {
        return None;
    }
    let own: Vec<&Value> = transcript
        .records
        .iter()
        .filter(|r| r.get("sessionId").and_then(Value::as_str) == Some(sid.as_str()))
        .collect();
    let times: Vec<i64> = own.iter().filter_map(|r| time(r)).collect();
    let (start, end) = (*times.iter().min()?, *times.iter().max()?);
    let branch = own
        .iter()
        .find_map(|r| r.get("gitBranch").and_then(Value::as_str))
        .filter(|b| !b.is_empty())
        .map(str::to_string);
    let prompt_times: Vec<i64> = own
        .iter()
        .filter(|r| human_text(r).is_some())
        .filter_map(|r| time(r))
        .collect();

    // A continued session's own total starts at what it inherited.
    let cost = |records: &mut dyn Iterator<Item = &Value>| -> Vec<f64> {
        records
            .filter(|r| r.get("type").and_then(Value::as_str) == Some("cost-state"))
            .filter_map(|r| r.get("totalCostUSD").and_then(Value::as_f64))
            .collect()
    };
    let mine = cost(&mut own.iter().copied());
    let inherited = cost(
        &mut transcript
            .records
            .iter()
            .filter(|r| r.get("sessionId").and_then(Value::as_str) != Some(sid.as_str())),
    )
    .into_iter()
    .fold(0.0_f64, f64::max);
    let cost_usd = mine.last().map(|c| (c - inherited).max(0.0));

    let mut runs = Vec::new();
    for (path, role) in subagent_files(file) {
        let Some(role) = role.filter(|r| roles.contains(r)) else {
            continue;
        };
        let Ok(t) = read_transcript(&path) else {
            continue;
        };
        let records: Vec<&Value> = t.records.iter().collect();
        let times: Vec<i64> = records.iter().filter_map(|r| time(r)).collect();
        let (Some(&start), Some(&end)) = (times.iter().min(), times.iter().max()) else {
            continue;
        };
        let text = final_text(&records);
        let (tokens_in, tokens_out) = tokens(&records);
        runs.push(RunRow {
            role,
            id: path
                .file_stem()
                .and_then(|s| s.to_str())
                .and_then(|s| s.strip_prefix("agent-"))
                .unwrap_or_default()
                .to_string(),
            start,
            end,
            tokens_in,
            tokens_out,
            failures: failures(&records).len() as u32,
            lessons: heading_section(&text, "Lessons").is_some(),
            unresolved: heading_section(&text, "Unresolved").map_or(0, |s| item_count(&s) as u32),
        });
    }
    runs.sort_by(|a, b| (a.start, &a.id).cmp(&(b.start, &b.id)));
    let reruns = reruns(&runs, &prompt_times);
    let (source_mtime, source_size) = source_stamp(file);
    Some(SessionRow {
        v: crate::store::VERSION,
        id: sid,
        start,
        end,
        branch,
        cost_usd,
        prompts: prompt_times.len() as u32,
        runs,
        reruns,
        source_mtime,
        source_size,
    })
}

/// Runs of a role that came back after you spoke: parallel fan-out and
/// back-to-back delegation don't count.
fn reruns(runs: &[RunRow], prompts: &[i64]) -> BTreeMap<String, u32> {
    let mut last_end: HashMap<&str, i64> = HashMap::new();
    let mut out = BTreeMap::new();
    for run in runs {
        if let Some(&ended) = last_end.get(run.role.as_str())
            && prompts.iter().any(|&t| t > ended && t < run.start)
        {
            *out.entry(run.role.clone()).or_insert(0) += 1;
        }
        let entry = last_end.entry(run.role.as_str()).or_insert(run.end);
        *entry = (*entry).max(run.end);
    }
    out
}

/// Tokens of a run, counting each `message.id` once, from its last record:
/// earlier records of a message carry partial output counts.
fn tokens(records: &[&Value]) -> (u64, u64) {
    let mut last: HashMap<String, &Value> = HashMap::new();
    let mut anonymous = Vec::new();
    for r in records {
        if r.get("type").and_then(Value::as_str) != Some("assistant") {
            continue;
        }
        let Some(usage) = r.pointer("/message/usage") else {
            continue;
        };
        match r.pointer("/message/id").and_then(Value::as_str) {
            Some(id) => {
                last.insert(id.to_string(), usage);
            }
            None => anonymous.push(usage),
        }
    }
    let n = |u: &Value, k: &str| u.get(k).and_then(Value::as_u64).unwrap_or(0);
    last.values()
        .copied()
        .chain(anonymous)
        .fold((0, 0), |(i, o), u| {
            (
                i + n(u, "input_tokens")
                    + n(u, "cache_creation_input_tokens")
                    + n(u, "cache_read_input_tokens"),
                o + n(u, "output_tokens"),
            )
        })
}

fn time(record: &Value) -> Option<i64> {
    record
        .get("timestamp")
        .and_then(Value::as_str)
        .and_then(parse_iso)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(role: &str, start: i64, end: i64) -> RunRow {
        RunRow {
            role: role.into(),
            id: format!("{role}{start}"),
            start,
            end,
            tokens_in: 0,
            tokens_out: 0,
            failures: 0,
            lessons: false,
            unresolved: 0,
        }
    }

    #[test]
    fn reruns_need_a_prompt_between() {
        // Two implementers in parallel, then one after your prompt.
        let runs = [
            run("impl", 10, 20),
            run("impl", 11, 21),
            run("impl", 40, 50),
        ];
        assert_eq!(
            reruns(&runs, &[30]),
            BTreeMap::from([("impl".to_string(), 1)])
        );
        assert!(reruns(&runs, &[]).is_empty());
        assert!(reruns(&runs, &[5]).is_empty());
    }

    #[test]
    fn tokens_take_the_last_record_of_a_message() {
        let r = |id: &str, out: u64| serde_json::json!({"type": "assistant", "message": {"id": id, "usage": {"input_tokens": 10, "cache_read_input_tokens": 5, "output_tokens": out}}});
        let records = [r("m1", 2), r("m1", 362), r("m2", 8)];
        let refs: Vec<&Value> = records.iter().collect();
        assert_eq!(tokens(&refs), (30, 370));
    }
}
