//! `mezha metrics`: what the store and the transcripts say over a window.
//! Every figure is labelled for what it is: costs are Claude Code's
//! estimates, follow-up prompts and re-runs are proxies for rework.

use std::collections::BTreeMap;

use mezha_memory::time::{format_iso, parse_iso};
use serde::Serialize;
use serde_json::Value;

use crate::ab::{self, AbRow};
use crate::dreams::{DreamRow, DreamTally, Status};
use crate::sessions::SessionRow;

#[derive(Debug, Clone, Default, Serialize)]
pub struct RoleStats {
    pub runs: u32,
    pub with_lessons: u32,
    pub unresolved: u32,
    pub failures: u32,
    pub tokens_in: u64,
    pub tokens_out: u64,
    /// Runs after one of your prompts that followed the role's last run.
    pub reruns: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub version: u32,
    pub project: String,
    pub since: String,
    pub sessions: usize,
    pub sessions_with_cost: usize,
    /// Claude Code's estimates, in US dollars.
    pub session_cost_usd: f64,
    pub dream_cost_usd: f64,
    pub cost_per_session_usd: Option<f64>,
    pub followups_per_session: Option<f64>,
    pub agent_runs: u32,
    /// Unresolved items per ISO week (`2026-W41`), oldest first.
    pub unresolved_by_week: Vec<(String, u32)>,
    pub roles: BTreeMap<String, RoleStats>,
    pub dreams: DreamTally,
    pub share_without_edits: Option<f64>,
    pub last_dream: Option<Value>,
    pub ab: Option<ab::Summary>,
    pub not_measured: Vec<&'static str>,
}

pub fn build(
    project: &str,
    since: i64,
    sessions: &[SessionRow],
    dreams: &[(DreamRow, Option<Status>)],
    ab_rows: &[AbRow],
    last_dream: Option<Value>,
) -> Report {
    let window: Vec<&SessionRow> = sessions.iter().filter(|s| s.end >= since).collect();
    let costs: Vec<f64> = window.iter().filter_map(|s| s.cost_usd).collect();
    let session_cost: f64 = costs.iter().sum();
    let mut roles: BTreeMap<String, RoleStats> = BTreeMap::new();
    let mut weeks: BTreeMap<String, u32> = BTreeMap::new();
    let mut agent_runs = 0;
    for s in &window {
        for run in &s.runs {
            agent_runs += 1;
            let r = roles.entry(run.role.clone()).or_default();
            r.runs += 1;
            r.with_lessons += u32::from(run.lessons);
            r.unresolved += run.unresolved;
            r.failures += run.failures;
            r.tokens_in += run.tokens_in;
            r.tokens_out += run.tokens_out;
            *weeks.entry(iso_week(run.end)).or_insert(0) += run.unresolved;
        }
        for (role, n) in &s.reruns {
            roles.entry(role.clone()).or_default().reruns += n;
        }
    }
    let mut tally = DreamTally::default();
    let mut dream_cost = 0.0;
    for (d, status) in dreams.iter().filter(|(d, _)| d.at >= since) {
        tally.add(d, *status);
        dream_cost += d.cost_usd;
    }
    let latest_ab = ab_rows.iter().map(|r| r.stamp.as_str()).max();
    let ab = latest_ab.map(|stamp| {
        let rows: Vec<AbRow> = ab_rows
            .iter()
            .filter(|r| r.stamp == stamp)
            .cloned()
            .collect();
        ab::summarize(&rows)
    });
    let n = window.len();
    Report {
        version: 1,
        project: project.to_string(),
        since: format_iso(since),
        sessions: n,
        sessions_with_cost: costs.len(),
        session_cost_usd: session_cost,
        dream_cost_usd: dream_cost,
        cost_per_session_usd: (!costs.is_empty()).then(|| session_cost / costs.len() as f64),
        followups_per_session: (n > 0)
            .then(|| window.iter().map(|s| f64::from(s.followups())).sum::<f64>() / n as f64),
        agent_runs,
        unresolved_by_week: weeks.into_iter().collect(),
        roles,
        share_without_edits: tally.share_without_edits(),
        dreams: tally,
        last_dream,
        ab,
        not_measured: vec![
            "returns from human review (needs PR data; phase 5)",
            "cost against bare Claude Code (the A/B compares memory with emptied memory)",
        ],
    }
}

impl Report {
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_default() + "\n"
    }

    pub fn to_human(&self) -> String {
        let mut out = format!(
            "Metrics for {} since {}: {} session(s) ({} with a cost), {} agent run(s)\n",
            self.project,
            &self.since[..10],
            self.sessions,
            self.sessions_with_cost,
            self.agent_runs
        );
        let per = self
            .cost_per_session_usd
            .map_or("no session reported a cost".to_string(), |c| {
                format!("${c:.2} per session with a known cost")
            });
        out.push_str(&format!(
            "Cost        ${:.2} sessions + ${:.2} dreams; {per} (Claude Code's estimates)\n",
            self.session_cost_usd, self.dream_cost_usd
        ));
        let reruns: Vec<String> = self
            .roles
            .iter()
            .filter(|(_, r)| r.reruns > 0)
            .map(|(name, r)| format!("{name} {}", r.reruns))
            .collect();
        out.push_str(&format!(
            "Rework      {} follow-up prompt(s) per session (proxy); re-runs after your prompt: {}\n",
            self.followups_per_session
                .map_or("-".to_string(), |f| format!("{f:.1}")),
            if reruns.is_empty() {
                "none".to_string()
            } else {
                reruns.join(", ")
            }
        ));
        let weeks: Vec<String> = self
            .unresolved_by_week
            .iter()
            .map(|(w, n)| format!("{w} {n}"))
            .collect();
        out.push_str(&format!(
            "Unresolved  {}\n",
            if weeks.is_empty() {
                "no agent runs".to_string()
            } else {
                weeks.join(" · ")
            }
        ));
        if !self.roles.is_empty() {
            let roles: Vec<String> = self
                .roles
                .iter()
                .map(|(name, r)| {
                    format!(
                        "{name} {} run(s), {} with lessons, {} unresolved, {} failed call(s), {} tokens",
                        r.runs,
                        r.with_lessons,
                        r.unresolved,
                        r.failures,
                        human_count(r.tokens_in + r.tokens_out)
                    )
                })
                .collect();
            out.push_str(&format!("Roles       {}\n", roles.join(" · ")));
        }
        let d = &self.dreams;
        out.push_str(&format!(
            "Dreams      {} without edits, {} with edits, {} pending, {} dropped, {} stale; {} local applied{} (as of your last fetch)\n",
            d.without_edits,
            d.with_edits,
            d.pending,
            d.dropped,
            d.stale,
            d.applied,
            self.share_without_edits
                .map_or(String::new(), |s| format!("; {:.0}% of merged ones without edits", s * 100.0))
        ));
        if let Some(last) = &self.last_dream {
            let at = last
                .get("at")
                .and_then(Value::as_i64)
                .map(format_iso)
                .unwrap_or_default();
            let ok = last.get("ok").and_then(Value::as_bool) == Some(true);
            let how = if last.get("scheduled").and_then(Value::as_bool) == Some(true) {
                "scheduled"
            } else {
                "by hand"
            };
            let mut line = format!(
                "Last dream  {at}, {how}, {}",
                if ok { "ok" } else { "FAILED" }
            );
            if let Some(err) = last.get("error").and_then(Value::as_str) {
                line.push_str(&format!(": {}", mezha_memory::scan::escape(err)));
            }
            out.push_str(&line);
            out.push('\n');
        }
        if let Some(ab) = &self.ab {
            out.push_str(&format!(
                "A/B         {}, {} task(s) × {}: with memory {}/{} passed, ${:.2} · without {}/{}, ${:.2}{}\n",
                ab.stamp,
                ab.tasks.len(),
                ab.repeat,
                ab.memory.passed,
                ab.memory.runs,
                ab.memory.cost_usd,
                ab.empty.passed,
                ab.empty.runs,
                ab.empty.cost_usd,
                if ab.too_few { " (too few runs to claim a difference)" } else { "" }
            ));
        }
        out.push_str(&format!("Not measured: {}\n", self.not_measured.join("; ")));
        out
    }
}

fn human_count(n: u64) -> String {
    match n {
        0..1_000 => n.to_string(),
        1_000..1_000_000 => format!("{:.1}k", n as f64 / 1e3),
        _ => format!("{:.1}M", n as f64 / 1e6),
    }
}

/// `2026-W41`: the ISO week of a time (weeks start on Monday, and week 1
/// holds the year's first Thursday).
pub fn iso_week(secs: i64) -> String {
    let days = secs.div_euclid(86_400);
    // 1970-01-01 was a Thursday; Monday = 0.
    let weekday = (days + 3).rem_euclid(7);
    let thursday = days - weekday + 3;
    let year: i64 = format_iso(thursday * 86_400)[..4].parse().unwrap_or(1970);
    let jan1 = parse_iso(&format!("{year:04}-01-01")).unwrap_or(0) / 86_400;
    let week = (thursday - jan1) / 7 + 1;
    format!("{year:04}-W{week:02}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sessions::RunRow;

    #[test]
    fn iso_weeks() {
        let at = |d: &str| parse_iso(d).unwrap();
        assert_eq!(iso_week(at("2026-10-09")), "2026-W41");
        assert_eq!(iso_week(at("2026-01-01")), "2026-W01");
        assert_eq!(iso_week(at("2021-01-03")), "2020-W53");
        assert_eq!(iso_week(at("2024-12-30")), "2025-W01");
    }

    fn session(
        id: &str,
        end: i64,
        cost: Option<f64>,
        prompts: u32,
        runs: Vec<RunRow>,
    ) -> SessionRow {
        SessionRow {
            v: 1,
            id: id.into(),
            start: end - 100,
            end,
            branch: None,
            cost_usd: cost,
            prompts,
            runs,
            reruns: BTreeMap::from([("implementer".to_string(), 1)]),
            source_mtime: 0,
            source_size: 0,
        }
    }

    #[test]
    fn aggregates() {
        let day = parse_iso("2026-10-09").unwrap();
        let run = RunRow {
            role: "implementer".into(),
            id: "a".into(),
            start: day,
            end: day + 10,
            tokens_in: 1500,
            tokens_out: 500,
            failures: 1,
            lessons: true,
            unresolved: 2,
        };
        let sessions = [
            session("s1", day + 50, Some(2.0), 3, vec![run.clone()]),
            session("s2", day + 60, None, 1, vec![]),
            session("old", 10, Some(100.0), 1, vec![]),
        ];
        let r = build("p", day - 86_400, &sessions, &[], &[], None);
        assert_eq!((r.sessions, r.sessions_with_cost), (2, 1));
        assert_eq!(r.cost_per_session_usd, Some(2.0));
        assert_eq!(r.followups_per_session, Some(1.0));
        assert_eq!(r.unresolved_by_week, [("2026-W41".to_string(), 2)]);
        assert_eq!(r.roles["implementer"].reruns, 2);
        let text = r.to_human();
        assert!(
            text.contains("2 session(s) (1 with a cost), 1 agent run(s)"),
            "{text}"
        );
        assert!(
            text.contains(
                "implementer 1 run(s), 1 with lessons, 2 unresolved, 1 failed call(s), 2.0k tokens"
            ),
            "{text}"
        );
        assert!(text.contains("Not measured"), "{text}");
        let json: Value = serde_json::from_str(&r.to_json()).unwrap();
        assert_eq!(json["version"], 1);
        assert_eq!(json["sessions"], 2);
    }
}
