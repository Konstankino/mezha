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
use crate::skill_eval::{self, EvalRow};

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
    /// The latest eval of each skill.
    pub skill_evals: Vec<skill_eval::Summary>,
    pub not_measured: Vec<&'static str>,
}

pub fn build(
    project: &str,
    since: i64,
    sessions: &[SessionRow],
    dreams: &[(DreamRow, Option<Status>)],
    ab_rows: &[AbRow],
    eval_rows: &[EvalRow],
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
    let mut latest: BTreeMap<&str, &str> = BTreeMap::new();
    for row in eval_rows {
        let stamp = latest.entry(&row.skill).or_insert(&row.stamp);
        if row.stamp.as_str() > *stamp {
            *stamp = &row.stamp;
        }
    }
    let skill_evals = latest
        .into_iter()
        .map(|(skill, stamp)| {
            let rows: Vec<EvalRow> = eval_rows
                .iter()
                .filter(|r| r.skill == skill && r.stamp == stamp)
                .cloned()
                .collect();
            skill_eval::summarize(&rows)
        })
        .collect();
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
        skill_evals,
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
        for s in &self.skill_evals {
            let mut parts = Vec::new();
            if !s.triggers.is_empty() {
                parts.push(format!(
                    "triggers precision {}, recall {}",
                    skill_eval::percent(s.precision),
                    skill_eval::percent(s.recall)
                ));
            }
            if !s.tasks.is_empty() {
                parts.push(format!(
                    "tasks with the skill {}/{} passed, without {}/{}{}",
                    s.with.passed,
                    s.with.runs,
                    s.without.passed,
                    s.without.runs,
                    if s.too_few {
                        " (too few runs to claim a difference)"
                    } else {
                        ""
                    }
                ));
            }
            out.push_str(&format!(
                "Skill eval  {}, {}: {}\n",
                s.skill,
                s.stamp,
                parts.join(" · ")
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
    use crate::ab::Variant;
    use crate::dreams::Outcome;
    use crate::sessions::RunRow;
    use crate::skill_eval::{Arm, Kind};
    use serde_json::json;

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
        let r = build("p", day - 86_400, &sessions, &[], &[], &[], None);
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

    fn dream(stamp: &str, at: i64, scope: &str, outcome: Option<Outcome>) -> DreamRow {
        DreamRow {
            v: 1,
            key: format!("{stamp}/implementer"),
            stamp: stamp.into(),
            role: "implementer".into(),
            scope: scope.into(),
            at,
            runs: 2,
            turns: 5,
            cost_usd: 0.1,
            commit: None,
            dir: None,
            patch_id: None,
            branch: None,
            applied: scope != "project",
            outcome,
        }
    }

    fn ab_row(stamp: &str, task: &str, variant: Variant, repeat: u32, passed: bool) -> AbRow {
        AbRow {
            v: 1,
            id: format!("{stamp}/{task}/{}/{repeat}", variant.as_str()),
            stamp: stamp.into(),
            task: task.into(),
            variant,
            repeat,
            passed,
            is_error: false,
            subtype: "success".into(),
            cost_usd: 0.5,
            turns: 4,
            duration_ms: 1000,
            claude_code: "2.1.285".into(),
            failure: None,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn eval(
        stamp: &str,
        skill: &str,
        kind: Kind,
        case: &str,
        arm: Arm,
        repeat: u32,
        should_trigger: Option<bool>,
        loaded: bool,
        passed: Option<bool>,
    ) -> EvalRow {
        EvalRow {
            v: 1,
            id: format!("{stamp}/{skill}/{case}/{}/{repeat}", arm.as_str()),
            stamp: stamp.into(),
            skill: skill.into(),
            kind,
            case: case.into(),
            prompt_sha: "0".repeat(16),
            arm,
            repeat,
            should_trigger,
            loaded,
            load_turn: loaded.then_some(1),
            passed,
            is_error: false,
            subtype: "success".into(),
            cost_usd: 0.25,
            turns: 2,
            duration_ms: 1000,
            claude_code: "2.1.285".into(),
            failure: None,
            skill_sha: None,
            model: None,
            tools_used: Vec::new(),
            undeclared_tools: Vec::new(),
        }
    }

    #[test]
    fn reports_dreams_ab_runs_and_skill_evals() {
        let day = parse_iso("2026-10-09").unwrap();
        let since = day - 86_400;
        let dreams = [
            (
                dream(
                    "20261008T030000Z",
                    day - 10,
                    "project",
                    Some(Outcome::WithoutEdits),
                ),
                None,
            ),
            (
                dream("20261007T030000Z", day - 20, "project", None),
                Some(Status::Dropped),
            ),
            (dream("20261006T030000Z", day - 30, "local", None), None),
            // Before the window: left out, cost included.
            (
                dream(
                    "20260901T030000Z",
                    since - 1,
                    "project",
                    Some(Outcome::WithEdits),
                ),
                None,
            ),
        ];
        let ab_rows = [
            ab_row("20261001T000000Z", "a", Variant::Memory, 0, true),
            ab_row("20261001T000000Z", "a", Variant::Empty, 0, false),
            // An older A/B run is left out.
            ab_row("20260901T000000Z", "b", Variant::Memory, 0, false),
        ];
        let x = "20261001T000000Z";
        let y = "20261002T000000Z";
        let z = "20261003T000000Z";
        let mut eval_rows = vec![
            // An older eval of the same skill is left out, whichever
            // order the store lists them in.
            eval(
                "20260901T000000Z",
                "x",
                Kind::Trigger,
                "trigger-1",
                Arm::With,
                0,
                Some(true),
                false,
                None,
            ),
            eval(
                x,
                "x",
                Kind::Trigger,
                "trigger-1",
                Arm::With,
                0,
                Some(true),
                true,
                None,
            ),
            eval(
                y,
                "y",
                Kind::Task,
                "t",
                Arm::With,
                0,
                None,
                true,
                Some(true),
            ),
            eval(
                y,
                "y",
                Kind::Task,
                "t",
                Arm::Without,
                0,
                None,
                false,
                Some(false),
            ),
        ];
        for r in 0..3 {
            eval_rows.push(eval(
                z,
                "z",
                Kind::Trigger,
                "trigger-1",
                Arm::With,
                r,
                Some(false),
                false,
                None,
            ));
            eval_rows.push(eval(
                z,
                "z",
                Kind::Task,
                "t",
                Arm::With,
                r,
                None,
                true,
                Some(true),
            ));
            eval_rows.push(eval(
                z,
                "z",
                Kind::Task,
                "t",
                Arm::Without,
                r,
                None,
                false,
                Some(true),
            ));
        }
        let last =
            json!({"at": day, "ok": false, "scheduled": true, "error": "claude exited 1\u{1b}[2J"});
        let r = build("p", since, &[], &dreams, &ab_rows, &eval_rows, Some(last));
        assert_eq!(
            r.dreams,
            DreamTally {
                without_edits: 1,
                dropped: 1,
                applied: 1,
                ..DreamTally::default()
            }
        );
        assert_eq!(r.share_without_edits, Some(1.0));
        assert!(
            (r.dream_cost_usd - 0.3).abs() < 1e-9,
            "{}",
            r.dream_cost_usd
        );
        let ab = r.ab.as_ref().unwrap();
        assert_eq!(ab.stamp, "20261001T000000Z");
        assert_eq!(ab.tasks.keys().collect::<Vec<_>>(), ["a"]);
        let evals: Vec<(&str, &str)> = r
            .skill_evals
            .iter()
            .map(|s| (s.skill.as_str(), s.stamp.as_str()))
            .collect();
        assert_eq!(evals, [("x", x), ("y", y), ("z", z)]);

        let text = r.to_human();
        for want in [
            "Metrics for p since 2026-10-08: 0 session(s) (0 with a cost), 0 agent run(s)\n",
            " sessions + $0.30 dreams; no session reported a cost (Claude Code's estimates)\n",
            "Rework      - follow-up prompt(s) per session (proxy); re-runs after your prompt: none\n",
            "Unresolved  no agent runs\n",
            "Dreams      1 without edits, 0 with edits, 0 pending, 1 dropped, 0 stale; 1 local applied; 100% of merged ones without edits (as of your last fetch)\n",
            "Last dream  2026-10-09T00:00:00Z, scheduled, FAILED: claude exited 1\\u{1b}[2J\n",
            "A/B         20261001T000000Z, 1 task(s) × 1: with memory 1/1 passed, $0.50 · without 0/1, $0.50 (too few runs to claim a difference)\n",
            "Skill eval  x, 20261001T000000Z: triggers precision 100%, recall 100%\n",
            "Skill eval  y, 20261002T000000Z: tasks with the skill 1/1 passed, without 0/1 (too few runs to claim a difference)\n",
            "Skill eval  z, 20261003T000000Z: triggers precision n/a, recall n/a · tasks with the skill 3/3 passed, without 3/3\n",
        ] {
            assert!(text.contains(want), "{want:?} is not in:\n{text}");
        }
        assert!(!text.contains("Roles"), "{text}");
        let json: Value = serde_json::from_str(&r.to_json()).unwrap();
        assert_eq!(json["ab"]["stamp"], "20261001T000000Z");
        assert_eq!(json["skill_evals"].as_array().map(Vec::len), Some(3));
        assert_eq!(json["last_dream"]["scheduled"], true);
    }

    #[test]
    fn a_dream_run_by_hand_that_succeeded() {
        let last = json!({"at": 1_800_000_000, "ok": true});
        let r = build("p", 0, &[], &[], &[], &[], Some(last));
        let text = r.to_human();
        assert!(
            text.contains("Last dream  2027-01-15T08:00:00Z, by hand, ok\n"),
            "{text}"
        );
        assert!(!text.contains("\nA/B "), "{text}");
        assert!(!text.contains("\nSkill eval "), "{text}");
        assert_eq!(r.ab, None);
        assert!(r.skill_evals.is_empty());
    }

    #[test]
    fn token_counts_read_like_people_write_them() {
        assert_eq!(human_count(0), "0");
        assert_eq!(human_count(999), "999");
        assert_eq!(human_count(1_500), "1.5k");
        assert_eq!(human_count(2_500_000), "2.5M");
    }
}
