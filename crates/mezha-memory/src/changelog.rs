//! `<role>/CHANGELOG.md`: what each dream did, written by mezha (the
//! dreamer may not touch it). Facts only, plus the dreamer's summary in a
//! fence. Claude Code loads `MEMORY.md`, not this file.

use crate::inbox::fenced;
use crate::time::format_iso;

#[derive(Debug, Clone, PartialEq)]
pub struct Entry {
    /// When the dream ran.
    pub when: i64,
    pub runs: usize,
    /// When the oldest and newest runs read ended.
    pub first: i64,
    pub last: i64,
    pub model: String,
    pub turns: u64,
    pub cost_usd: f64,
    pub claude_code: String,
    /// Already scanned by [`crate::review::review_text`].
    pub summary: String,
}

/// `existing` (if any) with `entry` appended.
pub fn append(existing: Option<&str>, role: &str, entry: &Entry) -> String {
    let mut out = match existing {
        Some(text) if !text.trim().is_empty() => {
            let mut text = text.trim_end().to_string();
            text.push_str("\n\n");
            text
        }
        _ => format!(
            "# Dream log: {role}\n\nWritten by `mezha dream`. The agent loads MEMORY.md, not \
             this file.\n\n"
        ),
    };
    out.push_str(&format!(
        "## {}\n\nRuns: {}, ended from {} to {}\nDreamer: {}, {} turns, ${:.2}, Claude Code {}\n\n{}",
        format_iso(entry.when),
        entry.runs,
        format_iso(entry.first),
        format_iso(entry.last),
        entry.model,
        entry.turns,
        entry.cost_usd,
        entry.claude_code,
        fenced(entry.summary.trim()),
    ));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn appends_entries() {
        let entry = Entry {
            when: 1_800_000_000,
            runs: 3,
            first: 1_799_900_000,
            last: 1_799_990_000,
            model: "sonnet".into(),
            turns: 12,
            cost_usd: 0.314,
            claude_code: "2.1.285".into(),
            summary: "Merged two lessons.".into(),
        };
        let first = append(None, "implementer", &entry);
        assert!(first.starts_with("# Dream log: implementer\n"));
        assert!(first.contains("## 2027-01-15T08:00:00Z\n\nRuns: 3, ended from 2027-01-14T04:13:20Z to 2027-01-15T05:13:20Z\nDreamer: sonnet, 12 turns, $0.31, Claude Code 2.1.285\n\n```text\nMerged two lessons.\n```\n"));
        let second = append(Some(&first), "implementer", &entry);
        assert_eq!(second.matches("## 2027-01-15").count(), 2);
        assert_eq!(second.matches("# Dream log").count(), 1);
    }
}
